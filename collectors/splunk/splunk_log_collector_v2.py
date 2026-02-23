#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Splunk Log Ingestion Collector
================================
Script para coletar informações de ingestão de logs do Splunk via REST API.
Roda continuamente por N dias (padrão: 6), coleta métricas a cada intervalo
configurável e gera relatório final com médias diárias por data source.

Projetado para sizing e planejamento de migração para Microsoft Sentinel /
Defender for Cloud.

Autor: Leandro Sardim
Data: 2026-02-23
"""

import argparse
import getpass
import csv
import datetime
import json
import logging
import os
import signal
import sqlite3
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import requests  # type: ignore[import-untyped]
    import urllib3  # type: ignore[import-untyped]
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("ERRO: Módulo 'requests' não encontrado. Instale com: pip install requests")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────────
# Configurações padrão
# ─────────────────────────────────────────────────────────────────────────────
DEFAULT_COLLECTION_DAYS = 6
DEFAULT_INTERVAL_HOURS = 1          # Coleta a cada 1 hora
DEFAULT_DB_FILE = "splunk_metrics.db"
DEFAULT_REPORT_DIR = "reports"
DEFAULT_SPLUNK_PORT = 8089          # Porta padrão do Splunk Management (REST API)
SPL_TIMEOUT_SECONDS = 300           # Timeout para queries SPL
SPL_POLL_INTERVAL = 5               # Intervalo de polling para jobs SPL
RETRY_MAX_ATTEMPTS = 3              # Máximo de retentativas
RETRY_BASE_DELAY = 2               # Delay base em segundos para backoff
RETRYABLE_HTTP_STATUSES = (429, 500, 502, 503, 504)
MAX_CATCHUP_WINDOWS = 3             # Máx. de intervalos para catch-up em caso de falha
MAX_RESULTS_PER_PAGE = 10000        # Limite de resultados por página

# ─────────────────────────────────────────────────────────────────────────────
# Logger
# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("splunk_collector.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Variável global para controle de parada graciosa
# ─────────────────────────────────────────────────────────────────────────────
STOP_SIGNAL = False


class ErrorCounter:
    """Contador simples de erros/avisos por categoria."""

    def __init__(self) -> None:
        self._counts: Dict[str, int] = {}

    def inc(self, key: str, amount: int = 1) -> None:
        self._counts[key] = self._counts.get(key, 0) + amount

    def as_dict(self) -> Dict[str, int]:
        return dict(self._counts)

    def summary_line(self) -> str:
        if not self._counts:
            return "sem erros"
        parts = [f"{k}={v}" for k, v in sorted(self._counts.items())]
        return ", ".join(parts)


def signal_handler(signum, frame):
    """Handler para parada graciosa via Ctrl+C."""
    global STOP_SIGNAL
    logger.warning("Sinal de parada recebido (Ctrl+C). Finalizando após coleta atual...")
    STOP_SIGNAL = True


signal.signal(signal.SIGINT, signal_handler)
if hasattr(signal, "SIGTERM"):
    signal.signal(signal.SIGTERM, signal_handler)


# ─────────────────────────────────────────────────────────────────────────────
# Utilitários de retry
# ─────────────────────────────────────────────────────────────────────────────
def _retry_with_backoff(func, max_retries: int = RETRY_MAX_ATTEMPTS, base_delay: int = RETRY_BASE_DELAY):
    """
    Executa func() com retry e backoff exponencial em falhas transitórias.
    Não faz retry em HTTP 401, 403, 404.
    """
    last_exc: Optional[BaseException] = None
    for attempt in range(max_retries + 1):
        try:
            return func()
        except requests.exceptions.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else 0
            if status not in RETRYABLE_HTTP_STATUSES:
                raise
            last_exc = exc
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
            last_exc = exc
        except Exception:
            raise

        if attempt == max_retries:
            assert last_exc is not None
            raise last_exc

        retry_after = None
        if isinstance(last_exc, requests.exceptions.HTTPError) and getattr(last_exc, "response", None) is not None:
            try:
                ra = last_exc.response.headers.get("Retry-After")
                if ra is not None:
                    retry_after = int(float(ra))
            except Exception:
                retry_after = None

        delay = retry_after if (retry_after is not None and retry_after > 0) else base_delay * (2 ** attempt)
        logger.debug(f"Retry {attempt + 1}/{max_retries} em {delay}s: {last_exc}")
        time.sleep(delay)

    assert last_exc is not None
    raise last_exc


# ─────────────────────────────────────────────────────────────────────────────
# Cliente REST para o Splunk
# ─────────────────────────────────────────────────────────────────────────────
class SplunkClient:
    """Cliente REST para o Splunk Enterprise / Cloud (via Management API na porta 8089).

    Autenticação suportada:
    - Bearer Token (Splunk Authentication Tokens — recomendado)
    - Basic Auth (usuário:senha) como fallback
    """

    def __init__(
        self,
        base_url: str,
        token: str = "",
        username: str = "",
        password: str = "",
        verify_ssl: bool = False,
    ):
        self.base_url = base_url.rstrip("/")
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = self.verify_ssl

        # Determinar modo de autenticação
        if token:
            self.auth_mode = "token"
            self.session.headers.update({
                "Authorization": f"Bearer {token}",
            })
        elif username and password:
            self.auth_mode = "basic"
            self.session.auth = (username, password)
        else:
            raise ValueError(
                "Forneça token (Bearer) ou username+password para autenticação no Splunk."
            )

        # Splunk REST API retorna JSON quando solicitado via output_mode
        self.session.headers.update({
            "Accept": "application/json",
        })

    # ── Validação de resposta ────────────────────────────────────────────
    def _check_response(self, resp: requests.Response, endpoint: str) -> None:
        """Verifica status HTTP e fornece mensagens acionáveis."""
        if resp.status_code == 401:
            raise requests.exceptions.HTTPError(
                f"HTTP 401 Unauthorized de {endpoint}. "
                "Verifique se o token/credenciais estão corretos e não expiraram.",
                response=resp,
            )
        if resp.status_code == 403:
            raise requests.exceptions.HTTPError(
                f"HTTP 403 Forbidden de {endpoint}. "
                "As credenciais não possuem as permissões (capabilities) necessárias.",
                response=resp,
            )
        resp.raise_for_status()

    def _get(self, endpoint: str, params: Optional[Dict] = None) -> Any:
        """GET request com retry e validação."""
        url = f"{self.base_url}/{endpoint}"
        if params is None:
            params = {}
        params["output_mode"] = "json"
        logger.debug(f"GET {url} params={params}")

        def _do_request():
            resp = self.session.get(url, params=params, timeout=60)
            self._check_response(resp, endpoint)
            return resp.json()

        return _retry_with_backoff(_do_request)

    def _post(self, endpoint: str, data: Optional[Dict] = None,
              params: Optional[Dict] = None) -> Any:
        """POST request com retry e validação."""
        url = f"{self.base_url}/{endpoint}"
        if params is None:
            params = {}
        params["output_mode"] = "json"
        logger.debug(f"POST {url} data={data}")

        def _do_request():
            resp = self.session.post(url, data=data, params=params, timeout=60)
            self._check_response(resp, endpoint)
            return resp.json()

        return _retry_with_backoff(_do_request)

    # ── Teste de conexão ─────────────────────────────────────────────────
    def test_connection(self) -> Dict:
        """Testa conectividade com o Splunk via /services/server/info.

        Returns:
            dict: Informações do Splunk (versão, nome do servidor, etc.).
        """
        logger.info(f"Testando conexão com {self.base_url}...")
        try:
            data = self._get("services/server/info")
            entries = data.get("entry", [])
            if entries:
                content = entries[0].get("content", {})
                version = content.get("version", "desconhecida")
                server_name = content.get("serverName", "desconhecido")
                logger.info(f"Conexão OK — Splunk {version} ({server_name})")
                return content
            logger.info("Conexão OK — informações limitadas retornadas")
            return data
        except requests.exceptions.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else 0
            if status == 401:
                logger.error(
                    "Falha de autenticação (HTTP 401). "
                    "Verifique se o token/credenciais estão corretos."
                )
            elif status == 403:
                logger.error(
                    "Acesso negado (HTTP 403). "
                    "As credenciais não têm permissões suficientes."
                )
            else:
                logger.error(f"Erro HTTP {status} ao testar conexão.")
            raise
        except requests.exceptions.ConnectionError:
            logger.error(
                f"Não foi possível conectar a {self.base_url}. "
                "Verifique se a URL e porta (padrão: 8089) estão corretas."
            )
            raise

    # ── Inventário de data inputs / indexes ──────────────────────────────
    def get_indexes(self) -> List[Dict]:
        """Retorna lista de indexes no Splunk (exceto internos)."""
        try:
            data = self._get(
                "services/data/indexes",
                params={"count": 0},  # sem limite
            )
            indexes = []
            for entry in data.get("entry", []):
                content = entry.get("content", {})
                name = entry.get("name", "")
                # Pular indexes internos
                if name.startswith("_") and name not in ("_internal", "_audit"):
                    continue
                indexes.append({
                    "name": name,
                    "totalEventCount": int(content.get("totalEventCount", 0)),
                    "currentDBSizeMB": float(content.get("currentDBSizeMB", 0)),
                    "maxDataSizeMB": content.get("maxDataSizeMB", "auto"),
                    "disabled": content.get("disabled", False),
                    "datatype": content.get("datatype", "event"),
                })
            logger.info(f"Total de indexes encontrados: {len(indexes)}")
            return indexes
        except Exception as e:
            logger.warning(f"Não foi possível listar indexes: {e}")
            return []

    def get_sourcetypes(self) -> List[str]:
        """Retorna lista de sourcetypes conhecidos."""
        try:
            data = self._get(
                "services/saved/sourcetypes",
                params={"count": 0},
            )
            sourcetypes = [entry.get("name", "") for entry in data.get("entry", [])]
            logger.info(f"Total de sourcetypes registrados: {len(sourcetypes)}")
            return sourcetypes
        except Exception:
            logger.debug("Endpoint saved/sourcetypes não disponível; sem inventário de sourcetypes.")
            return []

    def get_data_inputs_summary(self) -> List[Dict]:
        """Retorna resumo de data inputs (forwarders, monitored files, etc.)."""
        try:
            data = self._get(
                "services/data/inputs/all",
                params={"count": 0},
            )
            inputs_list = []
            for entry in data.get("entry", []):
                content = entry.get("content", {})
                inputs_list.append({
                    "name": entry.get("name", ""),
                    "type": content.get("type", entry.get("name", "").split("/")[-1]),
                    "disabled": content.get("disabled", False),
                    "index": content.get("index", "default"),
                    "sourcetype": content.get("sourcetype", ""),
                })
            logger.info(f"Total de data inputs: {len(inputs_list)}")
            return inputs_list
        except Exception as e:
            logger.debug(f"Não foi possível listar data inputs: {e}")
            return []

    # ── SPL Search Jobs ──────────────────────────────────────────────────
    def run_spl_query(self, spl: str, earliest: str = "", latest: str = "") -> Optional[List[Dict]]:
        """Executa uma query SPL via search job e aguarda resultado.

        Args:
            spl: Query SPL (sem o 'search' inicial se for um generating command).
            earliest: Tempo inicial (epoch, ISO, ou relativo como -1h).
            latest: Tempo final (epoch, ISO, ou relativo como now).

        Returns:
            Lista de dicts (resultados) ou None em caso de erro.
        """
        logger.info(f"Executando SPL: {spl[:150]}...")

        # Criar search job
        job_data: Dict[str, Any] = {
            "search": spl if spl.strip().startswith("|") else f"search {spl}",
            "exec_mode": "normal",
            "max_count": MAX_RESULTS_PER_PAGE,
        }
        if earliest:
            job_data["earliest_time"] = earliest
        if latest:
            job_data["latest_time"] = latest

        try:
            result = self._post("services/search/jobs", data=job_data)
        except requests.exceptions.HTTPError as e:
            logger.error(f"Erro ao criar search job: {e}")
            return None

        # Extrair SID (search ID)
        sid = result.get("sid", "")
        if not sid:
            logger.error("Não foi possível obter SID do search job.")
            return None

        # Polling até completar
        start = time.time()
        while True:
            if time.time() - start > SPL_TIMEOUT_SECONDS:
                logger.error(f"Timeout aguardando search job {sid}")
                # Tentar cancelar o job
                try:
                    self._post(f"services/search/jobs/{sid}/control", data={"action": "cancel"})
                except Exception:
                    pass
                return None

            try:
                status = self._get(f"services/search/jobs/{sid}")
            except Exception as e:
                logger.warning(f"Erro ao verificar status do job {sid}: {e}")
                time.sleep(SPL_POLL_INTERVAL)
                continue

            entries = status.get("entry", [])
            if not entries:
                time.sleep(SPL_POLL_INTERVAL)
                continue

            content = entries[0].get("content", {})
            dispatch_state = content.get("dispatchState", "")
            is_done = content.get("isDone", False)

            if is_done or dispatch_state == "DONE":
                break
            elif dispatch_state in ("FAILED", "INTERNAL_CANCEL"):
                logger.error(f"Search job {sid} falhou: {dispatch_state}")
                return None

            done_progress = content.get("doneProgress", 0)
            logger.debug(f"SPL job {sid}: {dispatch_state} ({float(done_progress)*100:.0f}%)")
            time.sleep(SPL_POLL_INTERVAL)

        # Buscar resultados
        try:
            results_data = self._get(
                f"services/search/jobs/{sid}/results",
                params={"count": MAX_RESULTS_PER_PAGE},
            )
            return results_data.get("results", [])
        except Exception as e:
            logger.error(f"Erro ao buscar resultados do job {sid}: {e}")
            return None

    def get_event_metrics_window(
        self, start_time_ms: int, end_time_ms: int
    ) -> Optional[List[Dict]]:
        """Coleta métricas de ingestão por source/sourcetype para um intervalo exato.

        Usa SPL com stats para agregar volume e contagem por (source, sourcetype, index).
        """
        # Converter ms para epoch seconds (Splunk usa epoch seconds)
        earliest = f"{start_time_ms / 1000:.3f}"
        latest = f"{end_time_ms / 1000:.3f}"

        spl = (
            'index=* '
            '| stats count as total_event_count, '
            'sum(len(_raw)) as total_payload_bytes, '
            'avg(len(_raw)) as avg_payload_bytes '
            'by source, sourcetype, index'
        )

        results = self.run_spl_query(spl, earliest=earliest, latest=latest)

        if results is None:
            return None

        # Normalizar para o formato esperado pelo MetricsDB
        normalized: List[Dict] = []
        for r in results:
            try:
                total_events = int(r.get("total_event_count", 0))
                total_bytes = float(r.get("total_payload_bytes", 0))
                avg_bytes = float(r.get("avg_payload_bytes", 0))
            except (ValueError, TypeError):
                total_events = 0
                total_bytes = 0.0
                avg_bytes = 0.0

            source = r.get("source", "Unknown")
            sourcetype = r.get("sourcetype", "Unknown")
            index_name = r.get("index", "default")

            # Compor nome do logsource como "source (index)"
            logsource_name = f"{source} [{index_name}]"

            normalized.append({
                "logsourceid": hash(f"{source}|{sourcetype}|{index_name}") % (10**9),
                "log_source_name": logsource_name,
                "log_source_type": sourcetype,
                "aggregated_event_count": total_events,
                "total_event_count": total_events,
                "total_payload_bytes": total_bytes,
                "avg_payload_bytes": avg_bytes,
            })

        return normalized

    def get_license_usage(self, earliest: str = "-1d", latest: str = "now") -> Optional[List[Dict]]:
        """Coleta dados de uso de licença do Splunk (volume ingerido por sourcetype).

        A tabela interna _internal contém dados de license_usage que são
        mais precisos para volume real ingerido (billing).
        """
        spl = (
            'index=_internal source=*license_usage.log type=Usage '
            '| stats sum(b) as bytes_indexed by s as sourcetype, idx as index, h as host '
            '| eval mb_indexed=round(bytes_indexed/1024/1024, 2) '
            '| sort -bytes_indexed'
        )
        return self.run_spl_query(spl, earliest=earliest, latest=latest)

    def get_forwarder_list(self) -> Optional[List[Dict]]:
        """Lista forwarders conectados ao Splunk."""
        spl = (
            '| rest /services/deployment/server/clients '
            '| table clientName, hostname, ip, splunkVersion, '
            'lastPhoneHomeTime, build'
        )
        try:
            return self.run_spl_query(spl)
        except Exception:
            logger.debug("Não foi possível listar forwarders (endpoint pode não estar disponível).")
            return None


# ─────────────────────────────────────────────────────────────────────────────
# Banco de dados local (SQLite) — mesma arquitetura do coletor QRadar
# ─────────────────────────────────────────────────────────────────────────────
class MetricsDB:
    """Armazena métricas coletadas em SQLite local."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self._create_tables()

    def _create_tables(self):
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS collection_runs (
                run_id INTEGER PRIMARY KEY AUTOINCREMENT,
                collection_time TEXT NOT NULL,
                collection_date TEXT NOT NULL,
                interval_hours REAL NOT NULL,
                status TEXT DEFAULT 'success'
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS event_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                collection_time TEXT NOT NULL,
                collection_date TEXT NOT NULL,
                window_start_ms INTEGER,
                window_end_ms INTEGER,
                window_seconds REAL,
                logsource_id INTEGER,
                logsource_name TEXT,
                logsource_type TEXT,
                event_count INTEGER DEFAULT 0,
                aggregated_event_count INTEGER DEFAULT 0,
                total_event_count INTEGER DEFAULT 0,
                unparsed_aggregated_events INTEGER DEFAULT 0,
                unparsed_total_events INTEGER DEFAULT 0,
                total_payload_bytes REAL DEFAULT 0,
                avg_payload_bytes REAL DEFAULT 0,
                interval_hours REAL DEFAULT 1,
                FOREIGN KEY (run_id) REFERENCES collection_runs(run_id)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS log_sources_inventory (
                logsource_id INTEGER,
                name TEXT,
                type_name TEXT,
                type_id INTEGER,
                enabled INTEGER,
                description TEXT,
                last_updated TEXT,
                PRIMARY KEY (logsource_id)
            )
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_event_metrics_date 
            ON event_metrics(collection_date)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_event_metrics_logsource 
            ON event_metrics(logsource_name)
        """)
        self.conn.commit()

    def save_collection_run(self, collection_time: str, collection_date: str, interval_hours: float) -> int:
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO collection_runs (collection_time, collection_date, interval_hours) VALUES (?, ?, ?)",
            (collection_time, collection_date, interval_hours),
        )
        self.conn.commit()
        row_id = cursor.lastrowid
        assert row_id is not None, "INSERT falhou: lastrowid é None"
        return row_id

    def save_event_metrics(
        self,
        run_id: int,
        collection_time: str,
        collection_date: str,
        window_start_ms: int,
        window_end_ms: int,
        window_seconds: float,
        metrics: List[Dict],
        interval_hours: float,
    ):
        cursor = self.conn.cursor()
        for m in metrics:
            aggregated = int(m.get("aggregated_event_count", m.get("event_count", 0)) or 0)
            total = m.get("total_event_count", None)
            total = int(total) if total is not None else aggregated

            cursor.execute(
                """INSERT INTO event_metrics 
                   (run_id, collection_time, collection_date,
                    window_start_ms, window_end_ms, window_seconds,
                    logsource_id, logsource_name, logsource_type,
                    event_count, aggregated_event_count, total_event_count,
                    unparsed_aggregated_events, unparsed_total_events,
                    total_payload_bytes, avg_payload_bytes, interval_hours)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    run_id,
                    collection_time,
                    collection_date,
                    int(window_start_ms),
                    int(window_end_ms),
                    float(window_seconds),
                    m.get("logsourceid", 0),
                    m.get("log_source_name", "Unknown"),
                    m.get("log_source_type", "Unknown"),
                    aggregated,
                    aggregated,
                    total,
                    0,  # unparsed_aggregated_events (não aplicável no Splunk)
                    0,  # unparsed_total_events
                    m.get("total_payload_bytes", 0) or 0,
                    m.get("avg_payload_bytes", 0) or 0,
                    float(interval_hours),
                ),
            )
        self.conn.commit()
        logger.info(f"Salvos {len(metrics)} registros de métricas (run_id={run_id})")

    def save_log_sources_inventory(self, sources: List[Dict]):
        """Salva inventário de sources (derivado dos primeiros resultados SPL)."""
        cursor = self.conn.cursor()
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        for src in sources:
            ls_id = src.get("logsource_id", 0)
            cursor.execute(
                """INSERT OR REPLACE INTO log_sources_inventory 
                   (logsource_id, name, type_name, type_id, enabled, description, last_updated)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    ls_id,
                    src.get("name", "Unknown"),
                    src.get("type_name", "Unknown"),
                    0,
                    1,
                    src.get("description", ""),
                    now,
                ),
            )
        self.conn.commit()
        logger.info(f"Inventário de {len(sources)} sources salvo.")

    def fill_zero_event_rows(
        self,
        run_id: int,
        collection_time: str,
        collection_date: str,
        window_start_ms: int,
        window_end_ms: int,
        window_seconds: float,
        seen_logsource_ids: set,
        interval_hours: float,
    ) -> int:
        """Insere linhas com zero eventos para log sources do inventário ausentes na SPL."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT logsource_id, name, type_name FROM log_sources_inventory")
        inventory = cursor.fetchall()

        zero_count = 0
        for ls_id, ls_name, ls_type in inventory:
            if ls_id in seen_logsource_ids:
                continue
            cursor.execute(
                """INSERT INTO event_metrics
                   (run_id, collection_time, collection_date,
                    window_start_ms, window_end_ms, window_seconds,
                    logsource_id, logsource_name, logsource_type,
                    event_count, aggregated_event_count, total_event_count,
                    unparsed_aggregated_events, unparsed_total_events,
                    total_payload_bytes, avg_payload_bytes, interval_hours)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0, 0, 0, 0, 0, ?)""",
                (run_id, collection_time, collection_date,
                 int(window_start_ms), int(window_end_ms), float(window_seconds),
                 ls_id, ls_name or "Unknown", ls_type or "Unknown",
                 float(interval_hours)),
            )
            zero_count += 1

        if zero_count > 0:
            self.conn.commit()
            logger.debug(f"Inseridas {zero_count} linhas zero-event para cobertura completa.")
        return zero_count

    def get_daily_summary(self) -> List[Dict]:
        """Retorna resumo diário por log source."""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT 
                collection_date,
                logsource_name,
                logsource_type,
                SUM(total_event_count) as total_events,
                SUM(aggregated_event_count) as aggregated_events,
                SUM(unparsed_total_events) as unparsed_total_events,
                SUM(unparsed_aggregated_events) as unparsed_aggregated_events,
                SUM(total_payload_bytes) as total_bytes,
                CASE 
                    WHEN SUM(total_event_count) > 0 THEN (SUM(total_payload_bytes) / SUM(total_event_count))
                    ELSE 0
                END as avg_event_size_bytes,
                COUNT(DISTINCT collection_time) as collection_count,
                SUM(window_seconds) as covered_seconds
            FROM event_metrics
            GROUP BY collection_date, logsource_name, logsource_type
            ORDER BY collection_date, total_events DESC
        """)
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]

    def get_overall_daily_average(self) -> List[Dict]:
        """Retorna média diária geral por log source (across all days)."""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT 
                logsource_name,
                logsource_type,
                COUNT(DISTINCT collection_date) as days_collected,

                ROUND(AVG(projected_daily_events), 2) as avg_daily_events,
                ROUND(AVG(projected_daily_bytes), 2) as avg_daily_bytes_total,
                ROUND(AVG(projected_daily_bytes) / (1024.0 * 1024.0), 4) as avg_daily_mb,
                ROUND(AVG(projected_daily_bytes) / (1024.0 * 1024.0 * 1024.0), 6) as avg_daily_gb,

                ROUND(AVG(projected_daily_aggregated_events), 2) as avg_daily_aggregated_events,
                ROUND(AVG(projected_daily_unparsed_events), 2) as avg_daily_unparsed_events,
                ROUND(AVG(coverage_pct), 2) as avg_coverage_pct,

                ROUND(AVG(avg_event_size_bytes), 2) as avg_event_size_bytes
            FROM (
                SELECT 
                    collection_date,
                    logsource_name,
                    logsource_type,
                    SUM(total_event_count) as daily_events,
                    SUM(aggregated_event_count) as daily_aggregated_events,
                    SUM(unparsed_total_events) as daily_unparsed_events,
                    SUM(total_payload_bytes) as daily_bytes,
                    CASE 
                        WHEN SUM(total_event_count) > 0 THEN (SUM(total_payload_bytes) / SUM(total_event_count))
                        ELSE 0
                    END as avg_event_size_bytes,
                    CASE WHEN SUM(window_seconds) > 0 THEN (SUM(window_seconds) / 86400.0) * 100.0 ELSE 0 END as coverage_pct,
                    CASE WHEN SUM(window_seconds) > 0 THEN (SUM(total_event_count) * 86400.0 / SUM(window_seconds)) ELSE SUM(total_event_count) END as projected_daily_events,
                    CASE WHEN SUM(window_seconds) > 0 THEN (SUM(aggregated_event_count) * 86400.0 / SUM(window_seconds)) ELSE SUM(aggregated_event_count) END as projected_daily_aggregated_events,
                    CASE WHEN SUM(window_seconds) > 0 THEN (SUM(unparsed_total_events) * 86400.0 / SUM(window_seconds)) ELSE SUM(unparsed_total_events) END as projected_daily_unparsed_events,
                    CASE WHEN SUM(window_seconds) > 0 THEN (SUM(total_payload_bytes) * 86400.0 / SUM(window_seconds)) ELSE SUM(total_payload_bytes) END as projected_daily_bytes
                FROM event_metrics
                GROUP BY collection_date, logsource_name, logsource_type
            ) daily
            GROUP BY logsource_name, logsource_type
            ORDER BY avg_daily_bytes_total DESC
        """)
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]

    def get_collection_dates(self) -> List[str]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT DISTINCT collection_date FROM collection_runs ORDER BY collection_date")
        return [row[0] for row in cursor.fetchall()]

    def get_total_runs(self) -> int:
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM collection_runs")
        return cursor.fetchone()[0]

    def close(self):
        self.conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# Gerador de Relatório
# ─────────────────────────────────────────────────────────────────────────────
class ReportGenerator:
    """Gera relatórios em CSV e texto a partir dos dados coletados."""

    def __init__(self, db: MetricsDB, report_dir: str):
        self.db = db
        self.report_dir = Path(report_dir)
        self.report_dir.mkdir(parents=True, exist_ok=True)

    def _format_bytes(self, bytes_val: float) -> str:
        if bytes_val is None or bytes_val == 0:
            return "0 B"
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if abs(bytes_val) < 1024.0:
                return f"{bytes_val:.2f} {unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.2f} PB"

    def generate_all_reports(self):
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        logger.info("=" * 70)
        logger.info("GERANDO RELATÓRIOS FINAIS")
        logger.info("=" * 70)

        self._generate_daily_csv(timestamp)
        self._generate_summary_csv(timestamp)
        self._generate_text_report(timestamp)

        logger.info(f"Relatórios salvos em: {self.report_dir.absolute()}")

    def _generate_daily_csv(self, timestamp: str):
        filepath = self.report_dir / f"splunk_daily_report_{timestamp}.csv"
        daily_data = self.db.get_daily_summary()

        with open(filepath, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f, delimiter=";")
            writer.writerow([
                "Data",
                "Source [Index]",
                "Sourcetype",
                "Total Eventos",
                "Cobertura (segundos)",
                "Cobertura % (do dia)",
                "Total Payload (Bytes)",
                "Total Payload (MB)",
                "Total Payload (GB)",
                "Tamanho Médio Evento (Bytes)",
                "Qtd Coletas no Dia",
            ])
            for row in daily_data:
                total_bytes = row.get("total_bytes", 0) or 0
                writer.writerow([
                    row["collection_date"],
                    row["logsource_name"],
                    row["logsource_type"],
                    int(row.get("total_events", 0) or 0),
                    float(row.get("covered_seconds", 0) or 0),
                    "{:.2f}".format((float(row.get('covered_seconds', 0) or 0) / 86400.0) * 100.0),
                    f"{total_bytes:.0f}",
                    f"{total_bytes / (1024 * 1024):.4f}",
                    f"{total_bytes / (1024 * 1024 * 1024):.6f}",
                    f"{row.get('avg_event_size_bytes', 0):.2f}",
                    row["collection_count"],
                ])

        logger.info(f"Relatório diário CSV: {filepath}")

    def _generate_summary_csv(self, timestamp: str):
        filepath = self.report_dir / f"splunk_summary_report_{timestamp}.csv"
        summary = self.db.get_overall_daily_average()

        with open(filepath, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f, delimiter=";")
            writer.writerow([
                "Source [Index]",
                "Sourcetype",
                "Dias Coletados",
                "Média Diária de Eventos (projetado 24h)",
                "Cobertura média % (do dia)",
                "Média Diária Volume (Bytes) (projetado 24h)",
                "Média Diária Volume (MB)",
                "Média Diária Volume (GB)",
                "Tamanho Médio por Evento (Bytes)",
            ])
            for row in summary:
                writer.writerow([
                    row["logsource_name"],
                    row["logsource_type"],
                    row["days_collected"],
                    f"{row['avg_daily_events']:.0f}",
                    f"{row.get('avg_coverage_pct', 0):.2f}",
                    f"{row['avg_daily_bytes_total']:.0f}",
                    f"{row['avg_daily_mb']:.4f}",
                    f"{row['avg_daily_gb']:.6f}",
                    f"{row['avg_event_size_bytes']:.2f}",
                ])

        logger.info(f"Relatório resumo CSV: {filepath}")

    def _generate_text_report(self, timestamp: str):
        filepath = self.report_dir / f"splunk_full_report_{timestamp}.txt"
        dates = self.db.get_collection_dates()
        daily_data = self.db.get_daily_summary()
        summary = self.db.get_overall_daily_average()
        total_runs = self.db.get_total_runs()

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("=" * 100 + "\n")
            f.write("  RELATÓRIO DE INGESTÃO DE LOGS - Splunk\n")
            f.write(f"  Gerado em: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 100 + "\n\n")

            f.write("─" * 100 + "\n")
            f.write("  INFORMAÇÕES DA COLETA\n")
            f.write("─" * 100 + "\n")
            f.write(f"  Período de coleta: {dates[0] if dates else 'N/A'} a {dates[-1] if dates else 'N/A'}\n")
            f.write(f"  Total de dias coletados: {len(dates)}\n")
            f.write(f"  Total de execuções de coleta: {total_runs}\n")
            f.write(f"  Total de data sources identificados: {len(summary)}\n\n")

            # Detalhamento diário
            f.write("=" * 100 + "\n")
            f.write("  DETALHAMENTO DIÁRIO POR DATA SOURCE\n")
            f.write("=" * 100 + "\n\n")

            for date in dates:
                date_data = [d for d in daily_data if d["collection_date"] == date]
                total_events_day = sum(d.get("total_events", 0) for d in date_data)
                total_bytes_day = sum(d.get("total_bytes", 0) or 0 for d in date_data)

                f.write(f"┌{'─' * 98}┐\n")
                f.write(f"│  DATA: {date:<89}│\n")
                f.write(f"│  Total de Eventos: {total_events_day:>15,}  │  "
                        f"Volume Total: {self._format_bytes(total_bytes_day):>15}  │\n")
                f.write(f"├{'─' * 98}┤\n")
                f.write(f"│ {'Source [Index]':<35} │ {'Sourcetype':<20} │ {'Eventos':>12} │ "
                        f"{'Volume Total':>15} │ {'Avg/Evento':>12} │\n")
                f.write(f"├{'─' * 98}┤\n")

                for d in date_data:
                    name = (d["logsource_name"] or "Unknown")[:35]
                    ltype = (d["logsource_type"] or "Unknown")[:20]
                    events = d.get("total_events", 0)
                    total_b = d.get("total_bytes", 0) or 0
                    avg_b = d.get("avg_event_size_bytes", 0) or 0
                    f.write(f"│ {name:<35} │ {ltype:<20} │ {events:>12,} │ "
                            f"{self._format_bytes(total_b):>15} │ {self._format_bytes(avg_b):>12} │\n")

                f.write(f"└{'─' * 98}┘\n\n")

            # Resumo
            f.write("=" * 100 + "\n")
            f.write("  RESUMO - MÉDIA DIÁRIA DE INGESTÃO POR DATA SOURCE\n")
            f.write("=" * 100 + "\n\n")

            f.write(f"┌{'─' * 98}┐\n")
            f.write(f"│ {'Source [Index]':<30} │ {'Sourcetype':<18} │ {'Dias':>4} │ "
                    f"{'Avg Eventos/Dia':>15} │ {'Avg Volume/Dia':>15} │ {'Avg/Evento':>10} │\n")
            f.write(f"├{'─' * 98}┤\n")

            grand_total_avg_events = 0
            grand_total_avg_bytes = 0

            for s in summary:
                name = (s["logsource_name"] or "Unknown")[:30]
                ltype = (s["logsource_type"] or "Unknown")[:18]
                days = s.get("days_collected", 0)
                avg_ev = s.get("avg_daily_events", 0)
                avg_bytes = s.get("avg_daily_bytes_total", 0) or 0
                avg_evt_size = s.get("avg_event_size_bytes", 0) or 0
                grand_total_avg_events += avg_ev
                grand_total_avg_bytes += avg_bytes

                f.write(f"│ {name:<30} │ {ltype:<18} │ {days:>4} │ "
                        f"{avg_ev:>15,.0f} │ {self._format_bytes(avg_bytes):>15} │ "
                        f"{self._format_bytes(avg_evt_size):>10} │\n")

            f.write(f"├{'─' * 98}┤\n")
            f.write(f"│ {'TOTAL (soma das médias)':<30} │ {'':18} │ {'':>4} │ "
                    f"{grand_total_avg_events:>15,.0f} │ "
                    f"{self._format_bytes(grand_total_avg_bytes):>15} │ {'':>10} │\n")
            f.write(f"└{'─' * 98}┘\n\n")

            # Estimativa mensal
            f.write("─" * 100 + "\n")
            f.write("  ESTIMATIVA DE VOLUME MENSAL (baseada nas médias diárias)\n")
            f.write("─" * 100 + "\n\n")

            for s in summary:
                name = s["logsource_name"] or "Unknown"
                avg_daily_bytes = s.get("avg_daily_bytes_total", 0) or 0
                monthly_bytes = avg_daily_bytes * 30
                f.write(f"  {name:<40}  "
                        f"Diário: {self._format_bytes(avg_daily_bytes):>12}  │  "
                        f"Mensal (30d): {self._format_bytes(monthly_bytes):>12}\n")

            total_monthly = grand_total_avg_bytes * 30
            f.write(f"\n  {'TOTAL ESTIMADO':<40}  "
                    f"Diário: {self._format_bytes(grand_total_avg_bytes):>12}  │  "
                    f"Mensal (30d): {self._format_bytes(total_monthly):>12}\n")

            f.write("\n" + "=" * 100 + "\n")
            f.write("  FIM DO RELATÓRIO\n")
            f.write("=" * 100 + "\n")

        logger.info(f"Relatório completo em texto: {filepath}")


# ─────────────────────────────────────────────────────────────────────────────
# Função principal de coleta
# ─────────────────────────────────────────────────────────────────────────────
def run_collection_cycle(
    client: SplunkClient,
    db: MetricsDB,
    interval_hours: float,
    window_start_ms: int,
    window_end_ms: int,
    error_counter: Optional["ErrorCounter"] = None,
) -> int:
    """Executa um ciclo de coleta de métricas para uma janela exata."""
    now = datetime.datetime.now(datetime.timezone.utc)
    collection_time = now.isoformat()
    window_end_dt = datetime.datetime.fromtimestamp(
        (max(window_end_ms - 1, window_start_ms) / 1000.0), tz=datetime.timezone.utc
    )
    collection_date = window_end_dt.strftime("%Y-%m-%d")
    window_seconds = max(0.0, (window_end_ms - window_start_ms) / 1000.0)

    logger.info(
        f"Iniciando ciclo de coleta: {collection_time} | "
        f"janela: {window_seconds:.1f}s ({window_start_ms} -> {window_end_ms})"
    )

    run_id = db.save_collection_run(collection_time, collection_date, float(interval_hours))

    try:
        metrics = client.get_event_metrics_window(window_start_ms, window_end_ms)
    except Exception as exc:
        if error_counter:
            error_counter.inc("spl_query_failed")
        logger.error(f"Falha ao coletar métricas via SPL: {exc}")
        return 0

    seen_ids: set = set()
    ds_count = 0

    if metrics:
        db.save_event_metrics(
            run_id,
            collection_time,
            collection_date,
            int(window_start_ms),
            int(window_end_ms),
            float(window_seconds),
            metrics,
            float(interval_hours),
        )
        seen_ids = {int(m.get("logsourceid", 0)) for m in metrics}
        ds_count = len(metrics)
        logger.info(f"Coleta #{run_id} concluída: {ds_count} data sources com dados.")

        # Atualizar inventário com sources descobertos (Splunk não tem endpoint explícito
        # de "log sources" como o QRadar, então construímos a partir dos resultados SPL)
        inventory_entries = []
        for m in metrics:
            inventory_entries.append({
                "logsource_id": int(m.get("logsourceid", 0)),
                "name": m.get("log_source_name", "Unknown"),
                "type_name": m.get("log_source_type", "Unknown"),
                "description": "",
            })
        if inventory_entries:
            db.save_log_sources_inventory(inventory_entries)
    else:
        logger.warning(f"Coleta #{run_id} sem resultados (janela vazia ou fontes silenciosas).")
        if error_counter:
            error_counter.inc("spl_no_results")

    # Zero-fill
    zero_filled = db.fill_zero_event_rows(
        run_id, collection_time, collection_date,
        int(window_start_ms), int(window_end_ms), float(window_seconds),
        seen_ids, float(interval_hours),
    )
    if zero_filled > 0:
        logger.debug(f"Zero-fill: {zero_filled} sources sem eventos nesta janela.")

    return ds_count


def collect_inventory(client: SplunkClient, db: MetricsDB) -> int:
    """Coleta inventário inicial de indexes e sourcetypes."""
    logger.info("Coletando inventário de indexes...")
    try:
        indexes = client.get_indexes()
        if indexes:
            inventory = []
            for idx in indexes:
                ls_id = hash(f"index:{idx['name']}") % (10**9)
                inventory.append({
                    "logsource_id": ls_id,
                    "name": f"index:{idx['name']}",
                    "type_name": idx.get("datatype", "event"),
                    "description": f"Events: {idx.get('totalEventCount', 0)}, Size: {idx.get('currentDBSizeMB', 0)} MB",
                })
            db.save_log_sources_inventory(inventory)
            logger.info(f"Inventário inicial: {len(indexes)} indexes")
        return len(indexes)
    except Exception as e:
        logger.warning(f"Não foi possível coletar inventário: {e}")
        return 0


# ─────────────────────────────────────────────────────────────────────────────
# Configuração via arquivo
# ─────────────────────────────────────────────────────────────────────────────
def load_config(config_path: str) -> Dict:
    if config_path and os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def create_sample_config(path: str):
    sample = {
        "splunk_url": "https://splunk.example.com:8089",
        "auth_token": "YOUR_BEARER_TOKEN_HERE",
        "username": "",
        "password": "",
        "verify_ssl": False,
        "collection_days": 6,
        "interval_hours": 1,
        "db_file": "splunk_metrics.db",
        "report_dir": "reports",
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(sample, f, indent=4, ensure_ascii=False)
    logger.info(f"Arquivo de configuração de exemplo criado: {path}")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Splunk Log Ingestion Collector - Coleta métricas de ingestão por data source",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  # Rodar com Bearer Token (recomendado):
  python splunk_log_collector_v2.py --url https://splunk:8089 --token SEU_TOKEN

  # Rodar com usuário:senha:
  python splunk_log_collector_v2.py --url https://splunk:8089 --username admin --password SENHA

  # Rodar com arquivo de configuração:
  python splunk_log_collector_v2.py --config config.json

  # Rodar por 10 dias com coleta a cada 2 horas:
  python splunk_log_collector_v2.py --url https://splunk:8089 --token TOK --days 10 --interval 2

  # Gerar apenas relatório (após coleta):
  python splunk_log_collector_v2.py --report-only

  # Criar arquivo de configuração de exemplo:
  python splunk_log_collector_v2.py --create-config
        """,
    )

    parser.add_argument("--url", help="URL base do Splunk Management API (ex: https://splunk:8089)")
    parser.add_argument("--token", help="Bearer Token de autenticação do Splunk")
    parser.add_argument("--username", help="Username para autenticação Basic Auth")
    parser.add_argument("--password", help="Password para autenticação Basic Auth")
    parser.add_argument("--config", help="Caminho para arquivo de configuração JSON")
    parser.add_argument("--days", type=float, default=None,
                        help=f"Quantidade de dias para coleta (padrão: {DEFAULT_COLLECTION_DAYS})")
    parser.add_argument("--interval", type=float, default=None,
                        help=f"Intervalo de coleta em horas (padrão: {DEFAULT_INTERVAL_HOURS})")
    parser.add_argument("--db", default=None, help=f"Arquivo SQLite (padrão: {DEFAULT_DB_FILE})")
    parser.add_argument("--report-dir", default=None,
                        help=f"Diretório para relatórios (padrão: {DEFAULT_REPORT_DIR})")
    parser.add_argument("--verify-ssl", action="store_true", help="Verificar certificado SSL")
    parser.add_argument("--report-only", action="store_true",
                        help="Apenas gera relatório dos dados já coletados")
    parser.add_argument("--create-config", action="store_true",
                        help="Cria um arquivo config.json de exemplo e sai")
    parser.add_argument("--verbose", action="store_true", help="Modo verboso (debug)")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Criar config de exemplo
    if args.create_config:
        create_sample_config("config.json")
        print("Arquivo config.json criado! Edite-o com suas credenciais e rode novamente.")
        return

    # Carregar config
    config = load_config(args.config) if args.config else {}

    splunk_url = args.url or config.get("splunk_url", "")
    # Token: CLI > config > env > prompt
    auth_token = args.token or config.get("auth_token", "") or os.environ.get("SPLUNK_TOKEN", "")
    username = args.username or config.get("username", "")
    password = args.password or config.get("password", "")

    if not auth_token and not username and not args.report_only:
        print("\nModo de autenticação:")
        print("  1) Bearer Token (recomendado)")
        print("  2) Usuário e Senha")
        choice = input("Escolha (1/2): ").strip()
        if choice == "2":
            username = input("Username: ").strip()
            password = getpass.getpass("Password (input oculto): ")
        else:
            auth_token = getpass.getpass("Informe o Bearer Token do Splunk (input oculto): ")

    verify_ssl = args.verify_ssl or config.get("verify_ssl", False)
    collection_days = args.days if args.days is not None else config.get("collection_days", DEFAULT_COLLECTION_DAYS)
    interval_hours = args.interval if args.interval is not None else config.get("interval_hours", DEFAULT_INTERVAL_HOURS)
    db_file = args.db if args.db is not None else config.get("db_file", DEFAULT_DB_FILE)
    report_dir = args.report_dir if args.report_dir is not None else config.get("report_dir", DEFAULT_REPORT_DIR)

    # Modo somente relatório
    if args.report_only:
        if not os.path.exists(db_file):
            print(f"ERRO: Banco de dados '{db_file}' não encontrado. Execute a coleta primeiro.")
            sys.exit(1)

        db = MetricsDB(db_file)
        reporter = ReportGenerator(db, report_dir)
        reporter.generate_all_reports()
        db.close()
        print(f"\nRelatórios gerados em: {os.path.abspath(report_dir)}")
        return

    # Validar parâmetros
    if not splunk_url:
        print("ERRO: URL do Splunk não informada (--url ou config.json)")
        parser.print_help()
        sys.exit(1)

    if not auth_token and not (username and password):
        print("ERRO: Credenciais não informadas (--token, --username/--password, config.json, env SPLUNK_TOKEN ou prompt)")
        parser.print_help()
        sys.exit(1)

    # Iniciar coleta
    logger.info("=" * 70)
    logger.info("  Splunk Log Ingestion Collector")
    logger.info("=" * 70)
    logger.info(f"  Splunk URL    : {splunk_url}")
    logger.info(f"  Auth Mode     : {'Bearer Token' if auth_token else 'Basic Auth'}")
    logger.info(f"  Dias de coleta: {collection_days}")
    logger.info(f"  Intervalo     : {interval_hours}h")
    logger.info(f"  Banco de dados: {db_file}")
    logger.info(f"  Relatórios em : {report_dir}")
    logger.info(f"  SSL Verify    : {verify_ssl}")
    logger.info("=" * 70)

    total_hours = collection_days * 24
    total_collections = int(total_hours / interval_hours)
    interval_seconds = interval_hours * 3600

    logger.info(f"  Total estimado de coletas: {total_collections}")
    logger.info(f"  Término estimado: {datetime.datetime.now() + datetime.timedelta(days=collection_days)}")
    logger.info("  Pressione Ctrl+C para parar (relatório será gerado)")
    logger.info("=" * 70)

    # Criar cliente e banco
    client = SplunkClient(
        base_url=splunk_url,
        token=auth_token,
        username=username,
        password=password,
        verify_ssl=verify_ssl,
    )
    db = MetricsDB(db_file)

    # Teste de conexão
    try:
        client.test_connection()
    except (requests.exceptions.HTTPError, requests.exceptions.ConnectionError):
        print("\nERRO: Não foi possível conectar ao Splunk. Verifique URL e credenciais.")
        db.close()
        sys.exit(1)
    except Exception as e:
        logger.error(f"Erro inesperado no teste de conexão: {e}")
        db.close()
        sys.exit(1)

    # Inventário inicial
    try:
        inv_count = collect_inventory(client, db)
        logger.info(f"Inventário inicial: {inv_count} indexes")
    except Exception as e:
        logger.warning(f"Não foi possível coletar inventário: {e}")

    # Loop de coleta
    start_monotonic = time.monotonic()
    end_monotonic = start_monotonic + (total_hours * 3600)
    collection_count = 0
    error_counter = ErrorCounter()

    last_window_end_ms: Optional[int] = None

    while not STOP_SIGNAL:
        now_monotonic = time.monotonic()
        if now_monotonic >= end_monotonic:
            logger.info("Período de coleta concluído!")
            break

        window_end_ms = int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000)
        if last_window_end_ms is None:
            window_start_ms = window_end_ms - int(interval_seconds * 1000)
        else:
            window_start_ms = last_window_end_ms
            max_window_ms = int(interval_seconds * 1000 * MAX_CATCHUP_WINDOWS)
            if (window_end_ms - window_start_ms) > max_window_ms:
                lost_start = window_start_ms
                window_start_ms = window_end_ms - max_window_ms
                logger.warning(
                    f"Catch-up excedeu limite ({MAX_CATCHUP_WINDOWS}x intervalo). "
                    f"Dados de {lost_start} a {window_start_ms} serão perdidos."
                )

        try:
            ds_count = run_collection_cycle(
                client=client,
                db=db,
                interval_hours=float(interval_hours),
                window_start_ms=int(window_start_ms),
                window_end_ms=int(window_end_ms),
                error_counter=error_counter,
            )
            collection_count += 1
            last_window_end_ms = window_end_ms

            remaining_seconds = max(0.0, end_monotonic - time.monotonic())
            remaining_hours = remaining_seconds / 3600.0
            remaining_collections = max(0, total_collections - collection_count)

            logger.info(
                f"Progresso: coleta {collection_count}/{total_collections} | "
                f"Data sources: {ds_count} | "
                f"Restante: {remaining_hours:.2f}h ({remaining_collections} coletas) | "
                f"Erros: {error_counter.summary_line()}"
            )

        except requests.exceptions.ConnectionError as e:
            error_counter.inc("connection_error")
            collection_count += 1
            logger.error(f"Erro de conexão com Splunk: {e}")
            logger.info("Tentando novamente no próximo intervalo (catch-up automático)...")
        except requests.exceptions.HTTPError as e:
            error_counter.inc("http_error")
            collection_count += 1
            logger.error(f"Erro HTTP da API Splunk: {e}")
            if hasattr(e, "response") and e.response is not None:
                logger.error(f"Status: {e.response.status_code}, Body: {e.response.text[:500]}")
        except Exception as e:
            error_counter.inc("unexpected_error")
            collection_count += 1
            logger.error(f"Erro inesperado durante coleta: {e}", exc_info=True)

        # Aguardar próximo intervalo
        if STOP_SIGNAL:
            break

        next_run_monotonic = start_monotonic + (collection_count * interval_seconds)
        sleep_seconds = max(0.0, next_run_monotonic - time.monotonic())
        if sleep_seconds > 0:
            logger.info(f"Próxima coleta em ~{sleep_seconds/3600.0:.2f}h. Aguardando...")
            wait_start = time.monotonic()
            while (time.monotonic() - wait_start) < sleep_seconds and not STOP_SIGNAL:
                time.sleep(min(30.0, sleep_seconds))

    # Gerar relatório final
    logger.info("\n")
    logger.info("Coleta finalizada. Gerando relatórios...")

    reporter = ReportGenerator(db, report_dir)
    reporter.generate_all_reports()

    db.close()

    logger.info("\n")
    logger.info("=" * 70)
    if error_counter.as_dict():
        logger.warning("  COLETA FINALIZADA COM ALERTAS/ERROS (ver log e contadores)!")
        logger.warning(f"  Contadores: {error_counter.summary_line()}")
    else:
        logger.info("  COLETA FINALIZADA COM SUCESSO!")
    logger.info(f"  Total de coletas realizadas: {collection_count}")
    logger.info(f"  Relatórios gerados em: {os.path.abspath(report_dir)}")
    logger.info("=" * 70)


if __name__ == "__main__":
    main()
