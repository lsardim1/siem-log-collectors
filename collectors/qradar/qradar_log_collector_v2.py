#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
QRadar Log Ingestion Collector
===============================
Script para coletar informações de ingestão de logs do IBM QRadar via REST API.
Roda continuamente por N dias (padrão: 6), coleta métricas a cada intervalo
configurável e gera relatório final com médias diárias por data source.

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
from pathlib import Path
from typing import Any, Dict, List, Optional

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
DEFAULT_DB_FILE = "qradar_metrics.db"
DEFAULT_REPORT_DIR = "reports"
AQL_TIMEOUT_SECONDS = 300           # Timeout para queries AQL
AQL_POLL_INTERVAL = 5               # Intervalo de polling para queries AQL
RETRY_MAX_ATTEMPTS = 3              # Máximo de retentativas
RETRY_BASE_DELAY = 2               # Delay base em segundos para backoff
RETRYABLE_HTTP_STATUSES = (429, 500, 502, 503, 504)
MAX_CATCHUP_WINDOWS = 3             # Máx. de intervalos para catch-up em caso de falha

# ─────────────────────────────────────────────────────────────────────────────
# Logger
# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("qradar_collector.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Variável global para controle de parada graciosa
# ─────────────────────────────────────────────────────────────────────────────
STOP_SIGNAL = False


class ErrorCounter:
    """Contador simples de erros/avisos por categoria, inspirado no script de pipeline."""

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
# Classe principal de conexão com QRadar
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

        # Se for 429 e houver Retry-After, respeitar (quando parseável)
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


def _validate_json_response(resp: requests.Response, endpoint: str) -> Any:
    """
    Valida que a resposta é JSON válido e não HTML de erro.
    """
    text = resp.text[:200].lower().lstrip()
    if text.startswith(('<!doctype', '<html', '<head')):
        raise ValueError(
            f"Esperado JSON de {endpoint} mas recebeu HTML: {resp.text[:200]}"
        )
    return resp.json()


class QRadarClient:
    """Cliente REST para o IBM QRadar."""

    def __init__(self, base_url: str, api_token: str, verify_ssl: bool = False, api_version: str = "26.0"):
        self.base_url = base_url.rstrip("/")
        self.api_token = api_token
        self.verify_ssl = verify_ssl
        self.api_version = api_version
        self.session = requests.Session()
        self.session.headers.update({
            "SEC": self.api_token,
            "Accept": "application/json",
            "Version": self.api_version,
        })
        self.session.verify = self.verify_ssl

    # ── Validação de resposta (espelho de _check_http_status do modelo) ──
    def _check_response(self, resp: requests.Response, endpoint: str) -> None:
        """Verifica status HTTP e fornece mensagens acionáveis para erros comuns."""
        if resp.status_code == 401:
            raise requests.exceptions.HTTPError(
                f"HTTP 401 Unauthorized de {endpoint}. "
                "Verifique se o token API (SEC) está correto e não expirado.",
                response=resp,
            )
        if resp.status_code == 403:
            raise requests.exceptions.HTTPError(
                f"HTTP 403 Forbidden de {endpoint}. "
                "O token API não possui as permissões necessárias.",
                response=resp,
            )
        resp.raise_for_status()

    def _get(self, endpoint: str, params: Optional[Dict] = None,
             extra_headers: Optional[Dict] = None) -> Any:
        """Faz GET request para a API do QRadar com retry e validação."""
        url = f"{self.base_url}/api/{endpoint}"
        logger.debug(f"GET {url} params={params} headers={extra_headers}")

        def _do_request():
            resp = self.session.get(url, params=params, headers=extra_headers, timeout=60)
            self._check_response(resp, endpoint)
            return _validate_json_response(resp, endpoint)

        return _retry_with_backoff(_do_request)

    def _post(self, endpoint: str, params: Optional[Dict] = None, data: Any = None) -> Any:
        """Faz POST request para a API do QRadar com retry e validação."""
        url = f"{self.base_url}/api/{endpoint}"
        logger.debug(f"POST {url} params={params}")

        def _do_request():
            resp = self.session.post(url, params=params, json=data, timeout=60)
            self._check_response(resp, endpoint)
            return _validate_json_response(resp, endpoint)

        return _retry_with_backoff(_do_request)

    # ── Log Sources ──────────────────────────────────────────────────────
    def _paginate_endpoint(self, endpoint: str, page_size: int = 500) -> List[Dict]:
        """Pagina um endpoint da API QRadar usando Range headers (padrão QRadar)."""
        all_items = []
        offset = 0
        while True:
            headers = {
                "Range": f"items={offset}-{offset + page_size - 1}",
            }
            try:
                batch = self._get(endpoint, extra_headers=headers)
                if not batch:
                    break
                all_items.extend(batch)
                if len(batch) < page_size:
                    break
                offset += page_size
            except requests.exceptions.HTTPError as e:
                if e.response is not None and e.response.status_code == 416:
                    break
                raise
        return all_items

    # ── Teste de conexão (Phase 0 — equivalente ao InitHandler do modelo) ──
    def test_connection(self) -> Dict:
        """Testa conectividade com o QRadar via /api/system/about.

        Deve ser chamado antes de qualquer operação para validar
        URL, token e rede.

        Returns:
            dict: Informações do QRadar (versão, etc.).
        """
        logger.info(f"Testando conexão com {self.base_url}...")
        try:
            info = self._get("system/about")
            version = info.get("external_version", info.get("version", "desconhecida"))
            logger.info(f"Conexão OK — QRadar versão: {version}")
            return info
        except requests.exceptions.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else 0
            if status == 401:
                logger.error(
                    "Falha de autenticação (HTTP 401). "
                    "Verifique se o token SEC está correto e não expirou."
                )
            elif status == 403:
                logger.error(
                    "Acesso negado (HTTP 403). "
                    "O token SEC não tem permissões suficientes."
                )
            else:
                logger.error(f"Erro HTTP {status} ao testar conexão.")
            raise
        except requests.exceptions.ConnectionError:
            logger.error(
                f"Não foi possível conectar a {self.base_url}. "
                "Verifique se a URL está correta e a rede acessível."
            )
            raise

    def get_log_sources(self) -> List[Dict]:
        """Retorna todas as log sources configuradas no QRadar."""
        log_sources = self._paginate_endpoint(
            "config/event_sources/log_source_management/log_sources", page_size=500
        )
        logger.info(f"Total de log sources encontradas: {len(log_sources)}")
        return log_sources

    def get_log_source_types(self) -> Dict[int, str]:
        """Retorna mapeamento de type_id → nome do tipo de log source (com paginação)."""
        types_map = {}
        try:
            types_list = self._paginate_endpoint(
                "config/event_sources/log_source_management/log_source_types", page_size=1000
            )
            for t in types_list:
                types_map[t.get("id")] = t.get("name", f"Unknown-{t.get('id')}")
        except Exception as e:
            logger.warning(f"Não foi possível obter tipos de log source: {e}")
        return types_map

    # ── AQL Queries ──────────────────────────────────────────────────────
    def run_aql_query(self, aql: str) -> Optional[List[Dict]]:
        """Executa uma query AQL e aguarda resultado."""
        logger.info(f"Executando AQL: {aql[:120]}...")
        try:
            search = self._post("ariel/searches", params={"query_expression": aql})
        except requests.exceptions.HTTPError as e:
            logger.error(f"Erro ao iniciar query AQL: {e}")
            return None

        search_id = search.get("search_id")
        if not search_id:
            logger.error("Não foi possível obter search_id da query AQL.")
            return None

        # Polling até completar
        start = time.time()
        while True:
            if time.time() - start > AQL_TIMEOUT_SECONDS:
                logger.error(f"Timeout aguardando query AQL {search_id}")
                return None

            status = self._get(f"ariel/searches/{search_id}")
            progress = status.get("progress", 0)
            query_status = status.get("status", "UNKNOWN")

            if query_status == "COMPLETED":
                break
            elif query_status in ("CANCELED", "ERROR"):
                logger.error(f"Query AQL falhou com status: {query_status}")
                return None

            logger.debug(f"AQL search {search_id}: {query_status} ({progress}%)")
            time.sleep(AQL_POLL_INTERVAL)

        # Buscar resultados (com Range para segurança em ambientes com muitos log sources)
        try:
            results = self._get(
                f"ariel/searches/{search_id}/results",
                extra_headers={"Range": "items=0-9999"},
            )
            return results.get("events", results.get("flows", []))
        except Exception as e:
            logger.error(f"Erro ao buscar resultados AQL: {e}")
            return None

    def get_event_counts_by_logsource(self, start_time: int, end_time: int) -> Optional[List[Dict]]:
        """
        [DEPRECATED] Mantido apenas por compatibilidade.

        Preferir: get_event_metrics_window(start_time_ms, end_time_ms)

        Motivo: esta função existia antes da correção de finalidade e era fácil
        utilizá-la de forma incorreta com fronteiras inclusivas (double-count).
        Agora ela usa a mesma convenção do coletor principal:

          starttime >= start_time AND starttime < end_time

        Além disso, passa a expor:
          - total_event_count = SUM(eventcount)
          - aggregated_event_count = COUNT(*)

        Parâmetros:
          start_time: epoch ms (início, inclusivo)
          end_time:   epoch ms (fim, exclusivo)
        """
        aql = (
            f"SELECT logsourceid, "
            f"LOGSOURCENAME(logsourceid) as log_source_name, "
            f"LOGSOURCETYPENAME(devicetype) as log_source_type, "
            f"SUM(eventcount) as total_event_count, "
            f"COUNT(*) as aggregated_event_count, "
            f"SUM(STRLEN(UTF8(payload))) as total_payload_bytes, "
            f"AVG(STRLEN(UTF8(payload))) as avg_payload_bytes, "
            f"MIN(STRLEN(UTF8(payload))) as min_payload_bytes, "
            f"MAX(STRLEN(UTF8(payload))) as max_payload_bytes "
            f"FROM events "
            f"WHERE starttime >= {start_time} AND starttime < {end_time} "
            f"GROUP BY logsourceid, devicetype "
            f"ORDER BY total_event_count DESC"
        )
        return self.run_aql_query(aql)


    def get_event_metrics_window(self, start_time_ms: int, end_time_ms: int) -> Optional[List[Dict]]:
        """
        Coleta métricas de ingestão *armazenada no Ariel* para um intervalo exato.

        IMPORTANTE:
        - "total_event_count" é calculado via SUM(eventcount) quando disponível (mais fiel ao total de eventos).
        - "aggregated_event_count" é COUNT(*) (registros/linhas agregadas no Ariel; pode ser menor que o total real).
        - Métricas de "payload" usam STRLEN(UTF8(payload)) sobre o payload armazenado.
        - Opcionalmente tenta coletar métricas de "unparsed". Se o campo não existir no ambiente,
          o coletor faz fallback sem essas colunas.
        """
        # Preferimos WHERE starttime, pois permite janelas fracionadas (minutos/segundos).
        # starttime em QRadar Ariel é epoch em milissegundos.
        base_select = (
            "SELECT logsourceid, "
            "LOGSOURCENAME(logsourceid) as log_source_name, "
            "LOGSOURCETYPENAME(devicetype) as log_source_type, "
            "COUNT(*) as aggregated_event_count, "
            "SUM(eventcount) as total_event_count, "
            "SUM(STRLEN(UTF8(payload))) as total_payload_bytes, "
            "AVG(STRLEN(UTF8(payload))) as avg_payload_bytes "
        )

        where_clause = (
            f"FROM events WHERE starttime >= {int(start_time_ms)} AND starttime < {int(end_time_ms)} "
            "GROUP BY logsourceid, devicetype "
            "ORDER BY total_event_count DESC"
        )

        # Tentativa 1: incluir métricas de unparsed (pode não existir em alguns ambientes)
        aql_with_unparsed = (
            base_select
            + ", SUM(CASE WHEN isunparsed=1 THEN 1 ELSE 0 END) as unparsed_aggregated_events, "
              "SUM(CASE WHEN isunparsed=1 THEN eventcount ELSE 0 END) as unparsed_total_events "
            + where_clause
        )

        try:
            data = self.run_aql_query(aql_with_unparsed)
            if data is not None:
                return data
        except Exception as exc:
            logger.debug(f"AQL com unparsed falhou; fazendo fallback sem unparsed. Motivo: {exc}")

        # Fallback: sem unparsed
        aql = base_select + where_clause
        return self.run_aql_query(aql)

    def get_event_counts_last_n_hours(self, hours: int = 1) -> Optional[List[Dict]]:
        """
        Compat: mantém a API antiga, mas agora baseada em janela exata.
        """
        end_ms = int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000)
        start_ms = int((datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=hours)).timestamp() * 1000)
        return self.get_event_metrics_window(start_ms, end_ms)

    def get_flow_counts_by_logsource(self, hours: int = 1) -> Optional[List[Dict]]:
        """Busca contagem de flows por log source nas últimas N horas."""
        time_clause = f"LAST {hours} HOURS" if hours <= 24 else f"LAST {hours // 24} DAYS"
        aql = (
            f"SELECT sourceip, "
            f"COUNT(*) as flow_count, "
            f"SUM(sourcebytes + destinationbytes) as total_bytes "
            f"FROM flows "
            f"GROUP BY sourceip "
            f"ORDER BY flow_count DESC "
            f"{time_clause}"
        )
        return self.run_aql_query(aql)


# ─────────────────────────────────────────────────────────────────────────────
# Banco de dados local (SQLite)
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
                -- Compat (antigo): mantenha, mas não use como fonte principal
                event_count INTEGER DEFAULT 0,
                -- Novos campos (fonte principal)
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
        self._ensure_event_metrics_schema(cursor)
        self.conn.commit()

    
    def _ensure_event_metrics_schema(self, cursor: sqlite3.Cursor) -> None:
        """Garante que colunas novas existam em bases antigas (migração leve via ALTER TABLE)."""
        try:
            cursor.execute("PRAGMA table_info(event_metrics)")
            existing = {row[1] for row in cursor.fetchall()}
        except Exception:
            return

        # (coluna, tipo, default_sql)
        desired = [
            ("window_start_ms", "INTEGER", None),
            ("window_end_ms", "INTEGER", None),
            ("window_seconds", "REAL", None),
            ("aggregated_event_count", "INTEGER", "0"),
            ("total_event_count", "INTEGER", "0"),
            ("unparsed_aggregated_events", "INTEGER", "0"),
            ("unparsed_total_events", "INTEGER", "0"),
        ]

        for col, col_type, default_val in desired:
            if col in existing:
                continue
            try:
                if default_val is None:
                    cursor.execute(f"ALTER TABLE event_metrics ADD COLUMN {col} {col_type}")
                else:
                    cursor.execute(f"ALTER TABLE event_metrics ADD COLUMN {col} {col_type} DEFAULT {default_val}")
            except Exception as exc:
                logger.debug(f"Não foi possível adicionar coluna {col} em event_metrics: {exc}")

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
            # Alguns ambientes podem não preencher SUM(eventcount); fallback para aggregated
            total = int(total) if total is not None else aggregated

            unparsed_agg = int(m.get("unparsed_aggregated_events", 0) or 0)
            unparsed_total = m.get("unparsed_total_events", None)
            unparsed_total = int(unparsed_total) if unparsed_total is not None else 0

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
                    # compat
                    aggregated,
                    aggregated,
                    total,
                    unparsed_agg,
                    unparsed_total,
                    m.get("total_payload_bytes", 0) or 0,
                    m.get("avg_payload_bytes", 0) or 0,
                    float(interval_hours),
                ),
            )
        self.conn.commit()
        logger.info(f"Salvos {len(metrics)} registros de métricas (run_id={run_id})")

    def save_log_sources_inventory(self, log_sources: List[Dict], type_map: Dict[int, str]):
        cursor = self.conn.cursor()
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        for ls in log_sources:
            type_id = ls.get("type_id", 0)
            cursor.execute(
                """INSERT OR REPLACE INTO log_sources_inventory 
                   (logsource_id, name, type_name, type_id, enabled, description, last_updated)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    ls.get("id", 0),
                    ls.get("name", "Unknown"),
                    type_map.get(type_id, f"Type-{type_id}"),
                    type_id,
                    1 if ls.get("enabled", False) else 0,
                    ls.get("description", ""),
                    now,
                ),
            )
        self.conn.commit()
        logger.info(f"Inventário de {len(log_sources)} log sources salvo.")

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
        """Insere linhas com zero eventos para log sources do inventário ausentes na AQL.

        Sem isso, 'covered_seconds' só conta janelas onde houve eventos,
        inflando projeções 24h para fontes intermitentes. Com o zero-fill,
        toda janela observada conta como cobertura — mesmo que sem dados —
        tornando a projeção diária matematicamente correta.
        """
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
        """Retorna resumo diário por log source.

        Observação: usa total_event_count (SUM(eventcount)) quando disponível, por ser mais fiel ao total de eventos.
        """
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
        """Retorna média diária geral por log source (across all days).

        Para tornar a métrica mais fiel quando há falhas/lacunas, calcula a projeção para 24h baseada no tempo
        efetivamente coberto (soma de window_seconds).
        """
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
        """Retorna lista de datas de coleta únicas."""
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
        """Formata bytes em unidade legível."""
        if bytes_val is None or bytes_val == 0:
            return "0 B"
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if abs(bytes_val) < 1024.0:
                return f"{bytes_val:.2f} {unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.2f} PB"

    def generate_all_reports(self):
        """Gera todos os relatórios."""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        logger.info("=" * 70)
        logger.info("GERANDO RELATÓRIOS FINAIS")
        logger.info("=" * 70)

        self._generate_daily_csv(timestamp)
        self._generate_summary_csv(timestamp)
        self._generate_text_report(timestamp)

        logger.info(f"Relatórios salvos em: {self.report_dir.absolute()}")

    def _generate_daily_csv(self, timestamp: str):
        """Gera CSV com detalhamento diário."""
        filepath = self.report_dir / f"qradar_daily_report_{timestamp}.csv"
        daily_data = self.db.get_daily_summary()

        with open(filepath, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f, delimiter=";")
            writer.writerow([
                "Data",
                "Log Source",
                "Tipo Log Source",
                "Total Eventos (SUM(eventcount))",
                "Eventos Agregados (COUNT(*))",
                "Eventos Unparsed (SUM)",
                "Unparsed % (sobre total)",
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
                    int(row.get("aggregated_events", 0) or 0),
                    int(row.get("unparsed_total_events", 0) or 0),
                    "{:.2f}".format((float(row.get('unparsed_total_events', 0) or 0) / float(row.get('total_events', 1) or 1)) * 100.0),
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
        """Gera CSV com resumo de médias por data source."""
        filepath = self.report_dir / f"qradar_summary_report_{timestamp}.csv"
        summary = self.db.get_overall_daily_average()

        with open(filepath, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f, delimiter=";")
            writer.writerow([
                "Log Source",
                "Tipo Log Source",
                "Dias Coletados",
                "Média Diária de Eventos (projetado 24h)",
                "Média Diária Eventos Agregados (projetado 24h)",
                "Média Diária Eventos Unparsed (projetado 24h)",
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
                    f"{row.get('avg_daily_aggregated_events', 0):.0f}",
                    f"{row.get('avg_daily_unparsed_events', 0):.0f}",
                    f"{row.get('avg_coverage_pct', 0):.2f}",
                    f"{row['avg_daily_bytes_total']:.0f}",
                    f"{row['avg_daily_mb']:.4f}",
                    f"{row['avg_daily_gb']:.6f}",
                    f"{row['avg_event_size_bytes']:.2f}",
                ])

        logger.info(f"Relatório resumo CSV: {filepath}")

    def _generate_text_report(self, timestamp: str):
        """Gera relatório em texto formatado."""
        filepath = self.report_dir / f"qradar_full_report_{timestamp}.txt"
        dates = self.db.get_collection_dates()
        daily_data = self.db.get_daily_summary()
        summary = self.db.get_overall_daily_average()
        total_runs = self.db.get_total_runs()

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("=" * 100 + "\n")
            f.write("  RELATÓRIO DE INGESTÃO DE LOGS - IBM QRadar\n")
            f.write(f"  Gerado em: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 100 + "\n\n")

            # Informações gerais
            f.write("─" * 100 + "\n")
            f.write("  INFORMAÇÕES DA COLETA\n")
            f.write("─" * 100 + "\n")
            f.write(f"  Período de coleta: {dates[0] if dates else 'N/A'} a {dates[-1] if dates else 'N/A'}\n")
            f.write(f"  Total de dias coletados: {len(dates)}\n")
            f.write(f"  Total de execuções de coleta: {total_runs}\n")
            f.write(f"  Total de data sources identificados: {len(summary)}\n\n")

            # ── Detalhamento diário ──────────────────────────────────────
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
                f.write(f"│ {'Log Source':<35} │ {'Tipo':<20} │ {'Eventos':>12} │ "
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

            # ── Resumo Geral (Médias) ────────────────────────────────────
            f.write("=" * 100 + "\n")
            f.write("  RESUMO - MÉDIA DIÁRIA DE INGESTÃO POR DATA SOURCE\n")
            f.write("=" * 100 + "\n\n")

            f.write(f"┌{'─' * 98}┐\n")
            f.write(f"│ {'Log Source':<30} │ {'Tipo':<18} │ {'Dias':>4} │ "
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

            # ── Estimativa de volume mensal ──────────────────────────────
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
    client: QRadarClient,
    db: MetricsDB,
    interval_hours: float,
    window_start_ms: int,
    window_end_ms: int,
    error_counter: Optional["ErrorCounter"] = None,
) -> int:
    """Executa um ciclo de coleta de métricas para uma janela exata.

    A finalidade aqui é medir, com o máximo de fidelidade possível via Ariel:
    - total_event_count (SUM(eventcount)) = total de eventos (preferível para "ingestão")
    - aggregated_event_count (COUNT(*)) = registros agregados/coalescidos (útil como indicador de coalescing)
    - payload_bytes = volume do payload armazenado
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    collection_time = now.isoformat()
    # IMPORTANT: usar a janela coletada (e não o 'agora') para definir a data.
    # Isso evita que uma janela do dia anterior (ex.: 23:00-00:00) seja contabilizada no dia seguinte.
    window_end_dt = datetime.datetime.fromtimestamp((max(window_end_ms - 1, window_start_ms) / 1000.0), tz=datetime.timezone.utc)
    collection_date = window_end_dt.strftime("%Y-%m-%d")
    window_seconds = max(0.0, (window_end_ms - window_start_ms) / 1000.0)

    logger.info(
        f"Iniciando ciclo de coleta: {collection_time} | "
        f"janela: {window_seconds:.1f}s ({window_start_ms} -> {window_end_ms})"
    )

    # Registrar execução
    run_id = db.save_collection_run(collection_time, collection_date, float(interval_hours))

    try:
        metrics = client.get_event_metrics_window(window_start_ms, window_end_ms)
    except Exception as exc:
        if error_counter:
            error_counter.inc("aql_query_failed")
        logger.error(f"Falha ao coletar métricas via AQL: {exc}")
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
    else:
        logger.warning(f"Coleta #{run_id} sem resultados (janela vazia ou fontes silenciosas).")
        if error_counter:
            error_counter.inc("aql_no_results")

    # Zero-fill: garante que log sources inativos contam como "observados com 0",
    # evitando superestimativa nas projeções 24h para fontes intermitentes.
    zero_filled = db.fill_zero_event_rows(
        run_id, collection_time, collection_date,
        int(window_start_ms), int(window_end_ms), float(window_seconds),
        seen_ids, float(interval_hours),
    )
    if zero_filled > 0:
        logger.debug(f"Zero-fill: {zero_filled} log sources sem eventos nesta janela.")

    return ds_count


def collect_inventory(client: QRadarClient, db: MetricsDB) -> int:
    """Coleta inventário de log sources uma vez."""
    logger.info("Coletando inventário de log sources...")
    try:
        log_sources = client.get_log_sources()
        type_map = client.get_log_source_types()
        db.save_log_sources_inventory(log_sources, type_map)
        return len(log_sources)
    except Exception as e:
        logger.error(f"Erro ao coletar inventário: {e}")
        return 0


# ─────────────────────────────────────────────────────────────────────────────
# Configuração via arquivo (opcional)
# ─────────────────────────────────────────────────────────────────────────────
def load_config(config_path: str) -> Dict:
    """Carrega configurações de um arquivo JSON."""
    if config_path and os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def create_sample_config(path: str):
    """Cria arquivo de configuração de exemplo."""
    sample = {
        "qradar_url": "https://qradar.example.com",
        "api_token": "YOUR_API_TOKEN_HERE",
        "verify_ssl": False,
        "api_version": "26.0",
        "collection_days": 6,
        "interval_hours": 1,
        "db_file": "qradar_metrics.db",
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
        description="QRadar Log Ingestion Collector - Coleta métricas de ingestão por data source",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  # Rodar com parâmetros diretos (6 dias, coleta a cada 1h):
  python qradar_log_collector.py --url https://qradar:443 --token SEU_TOKEN

  # Rodar com arquivo de configuração:
  python qradar_log_collector.py --config config.json

  # Rodar por 5 dias com coleta a cada 2 horas:
  python qradar_log_collector.py --url https://qradar:443 --token SEU_TOKEN --days 5 --interval 2

  # Gerar apenas relatório (após coleta):
  python qradar_log_collector.py --report-only

  # Criar arquivo de configuração de exemplo:
  python qradar_log_collector.py --create-config
        """,
    )

    parser.add_argument("--url", help="URL base do QRadar (ex: https://qradar.empresa.com)")
    parser.add_argument("--token", help="API Token do QRadar (SEC token)")
    parser.add_argument("--config", help="Caminho para arquivo de configuração JSON")
    parser.add_argument("--days", type=float, default=None,
                        help=f"Quantidade de dias para coleta (padrão: {DEFAULT_COLLECTION_DAYS})")
    parser.add_argument("--interval", type=float, default=None,
                        help=f"Intervalo de coleta em horas (padrão: {DEFAULT_INTERVAL_HOURS})")
    parser.add_argument("--db", default=None, help=f"Arquivo SQLite (padrão: {DEFAULT_DB_FILE})")
    parser.add_argument("--report-dir", default=None,
                        help=f"Diretório para relatórios (padrão: {DEFAULT_REPORT_DIR})")
    parser.add_argument("--verify-ssl", action="store_true", help="Verificar certificado SSL")
    parser.add_argument("--api-version", default=None, help="Versão da API QRadar (padrão: 26.0)")
    parser.add_argument("--report-only", action="store_true",
                        help="Apenas gera relatório dos dados já coletados")
    parser.add_argument("--create-config", action="store_true",
                        help="Cria um arquivo config.json de exemplo e sai")
    parser.add_argument("--verbose", action="store_true", help="Modo verboso (debug)")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # ── Criar config de exemplo ──────────────────────────────────────────
    if args.create_config:
        create_sample_config("config.json")
        print("Arquivo config.json criado! Edite-o com suas credenciais e rode novamente.")
        return

    # ── Carregar config de arquivo se fornecido ──────────────────────────
    config = load_config(args.config) if args.config else {}

    qradar_url = args.url or config.get("qradar_url", "")
    # Ordem de prioridade do token:
    # 1) CLI --token (útil para execução ad-hoc)
    # 2) config.json (útil para operação controlada; cuidado para não versionar o arquivo)
    # 3) variável de ambiente QRADAR_TOKEN (recomendado para automação)
    # 4) prompt seguro (fallback interativo)
    api_token = args.token or config.get("api_token", "") or os.environ.get("QRADAR_TOKEN", "")
    if not api_token and not args.report_only:
        try:
            api_token = getpass.getpass("Informe o API Token do QRadar (input oculto): ")
        except Exception:
            api_token = ""
    verify_ssl = args.verify_ssl or config.get("verify_ssl", False)
    api_version = args.api_version if args.api_version is not None else config.get("api_version", "26.0")
    collection_days = args.days if args.days is not None else config.get("collection_days", DEFAULT_COLLECTION_DAYS)
    interval_hours = args.interval if args.interval is not None else config.get("interval_hours", DEFAULT_INTERVAL_HOURS)
    db_file = args.db if args.db is not None else config.get("db_file", DEFAULT_DB_FILE)
    report_dir = args.report_dir if args.report_dir is not None else config.get("report_dir", DEFAULT_REPORT_DIR)

    # ── Modo somente relatório ───────────────────────────────────────────
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

    # ── Validar parâmetros ───────────────────────────────────────────────
    if not qradar_url:
        print("ERRO: URL do QRadar não informada (--url ou config.json)")
        parser.print_help()
        sys.exit(1)

    if not api_token:
        print("ERRO: API Token do QRadar não informado (--token, config.json, env QRADAR_TOKEN ou prompt)")
        parser.print_help()
        sys.exit(1)

    # ── Iniciar coleta ───────────────────────────────────────────────────
    logger.info("=" * 70)
    logger.info("  QRadar Log Ingestion Collector")
    logger.info("=" * 70)
    logger.info(f"  QRadar URL    : {qradar_url}")
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
    client = QRadarClient(qradar_url, api_token, verify_ssl, api_version)
    db = MetricsDB(db_file)

    # Teste de conexão (Phase 0 — equivalente ao InitHandler do modelo)
    try:
        client.test_connection()
    except (requests.exceptions.HTTPError, requests.exceptions.ConnectionError):
        print("\nERRO: Não foi possível conectar ao QRadar. Verifique URL e token.")
        db.close()
        sys.exit(1)
    except Exception as e:
        logger.error(f"Erro inesperado no teste de conexão: {e}")
        db.close()
        sys.exit(1)

    # Coletar inventário inicial
    try:
        inv_count = collect_inventory(client, db)
        logger.info(f"Inventário inicial: {inv_count} log sources")
    except Exception as e:
        logger.warning(f"Não foi possível coletar inventário: {e}")

    # ── Loop de coleta ───────────────────────────────────────────────────
    start_monotonic = time.monotonic()
    end_monotonic = start_monotonic + (total_hours * 3600)
    collection_count = 0
    error_counter = ErrorCounter()

    # Mantém janelas contíguas sem sobreposição (mais fiel que "LAST N HOURS")
    last_window_end_ms: Optional[int] = None

    while not STOP_SIGNAL:
        now_monotonic = time.monotonic()
        if now_monotonic >= end_monotonic:
            logger.info("Período de coleta concluído!")
            break

        # Janela exata desta coleta
        window_end_ms = int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000)
        if last_window_end_ms is None:
            window_start_ms = window_end_ms - int(interval_seconds * 1000)
        else:
            window_start_ms = last_window_end_ms
            # Catch-up com cap: se houve falhas consecutivas, a janela pode
            # ter crescido demais. Limitar para evitar queries AQL gigantes.
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
            # NÃO avança last_window_end_ms — próximo ciclo faz catch-up (com cap)
            logger.error(f"Erro de conexão com QRadar: {e}")
            logger.info("Tentando novamente no próximo intervalo (catch-up automático)...")
        except requests.exceptions.HTTPError as e:
            error_counter.inc("http_error")
            collection_count += 1
            # NÃO avança last_window_end_ms — catch-up no próximo ciclo
            logger.error(f"Erro HTTP da API QRadar: {e}")
            if hasattr(e, "response") and e.response is not None:
                logger.error(f"Status: {e.response.status_code}, Body: {e.response.text[:500]}")
        except Exception as e:
            error_counter.inc("unexpected_error")
            collection_count += 1
            # NÃO avança last_window_end_ms — catch-up no próximo ciclo
            logger.error(f"Erro inesperado durante coleta: {e}", exc_info=True)

        # Aguardar próximo intervalo (agenda baseada em monotonic para evitar drift)
        if STOP_SIGNAL:
            break

        next_run_monotonic = start_monotonic + (collection_count * interval_seconds)
        sleep_seconds = max(0.0, next_run_monotonic - time.monotonic())
        if sleep_seconds > 0:
            logger.info(f"Próxima coleta em ~{sleep_seconds/3600.0:.2f}h. Aguardando...")
            wait_start = time.monotonic()
            while (time.monotonic() - wait_start) < sleep_seconds and not STOP_SIGNAL:
                time.sleep(min(30.0, sleep_seconds))

    # ── Gerar relatório final ────────────────────────────────────────────
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
