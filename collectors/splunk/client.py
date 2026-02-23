#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Splunk REST API Client.

Contém apenas a lógica específica do Splunk: autenticação via Bearer Token
ou Basic Auth, queries SPL via Search Jobs API v2, e inventário de indexes.
Toda a lógica compartilhada (MetricsDB, retry, relatórios, etc.) vem de core/.
"""

import json
import logging
import time
from typing import Any, Dict, List, Optional

import requests

from collectors.base import SIEMClient
from core.db import MetricsDB
from core.utils import _retry_with_backoff

logger = logging.getLogger("siem_collector")

# ─── Splunk-specific constants ───────────────────────────────────────────────
DEFAULT_SPLUNK_PORT = 8089
SPL_TIMEOUT_SECONDS = 300
SPL_POLL_INTERVAL = 5
MAX_RESULTS_PER_PAGE = 10000


# ─── Splunk Client ───────────────────────────────────────────────────────────
class SplunkClient(SIEMClient):
    """Cliente REST para o Splunk Enterprise / Cloud (Management API na porta 8089).

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

        if token:
            self.auth_mode = "token"
            self.session.headers.update({"Authorization": f"Bearer {token}"})
        elif username and password:
            self.auth_mode = "basic"
            self.session.auth = (username, password)
        else:
            raise ValueError(
                "Forneça token (Bearer) ou username+password para autenticação no Splunk."
            )

        self.session.headers.update({"Accept": "application/json"})

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

        def _do_request():
            resp = self.session.post(url, data=data, params=params, timeout=60)
            self._check_response(resp, endpoint)
            return resp.json()

        return _retry_with_backoff(_do_request)

    # ── SIEMClient interface ─────────────────────────────────────────────
    def test_connection(self) -> Dict:
        """Testa conectividade via /services/server/info."""
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
                logger.error("Falha de autenticação (HTTP 401). Verifique credenciais.")
            elif status == 403:
                logger.error("Acesso negado (HTTP 403). Permissões insuficientes.")
            else:
                logger.error(f"Erro HTTP {status} ao testar conexão.")
            raise
        except requests.exceptions.ConnectionError:
            logger.error(f"Não foi possível conectar a {self.base_url}.")
            raise

    # ── Inventário de indexes ────────────────────────────────────────────
    def get_indexes(self) -> List[Dict]:
        """Retorna lista de indexes no Splunk (exceto internos)."""
        try:
            data = self._get("services/data/indexes", params={"count": 0})
            indexes = []
            for entry in data.get("entry", []):
                content = entry.get("content", {})
                name = entry.get("name", "")
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
        """Retorna lista de sourcetypes conhecidos via SPL metadata."""
        try:
            results = self.run_spl_query("| metadata type=sourcetypes index=*")
            if results is None:
                return []
            sourcetypes = [r.get("sourcetype", "") for r in results if r.get("sourcetype")]
            logger.info(f"Total de sourcetypes registrados: {len(sourcetypes)}")
            return sourcetypes
        except Exception:
            logger.debug("Não foi possível obter sourcetypes via metadata.")
            return []

    def get_data_inputs_summary(self) -> List[Dict]:
        """Retorna resumo de data inputs via SPL '| rest'."""
        try:
            results = self.run_spl_query(
                "| rest /services/data/inputs/monitor "
                "| table title, disabled, index, sourcetype"
            )
            if results is None:
                return []
            inputs_list = []
            for r in results:
                inputs_list.append({
                    "name": r.get("title", ""),
                    "type": "monitor",
                    "disabled": r.get("disabled", "0") == "1",
                    "index": r.get("index", "default"),
                    "sourcetype": r.get("sourcetype", ""),
                })
            logger.info(f"Total de data inputs: {len(inputs_list)}")
            return inputs_list
        except Exception as e:
            logger.debug(f"Não foi possível listar data inputs: {e}")
            return []

    # ── SPL Search Jobs ──────────────────────────────────────────────────
    def run_spl_query(self, spl: str, earliest: str = "", latest: str = "") -> Optional[List[Dict]]:
        """Executa uma query SPL via search job e aguarda resultado."""
        logger.info(f"Executando SPL: {spl[:150]}...")

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

        sid = result.get("sid", "")
        if not sid:
            logger.error("Não foi possível obter SID do search job.")
            return None

        # Polling até completar
        start = time.time()
        while True:
            if time.time() - start > SPL_TIMEOUT_SECONDS:
                logger.error(f"Timeout aguardando search job {sid}")
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

        # Buscar resultados (Search API v2 — padrão desde Splunk Enterprise 9.0.1)
        try:
            results_data = self._get(
                f"services/search/v2/jobs/{sid}/results",
                params={"count": MAX_RESULTS_PER_PAGE},
            )
            return results_data.get("results", [])
        except Exception as e:
            logger.error(f"Erro ao buscar resultados do job {sid}: {e}")
            return None

    def get_event_metrics_window(
        self, start_time_ms: int, end_time_ms: int
    ) -> Optional[List[Dict]]:
        """Coleta métricas de ingestão por source/sourcetype para um intervalo exato."""
        earliest = f"{start_time_ms / 1000:.3f}"
        latest = f"{end_time_ms / 1000:.3f}"

        # NOTA: sum(len(_raw)) calcula o tamanho bruto dos eventos no index.
        # Para bytes licenciados com precisão, use get_license_usage().
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
        """Coleta dados de uso de licença (volume ingerido por sourcetype)."""
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
            logger.debug("Não foi possível listar forwarders.")
            return None


# ─── Inventory ───────────────────────────────────────────────────────────────
def collect_inventory(client: SplunkClient, db: MetricsDB) -> int:
    """Coleta inventário inicial de indexes do Splunk."""
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


def update_inventory_from_results(db: MetricsDB, metrics: List[Dict]):
    """Callback pós-coleta: atualiza inventário com sources descobertos via SPL."""
    inventory_entries = []
    for m in metrics:
        inventory_entries.append({
            "logsource_id": int(m.get("logsourceid", 0)),
            "name": m.get("log_source_name", "Unknown"),
            "type_name": m.get("log_source_type", "Unknown"),
        })
    if inventory_entries:
        db.save_log_sources_inventory(inventory_entries)


def create_sample_config(path: str):
    """Cria arquivo de configuração de exemplo para Splunk."""
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
