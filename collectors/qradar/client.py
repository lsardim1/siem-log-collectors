#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
QRadar REST API Client.

Contém apenas a lógica específica do QRadar: autenticação via SEC token,
queries AQL, paginação com Range headers, e inventário de log sources.
Toda a lógica compartilhada (MetricsDB, retry, relatórios, etc.) vem de core/.
"""

import datetime
import json
import logging
import time
from typing import Any, Dict, List, Optional

import requests

from collectors.base import SIEMClient
from core.db import MetricsDB
from core.utils import _retry_with_backoff

logger = logging.getLogger("siem_collector")

# ─── QRadar-specific constants ───────────────────────────────────────────────
AQL_TIMEOUT_SECONDS = 300
AQL_POLL_INTERVAL = 5
ARIEL_MAX_RESULTS = 50000  # Limite máximo de resultados por query AQL

# ─── Helpers ─────────────────────────────────────────────────────────────────
def _validate_json_response(resp: requests.Response, endpoint: str) -> Any:
    """Valida que a resposta é JSON válido e não HTML de erro."""
    text = resp.text[:200].lower().lstrip()
    if text.startswith(('<!doctype', '<html', '<head')):
        raise ValueError(
            f"Esperado JSON de {endpoint} mas recebeu HTML: {resp.text[:200]}"
        )
    return resp.json()


# ─── QRadar Client ───────────────────────────────────────────────────────────
class QRadarClient(SIEMClient):
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

    def _check_response(self, resp: requests.Response, endpoint: str) -> None:
        """Verifica status HTTP e fornece mensagens acionáveis."""
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
        """GET request com retry e validação."""
        url = f"{self.base_url}/api/{endpoint}"
        logger.debug(f"GET {url} params={params} headers={extra_headers}")

        def _do_request():
            resp = self.session.get(url, params=params, headers=extra_headers, timeout=60)
            self._check_response(resp, endpoint)
            return _validate_json_response(resp, endpoint)

        return _retry_with_backoff(_do_request)

    def _post(self, endpoint: str, params: Optional[Dict] = None, data: Any = None) -> Any:
        """POST request com retry e validação."""
        url = f"{self.base_url}/api/{endpoint}"
        logger.debug(f"POST {url} params={params}")

        def _do_request():
            resp = self.session.post(url, params=params, json=data, timeout=60)
            self._check_response(resp, endpoint)
            return _validate_json_response(resp, endpoint)

        return _retry_with_backoff(_do_request)

    def _paginate_endpoint(self, endpoint: str, page_size: int = 500) -> List[Dict]:
        """Pagina um endpoint usando Range headers (padrão QRadar)."""
        all_items: List[Dict] = []
        offset = 0
        while True:
            headers = {"Range": f"items={offset}-{offset + page_size - 1}"}
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

    # ── SIEMClient interface ─────────────────────────────────────────────
    def test_connection(self) -> Dict:
        """Testa conectividade via /api/system/about."""
        logger.info(f"Testando conexão com {self.base_url}...")
        try:
            info = self._get("system/about")
            version = info.get("external_version", info.get("version", "desconhecida"))
            logger.info(f"Conexão OK — QRadar versão: {version}")
            return info
        except requests.exceptions.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else 0
            if status == 401:
                logger.error("Falha de autenticação (HTTP 401). Verifique o token SEC.")
            elif status == 403:
                logger.error("Acesso negado (HTTP 403). Permissões insuficientes.")
            else:
                logger.error(f"Erro HTTP {status} ao testar conexão.")
            raise
        except requests.exceptions.ConnectionError:
            logger.error(f"Não foi possível conectar a {self.base_url}.")
            raise

    # ── Log Sources ──────────────────────────────────────────────────────
    def get_log_sources(self) -> List[Dict]:
        """Retorna todas as log sources configuradas."""
        log_sources = self._paginate_endpoint(
            "config/event_sources/log_source_management/log_sources", page_size=500
        )
        logger.info(f"Total de log sources encontradas: {len(log_sources)}")
        return log_sources

    def get_log_source_types(self) -> Dict[int, str]:
        """Retorna mapeamento de type_id → nome do tipo."""
        types_map: Dict[int, str] = {}
        try:
            types_list = self._paginate_endpoint(
                "config/event_sources/log_source_management/log_source_types", page_size=1000
            )
            for t in types_list:
                type_id = t.get("id")
                if type_id is not None:
                    types_map[type_id] = t.get("name", f"Unknown-{type_id}")
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

        # Buscar resultados
        try:
            results = self._get(
                f"ariel/searches/{search_id}/results",
                extra_headers={"Range": f"items=0-{ARIEL_MAX_RESULTS - 1}"},
            )
            events = results.get("events", results.get("flows", []))
            if len(events) >= ARIEL_MAX_RESULTS:
                logger.warning(
                    f"Resultado AQL atingiu o limite de {ARIEL_MAX_RESULTS} linhas. "
                    "Dados podem estar truncados. Considere intervalos menores "
                    "ou verifique se o ambiente possui log sources em excesso."
                )
            return events
        except Exception as e:
            logger.error(f"Erro ao buscar resultados AQL: {e}")
            return None

    def get_event_metrics_window(self, start_time_ms: int, end_time_ms: int) -> Optional[List[Dict]]:
        """Coleta métricas de ingestão via AQL para um intervalo exato."""
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

        # Tentativa 1: incluir unparsed
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
            logger.debug(f"AQL com unparsed falhou; fallback. Motivo: {exc}")

        # Fallback: sem unparsed
        aql = base_select + where_clause
        return self.run_aql_query(aql)

    def get_event_counts_by_logsource(self, start_time: int, end_time: int) -> Optional[List[Dict]]:
        """[DEPRECATED] Use get_event_metrics_window()."""
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

    def get_event_counts_last_n_hours(self, hours: int = 1) -> Optional[List[Dict]]:
        """Compat: baseada em janela exata."""
        end_ms = int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000)
        start_ms = int((datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=hours)).timestamp() * 1000)
        return self.get_event_metrics_window(start_ms, end_ms)

    def get_flow_counts_by_logsource(self, hours: int = 1) -> Optional[List[Dict]]:
        """Busca contagem de flows por log source."""
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


# ─── Inventory ───────────────────────────────────────────────────────────────
def collect_inventory(client: QRadarClient, db: MetricsDB) -> int:
    """Coleta inventário de log sources do QRadar."""
    logger.info("Coletando inventário de log sources...")
    try:
        log_sources = client.get_log_sources()
        type_map = client.get_log_source_types()
        # Transformar para formato unificado
        unified = []
        for ls in log_sources:
            type_id = ls.get("type_id", 0)
            unified.append({
                "logsource_id": ls.get("id", 0),
                "name": ls.get("name", "Unknown"),
                "type_name": type_map.get(type_id, f"Type-{type_id}"),
                "type_id": type_id,
                "enabled": ls.get("enabled", False),
                "description": ls.get("description", ""),
            })
        db.save_log_sources_inventory(unified)
        return len(unified)
    except Exception as e:
        logger.error(f"Erro ao coletar inventário: {e}")
        return 0


def create_sample_config(path: str):
    """Cria arquivo de configuração de exemplo para QRadar."""
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
