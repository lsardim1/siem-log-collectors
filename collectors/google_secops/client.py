#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Google SecOps (formerly Chronicle) REST API Client.

Contém apenas a lógica específica do Google SecOps: autenticação via
Service Account JSON ou Bearer Token, queries UDM Search, inventário de
log types e coleta de métricas de ingestão.
Toda a lógica compartilhada (MetricsDB, retry, relatórios, etc.) vem de core/.

MIT License — Copyright (c) 2025 lsardim1
"""

import datetime
import json
import logging
import time
from typing import Any, Dict, List, Optional

import requests

from collectors.base import SIEMClient
from core.db import MetricsDB
from core.utils import _retry_with_backoff, _stable_id

logger = logging.getLogger("siem_collector")

# ─── Google SecOps-specific constants ────────────────────────────────────────
SCOPES = ["https://www.googleapis.com/auth/chronicle-backstory"]

UDM_SEARCH_MAX_EVENTS = 10000
UDM_SEARCH_TIMEOUT = 600  # 10 minutes per API docs (600s)

# Regional Backstory API endpoints
# Ref: https://docs.cloud.google.com/chronicle/docs/reference/search-api#regional_endpoints
BACKSTORY_ENDPOINTS: Dict[str, str] = {
    "us": "https://backstory.googleapis.com",
    "europe": "https://europe-backstory.googleapis.com",
    "europe-west2": "https://europe-west2-backstory.googleapis.com",
    "europe-west3": "https://europe-west3-backstory.googleapis.com",
    "europe-west6": "https://europe-west6-backstory.googleapis.com",
    "europe-west9": "https://europe-west9-backstory.googleapis.com",
    "europe-west12": "https://europe-west12-backstory.googleapis.com",
    "europe-central2": "https://europe-central2-backstory.googleapis.com",
    "asia-south1": "https://asia-south1-backstory.googleapis.com",
    "asia-southeast1": "https://asia-southeast1-backstory.googleapis.com",
    "asia-southeast2": "https://asia-southeast2-backstory.googleapis.com",
    "asia-northeast1": "https://asia-northeast1-backstory.googleapis.com",
    "australia-southeast1": "https://australia-southeast1-backstory.googleapis.com",
    "me-central1": "https://me-central1-backstory.googleapis.com",
    "me-central2": "https://me-central2-backstory.googleapis.com",
    "me-west1": "https://me-west1-backstory.googleapis.com",
    "northamerica-northeast2": "https://northamerica-northeast2-backstory.googleapis.com",
    "southamerica-east1": "https://southamerica-east1-backstory.googleapis.com",
    "africa-south1": "https://africa-south1-backstory.googleapis.com",
}


# ─── Google SecOps Client ───────────────────────────────────────────────────
class GoogleSecOpsClient(SIEMClient):
    """Cliente REST para o Google SecOps (antigo Chronicle).

    Autenticação suportada:
    - Service Account JSON (recomendado) — requer pacote ``google-auth``
    - Bearer Token (manual) — para testes ou tokens pré-gerados
    """

    def __init__(
        self,
        service_account_file: str = "",
        token: str = "",
        region: str = "us",
        verify_ssl: bool = True,
    ):
        self.verify_ssl = verify_ssl
        self.region = region
        self.base_url = BACKSTORY_ENDPOINTS.get(region, BACKSTORY_ENDPOINTS["us"])
        self.session = requests.Session()
        self.session.verify = self.verify_ssl
        self._credentials = None

        if service_account_file:
            self.auth_mode = "service_account"
            self._init_service_account(service_account_file)
        elif token:
            self.auth_mode = "token"
            self.session.headers.update({"Authorization": f"Bearer {token}"})
        else:
            raise ValueError(
                "Forneça service_account_file (caminho para JSON) ou token (Bearer) "
                "para autenticação no Google SecOps."
            )

        self.session.headers.update({"Accept": "application/json"})

    def _init_service_account(self, sa_file: str):
        """Inicializa autenticação via Service Account JSON."""
        try:
            from google.auth.transport.requests import AuthorizedSession
            from google.oauth2 import service_account
        except ImportError:
            raise ImportError(
                "Pacote 'google-auth' é necessário para autenticação via Service Account. "
                "Instale com: pip install google-auth"
            )

        self._credentials = service_account.Credentials.from_service_account_file(
            sa_file, scopes=SCOPES
        )
        # Replace session with AuthorizedSession for automatic token refresh
        self.session = AuthorizedSession(self._credentials)
        self.session.verify = self.verify_ssl

    def _check_response(self, resp: requests.Response, endpoint: str) -> None:
        """Verifica status HTTP e fornece mensagens acionáveis."""
        if resp.status_code == 401:
            raise requests.exceptions.HTTPError(
                f"HTTP 401 Unauthorized de {endpoint}. "
                "Verifique se as credenciais (Service Account/Token) estão corretas "
                "e não expiraram.",
                response=resp,
            )
        if resp.status_code == 403:
            raise requests.exceptions.HTTPError(
                f"HTTP 403 Forbidden de {endpoint}. "
                "A Service Account não possui permissões para acessar o Google SecOps. "
                "Verifique as roles e scopes do IAM.",
                response=resp,
            )
        if resp.status_code == 429:
            raise requests.exceptions.HTTPError(
                f"HTTP 429 RESOURCE_EXHAUSTED de {endpoint}. "
                "Limite de taxa atingido (360 queries/hora para UDM Search). "
                "Aguarde antes de fazer novas requisições.",
                response=resp,
            )
        resp.raise_for_status()

    def _get(self, endpoint: str, params: Optional[Dict] = None) -> Any:
        """GET request com retry e validação."""
        url = f"{self.base_url}/{endpoint}"
        logger.debug(f"GET {url} params={params}")

        def _do_request():
            resp = self.session.get(url, params=params, timeout=UDM_SEARCH_TIMEOUT)
            self._check_response(resp, endpoint)
            return resp.json()

        return _retry_with_backoff(_do_request)

    # ── SIEMClient interface ─────────────────────────────────────────────
    def test_connection(self) -> Dict:
        """Testa conectividade via UDM Search simples."""
        logger.info(f"Testando conexão com Google SecOps ({self.region})...")
        try:
            now = datetime.datetime.now(datetime.timezone.utc)
            start = (now - datetime.timedelta(hours=1)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            end = now.strftime("%Y-%m-%dT%H:%M:%SZ")

            result = self._get("v1/events:udmSearch", params={
                "query": 'metadata.event_type != ""',
                "time_range.start_time": start,
                "time_range.end_time": end,
                "limit": 1,
            })
            event_count = len(result.get("events", []))
            info = {
                "platform": "Google SecOps",
                "region": self.region,
                "base_url": self.base_url,
                "auth_mode": self.auth_mode,
                "test_events_found": event_count,
            }
            logger.info(
                f"Conexão OK — Google SecOps ({self.region}), "
                f"{event_count} evento(s) de teste"
            )
            return info
        except requests.exceptions.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else 0
            if status == 401:
                logger.error(
                    "Falha de autenticação (HTTP 401). Verifique credenciais."
                )
            elif status == 403:
                logger.error(
                    "Acesso negado (HTTP 403). Verifique permissões IAM."
                )
            else:
                logger.error(f"Erro HTTP {status} ao testar conexão.")
            raise
        except requests.exceptions.ConnectionError:
            logger.error(f"Não foi possível conectar a {self.base_url}.")
            raise

    # ── UDM Search ───────────────────────────────────────────────────────
    def udm_search(
        self,
        query: str,
        start_time_iso: str,
        end_time_iso: str,
        limit: int = UDM_SEARCH_MAX_EVENTS,
    ) -> Optional[Dict]:
        """Executa uma UDM Search e retorna o resultado completo.

        Args:
            query: Query UDM (ex: ``metadata.event_type != ""``)
            start_time_iso: Início (ISO 8601, inclusivo)
            end_time_iso: Fim (ISO 8601, exclusivo)
            limit: Máximo de eventos (default/max: 10000)

        Returns:
            Dict com keys ``events`` (list) e ``moreDataAvailable`` (bool),
            ou None em caso de erro.
        """
        logger.info(f"Executando UDM Search: {query[:120]}...")
        try:
            result = self._get("v1/events:udmSearch", params={
                "query": query,
                "time_range.start_time": start_time_iso,
                "time_range.end_time": end_time_iso,
                "limit": min(limit, UDM_SEARCH_MAX_EVENTS),
            })
            events = result.get("events", [])
            more = result.get("moreDataAvailable", False)
            logger.info(
                f"UDM Search retornou {len(events)} eventos "
                f"(moreDataAvailable={more})"
            )
            return result
        except requests.exceptions.HTTPError as e:
            logger.error(f"Erro na UDM Search: {e}")
            return None
        except Exception as e:
            logger.error(f"Erro inesperado na UDM Search: {e}")
            return None

    def get_event_metrics_window(
        self, start_time_ms: int, end_time_ms: int
    ) -> Optional[List[Dict]]:
        """Coleta métricas de ingestão via UDM Search para um intervalo exato.

        Agrega eventos por ``metadata.log_type`` e ``metadata.product_name``,
        retornando métricas no formato unificado do SIEMClient.

        Nota: O UDM Search retorna no máximo 10.000 eventos por consulta.
        Para ambientes de alto volume, use janelas de coleta menores
        (ex: ``--interval 0.25`` para janelas de 15 min).
        """
        start_iso = datetime.datetime.fromtimestamp(
            start_time_ms / 1000.0, tz=datetime.timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        end_iso = datetime.datetime.fromtimestamp(
            end_time_ms / 1000.0, tz=datetime.timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Query all events in the window
        query = 'metadata.event_type != ""'
        result = self.udm_search(
            query, start_iso, end_iso, limit=UDM_SEARCH_MAX_EVENTS
        )

        if result is None:
            return None

        events = result.get("events", [])
        more_data = result.get("moreDataAvailable", False)

        if more_data:
            logger.warning(
                f"UDM Search atingiu o limite de {UDM_SEARCH_MAX_EVENTS} eventos. "
                "Contagens podem estar truncadas. Considere usar intervalos menores "
                "(ex: --interval 0.25 para janelas de 15 min)."
            )

        if not events:
            return []

        # Aggregate by log_type + product_name
        aggregation: Dict[str, Dict] = {}
        for event_wrapper in events:
            udm = event_wrapper.get("udm", {})
            metadata = udm.get("metadata", {})
            log_type = metadata.get(
                "logType", metadata.get("log_type", "UNKNOWN")
            )
            product_name = metadata.get(
                "productName", metadata.get("product_name", "Unknown")
            )
            vendor_name = metadata.get(
                "vendorName", metadata.get("vendor_name", "Unknown")
            )

            key = f"{log_type}|{product_name}"
            if key not in aggregation:
                aggregation[key] = {
                    "log_type": log_type,
                    "product_name": product_name,
                    "vendor_name": vendor_name,
                    "count": 0,
                }
            aggregation[key]["count"] += 1

        # Normalize to unified format (same keys as QRadar/Splunk)
        normalized: List[Dict] = []
        for key, agg in aggregation.items():
            log_type = agg["log_type"]
            product_name = agg["product_name"]
            vendor_name = agg["vendor_name"]
            count = agg["count"]
            source_name = (
                f"{product_name} ({vendor_name})"
                if vendor_name != "Unknown"
                else product_name
            )

            normalized.append({
                "logsourceid": _stable_id(f"{log_type}|{product_name}"),
                "log_source_name": source_name,
                "log_source_type": log_type,
                "aggregated_event_count": count,
                "total_event_count": count,
                "total_payload_bytes": 0.0,   # Not available via UDM Search
                "avg_payload_bytes": 0.0,      # Not available via UDM Search
            })

        return normalized

    # ── Log Types (inventory) ────────────────────────────────────────────
    def get_log_types(self) -> List[str]:
        """Descobre log types existentes via UDM Search nas últimas 24h."""
        logger.info("Descobrindo log types via UDM Search...")
        now = datetime.datetime.now(datetime.timezone.utc)
        start = (now - datetime.timedelta(hours=24)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        end = now.strftime("%Y-%m-%dT%H:%M:%SZ")

        result = self.udm_search(
            'metadata.event_type != ""',
            start, end, limit=UDM_SEARCH_MAX_EVENTS,
        )

        if result is None:
            return []

        log_types: set = set()
        for event_wrapper in result.get("events", []):
            udm = event_wrapper.get("udm", {})
            metadata = udm.get("metadata", {})
            lt = metadata.get("logType", metadata.get("log_type", ""))
            if lt:
                log_types.add(lt)

        sorted_types = sorted(log_types)
        logger.info(f"Log types descobertos: {len(sorted_types)}")
        return sorted_types


# ─── Inventory ───────────────────────────────────────────────────────────────
def collect_inventory(client: GoogleSecOpsClient, db: MetricsDB) -> int:
    """Coleta inventário de log types do Google SecOps."""
    logger.info("Coletando inventário de log types...")
    try:
        log_types = client.get_log_types()
        if log_types:
            inventory = []
            for lt in log_types:
                ls_id = _stable_id(f"logtype:{lt}")
                inventory.append({
                    "logsource_id": ls_id,
                    "name": lt,
                    "type_name": lt,
                    "description": f"Google SecOps Log Type: {lt}",
                })
            db.save_log_sources_inventory(inventory)
            logger.info(f"Inventário: {len(log_types)} log types")
        return len(log_types)
    except Exception as e:
        logger.warning(f"Não foi possível coletar inventário: {e}")
        return 0


def update_inventory_from_results(db: MetricsDB, metrics: List[Dict]):
    """Callback pós-coleta: atualiza inventário com log types descobertos."""
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
    """Cria arquivo de configuração de exemplo para Google SecOps."""
    sample = {
        "service_account_file": "/path/to/service-account.json",
        "auth_token": "",
        "region": "us",
        "verify_ssl": True,
        "collection_days": 6,
        "interval_hours": 1,
        "db_file": "secops_metrics.db",
        "report_dir": "reports",
        "_comment_regions": (
            "Regiões disponíveis: us, europe, southamerica-east1, "
            "asia-southeast1, etc. Veja documentação completa."
        ),
        "_comment_auth": (
            "Forneça service_account_file OU auth_token. "
            "Service Account é recomendado para produção."
        ),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(sample, f, indent=4, ensure_ascii=False)
    logger.info(f"Arquivo de configuração de exemplo criado: {path}")
