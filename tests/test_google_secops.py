#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Testes para o módulo Google SecOps (collectors/google_secops/client.py).

Cobre: GoogleSecOpsClient auth, UDM Search, _check_response,
test_connection, get_event_metrics_window (agregação client-side),
get_log_types, collect_inventory, update_inventory_from_results,
create_sample_config e constantes específicas.

Execução:
    python -m pytest tests/test_google_secops.py -v
    python -m unittest tests.test_google_secops -v
"""

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch, PropertyMock

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collectors.google_secops.client import (
    BACKSTORY_ENDPOINTS,
    SCOPES,
    UDM_SEARCH_MAX_EVENTS,
    UDM_SEARCH_TIMEOUT,
    GoogleSecOpsClient,
    collect_inventory,
    create_sample_config,
    update_inventory_from_results,
)
from core.db import MetricsDB


# ─── Helper: build a GoogleSecOpsClient with token auth (no real HTTP) ───────
def _make_client(**kwargs):
    """Cria um GoogleSecOpsClient com token fake para testes."""
    defaults = {"token": "fake-token", "region": "us", "verify_ssl": False}
    defaults.update(kwargs)
    return GoogleSecOpsClient(**defaults)


# ─────────────────────────────────────────────────────────────────────────────
# 1. Auth modes
# ─────────────────────────────────────────────────────────────────────────────
class TestGoogleSecOpsAuth(unittest.TestCase):
    """Verifica modos de autenticação do GoogleSecOpsClient."""

    def test_token_auth(self):
        """Token Bearer deve ser aceito e configurado no header."""
        client = _make_client(token="my_token_123")
        self.assertEqual(client.auth_mode, "token")
        self.assertIn("Authorization", client.session.headers)
        self.assertEqual(
            client.session.headers["Authorization"], "Bearer my_token_123"
        )

    def test_no_credentials_raises(self):
        """Sem credenciais deve levantar ValueError."""
        with self.assertRaises(ValueError) as ctx:
            GoogleSecOpsClient()
        self.assertIn("service_account_file", str(ctx.exception))

    @patch(
        "collectors.google_secops.client.GoogleSecOpsClient._init_service_account"
    )
    def test_service_account_mode(self, mock_init_sa):
        """Service Account deve chamar _init_service_account."""
        client = GoogleSecOpsClient(
            service_account_file="/fake/sa.json", verify_ssl=False
        )
        self.assertEqual(client.auth_mode, "service_account")
        mock_init_sa.assert_called_once_with("/fake/sa.json")

    def test_service_account_import_error(self):
        """Sem google-auth instalado, deve levantar ImportError."""
        with patch.dict("sys.modules", {"google.oauth2": None, "google.auth": None}):
            with self.assertRaises(ImportError) as ctx:
                # Bypass __init__ — test _init_service_account directly
                client = GoogleSecOpsClient.__new__(GoogleSecOpsClient)
                client.verify_ssl = False
                client.region = "us"
                client.base_url = BACKSTORY_ENDPOINTS["us"]
                client.session = MagicMock()
                client._credentials = None
                client._init_service_account("/fake/sa.json")
            self.assertIn("google-auth", str(ctx.exception))

    def test_region_sets_base_url(self):
        """Region deve selecionar o endpoint correto."""
        client = _make_client(region="southamerica-east1")
        self.assertEqual(
            client.base_url,
            "https://southamerica-east1-backstory.googleapis.com",
        )

    def test_unknown_region_defaults_to_us(self):
        """Região desconhecida deve usar endpoint US padrão."""
        client = _make_client(region="unknown-region-42")
        self.assertEqual(client.base_url, BACKSTORY_ENDPOINTS["us"])


# ─────────────────────────────────────────────────────────────────────────────
# 2. _check_response
# ─────────────────────────────────────────────────────────────────────────────
class TestCheckResponse(unittest.TestCase):
    """Verifica mensagens acionáveis para erros HTTP."""

    def setUp(self):
        self.client = _make_client()

    def test_401_actionable_message(self):
        resp = MagicMock()
        resp.status_code = 401
        with self.assertRaises(requests.exceptions.HTTPError) as ctx:
            self.client._check_response(resp, "v1/events:udmSearch")
        self.assertIn("401", str(ctx.exception))
        self.assertIn("credenciais", str(ctx.exception).lower())

    def test_403_actionable_message(self):
        resp = MagicMock()
        resp.status_code = 403
        with self.assertRaises(requests.exceptions.HTTPError) as ctx:
            self.client._check_response(resp, "v1/events:udmSearch")
        self.assertIn("403", str(ctx.exception))
        self.assertIn("permiss", str(ctx.exception).lower())

    def test_429_rate_limit_message(self):
        resp = MagicMock()
        resp.status_code = 429
        with self.assertRaises(requests.exceptions.HTTPError) as ctx:
            self.client._check_response(resp, "v1/events:udmSearch")
        self.assertIn("429", str(ctx.exception))
        self.assertIn("360", str(ctx.exception))

    def test_200_no_exception(self):
        resp = MagicMock()
        resp.status_code = 200
        resp.raise_for_status = MagicMock()
        self.client._check_response(resp, "v1/events:udmSearch")
        resp.raise_for_status.assert_called_once()


# ─────────────────────────────────────────────────────────────────────────────
# 3. test_connection
# ─────────────────────────────────────────────────────────────────────────────
class TestTestConnection(unittest.TestCase):
    """Verifica test_connection() via UDM Search simples."""

    def test_connection_success(self):
        client = _make_client()
        mock_result = {"events": [{"udm": {"metadata": {"eventType": "GENERIC_EVENT"}}}]}
        with patch.object(client, "_get", return_value=mock_result) as mock_get:
            info = client.test_connection()
            mock_get.assert_called_once()
            call_args = mock_get.call_args
            self.assertEqual(call_args[0][0], "v1/events:udmSearch")
            self.assertEqual(info["platform"], "Google SecOps")
            self.assertEqual(info["region"], "us")
            self.assertEqual(info["auth_mode"], "token")
            self.assertEqual(info["test_events_found"], 1)

    def test_connection_success_empty(self):
        """Conexão OK, mas sem eventos recentes — ainda retorna info."""
        client = _make_client()
        with patch.object(client, "_get", return_value={"events": []}):
            info = client.test_connection()
            self.assertEqual(info["test_events_found"], 0)

    def test_connection_http_401(self):
        client = _make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        http_err = requests.exceptions.HTTPError(response=mock_resp)
        with patch.object(client, "_get", side_effect=http_err):
            with self.assertRaises(requests.exceptions.HTTPError):
                client.test_connection()

    def test_connection_http_403(self):
        client = _make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        http_err = requests.exceptions.HTTPError(response=mock_resp)
        with patch.object(client, "_get", side_effect=http_err):
            with self.assertRaises(requests.exceptions.HTTPError):
                client.test_connection()

    def test_connection_error(self):
        client = _make_client()
        with patch.object(
            client, "_get",
            side_effect=requests.exceptions.ConnectionError("DNS fail"),
        ):
            with self.assertRaises(requests.exceptions.ConnectionError):
                client.test_connection()


# ─────────────────────────────────────────────────────────────────────────────
# 4. UDM Search
# ─────────────────────────────────────────────────────────────────────────────
class TestUdmSearch(unittest.TestCase):
    """Verifica chamada e tratamento de erros da UDM Search."""

    def setUp(self):
        self.client = _make_client()

    def test_udm_search_success(self):
        mock_result = {
            "events": [{"udm": {"metadata": {"logType": "WINDOWS_EVENT"}}}],
            "moreDataAvailable": False,
        }
        with patch.object(self.client, "_get", return_value=mock_result) as mg:
            result = self.client.udm_search(
                'metadata.event_type != ""',
                "2025-01-01T00:00:00Z",
                "2025-01-01T01:00:00Z",
            )
            self.assertIsNotNone(result)
            self.assertEqual(len(result["events"]), 1)
            self.assertFalse(result["moreDataAvailable"])
            # Verify params
            params = mg.call_args[1]["params"]
            self.assertEqual(params["limit"], UDM_SEARCH_MAX_EVENTS)

    def test_udm_search_limit_capped(self):
        """Limit deve ser capeado a UDM_SEARCH_MAX_EVENTS."""
        with patch.object(
            self.client, "_get", return_value={"events": []}
        ) as mg:
            self.client.udm_search("test", "2025-01-01T00:00:00Z", "2025-01-01T01:00:00Z", limit=99999)
            params = mg.call_args[1]["params"]
            self.assertEqual(params["limit"], UDM_SEARCH_MAX_EVENTS)

    def test_udm_search_http_error(self):
        """Erro HTTP deve retornar None, não levantar exceção."""
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        with patch.object(
            self.client, "_get",
            side_effect=requests.exceptions.HTTPError(response=mock_resp),
        ):
            result = self.client.udm_search(
                "test", "2025-01-01T00:00:00Z", "2025-01-01T01:00:00Z"
            )
            self.assertIsNone(result)

    def test_udm_search_unexpected_error(self):
        """Erro inesperado deve retornar None."""
        with patch.object(
            self.client, "_get", side_effect=RuntimeError("unexpected")
        ):
            result = self.client.udm_search(
                "test", "2025-01-01T00:00:00Z", "2025-01-01T01:00:00Z"
            )
            self.assertIsNone(result)


# ─────────────────────────────────────────────────────────────────────────────
# 5. get_event_metrics_window (agregação client-side)
# ─────────────────────────────────────────────────────────────────────────────
class TestGetEventMetricsWindow(unittest.TestCase):
    """Verifica agregação client-side de eventos UDM."""

    def setUp(self):
        self.client = _make_client()

    def _make_event(self, log_type="WINDOWS_EVENT", product="Windows", vendor="Microsoft"):
        return {
            "udm": {
                "metadata": {
                    "logType": log_type,
                    "productName": product,
                    "vendorName": vendor,
                }
            }
        }

    def test_aggregation_single_type(self):
        """3 eventos do mesmo tipo devem gerar 1 entrada agrupada."""
        events = [self._make_event()] * 3
        with patch.object(
            self.client, "udm_search",
            return_value={"events": events, "moreDataAvailable": False},
        ):
            metrics = self.client.get_event_metrics_window(1000, 2000)
            self.assertIsNotNone(metrics)
            self.assertEqual(len(metrics), 1)
            self.assertEqual(metrics[0]["aggregated_event_count"], 3)
            self.assertEqual(metrics[0]["log_source_type"], "WINDOWS_EVENT")
            self.assertIn("Windows", metrics[0]["log_source_name"])
            self.assertIn("Microsoft", metrics[0]["log_source_name"])

    def test_aggregation_multiple_types(self):
        """Tipos diferentes devem gerar entradas separadas."""
        events = [
            self._make_event("WINDOWS_EVENT", "Windows", "Microsoft"),
            self._make_event("WINDOWS_EVENT", "Windows", "Microsoft"),
            self._make_event("GCP_CLOUDAUDIT", "Cloud Audit", "Google"),
        ]
        with patch.object(
            self.client, "udm_search",
            return_value={"events": events, "moreDataAvailable": False},
        ):
            metrics = self.client.get_event_metrics_window(1000, 2000)
            self.assertEqual(len(metrics), 2)
            counts = {m["log_source_type"]: m["aggregated_event_count"] for m in metrics}
            self.assertEqual(counts["WINDOWS_EVENT"], 2)
            self.assertEqual(counts["GCP_CLOUDAUDIT"], 1)

    def test_empty_events(self):
        """Sem eventos deve retornar lista vazia."""
        with patch.object(
            self.client, "udm_search",
            return_value={"events": [], "moreDataAvailable": False},
        ):
            metrics = self.client.get_event_metrics_window(1000, 2000)
            self.assertEqual(metrics, [])

    def test_none_result(self):
        """udm_search retornando None deve propagar None."""
        with patch.object(self.client, "udm_search", return_value=None):
            metrics = self.client.get_event_metrics_window(1000, 2000)
            self.assertIsNone(metrics)

    def test_more_data_available_warning(self):
        """moreDataAvailable=True deve gerar warning no log."""
        events = [self._make_event()] * 5
        with patch.object(
            self.client, "udm_search",
            return_value={"events": events, "moreDataAvailable": True},
        ):
            with self.assertLogs("siem_collector", level="WARNING") as log:
                metrics = self.client.get_event_metrics_window(1000, 2000)
                self.assertTrue(
                    any("truncad" in msg.lower() for msg in log.output)
                )
            self.assertEqual(len(metrics), 1)
            self.assertEqual(metrics[0]["aggregated_event_count"], 5)

    def test_unknown_vendor_format(self):
        """Vendor 'Unknown' não deve aparecer no log_source_name."""
        events = [self._make_event("CUSTOM_LOG", "MyApp", "Unknown")]
        with patch.object(
            self.client, "udm_search",
            return_value={"events": events, "moreDataAvailable": False},
        ):
            metrics = self.client.get_event_metrics_window(1000, 2000)
            self.assertEqual(metrics[0]["log_source_name"], "MyApp")
            self.assertNotIn("Unknown", metrics[0]["log_source_name"])

    def test_normalized_keys_present(self):
        """Métricas normalizadas devem ter todas as chaves padrão."""
        events = [self._make_event()]
        with patch.object(
            self.client, "udm_search",
            return_value={"events": events, "moreDataAvailable": False},
        ):
            metrics = self.client.get_event_metrics_window(1000, 2000)
            entry = metrics[0]
            expected_keys = {
                "logsourceid", "log_source_name", "log_source_type",
                "aggregated_event_count", "total_event_count",
                "total_payload_bytes", "avg_payload_bytes",
            }
            self.assertEqual(set(entry.keys()), expected_keys)
            self.assertEqual(entry["total_payload_bytes"], 0.0)
            self.assertEqual(entry["avg_payload_bytes"], 0.0)

    def test_iso_time_conversion(self):
        """Timestamps em ms devem ser convertidos para ISO 8601."""
        # 2025-06-01T12:00:00Z = 1748779200000 ms
        start_ms = 1748779200000
        end_ms = start_ms + 3600000  # +1h

        with patch.object(self.client, "udm_search", return_value={"events": []}) as mock:
            self.client.get_event_metrics_window(start_ms, end_ms)
            call_args = mock.call_args
            start_iso = call_args[0][1]
            end_iso = call_args[0][2]
            self.assertIn("2025-06-01T12:00:00Z", start_iso)
            self.assertIn("2025-06-01T13:00:00Z", end_iso)


# ─────────────────────────────────────────────────────────────────────────────
# 6. get_log_types
# ─────────────────────────────────────────────────────────────────────────────
class TestGetLogTypes(unittest.TestCase):
    """Verifica descoberta de log types."""

    def setUp(self):
        self.client = _make_client()

    def test_discovers_unique_log_types(self):
        events = [
            {"udm": {"metadata": {"logType": "WINDOWS_EVENT"}}},
            {"udm": {"metadata": {"logType": "GCP_CLOUDAUDIT"}}},
            {"udm": {"metadata": {"logType": "WINDOWS_EVENT"}}},  # duplicate
        ]
        with patch.object(
            self.client, "udm_search",
            return_value={"events": events, "moreDataAvailable": False},
        ):
            types = self.client.get_log_types()
            self.assertEqual(types, ["GCP_CLOUDAUDIT", "WINDOWS_EVENT"])

    def test_empty_events(self):
        with patch.object(
            self.client, "udm_search",
            return_value={"events": [], "moreDataAvailable": False},
        ):
            types = self.client.get_log_types()
            self.assertEqual(types, [])

    def test_none_result(self):
        with patch.object(self.client, "udm_search", return_value=None):
            types = self.client.get_log_types()
            self.assertEqual(types, [])

    def test_skips_empty_log_type(self):
        """Log types vazios devem ser ignorados."""
        events = [
            {"udm": {"metadata": {"logType": "VALID_TYPE"}}},
            {"udm": {"metadata": {"logType": ""}}},
            {"udm": {"metadata": {}}},
        ]
        with patch.object(
            self.client, "udm_search",
            return_value={"events": events, "moreDataAvailable": False},
        ):
            types = self.client.get_log_types()
            self.assertEqual(types, ["VALID_TYPE"])


# ─────────────────────────────────────────────────────────────────────────────
# 7. Inventory (collect + update callback)
# ─────────────────────────────────────────────────────────────────────────────
class TestInventory(unittest.TestCase):
    """Testa collect_inventory e update_inventory_from_results."""

    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        self.db = MetricsDB(self.db_path)

    def tearDown(self):
        self.db.close()
        os.close(self.db_fd)
        os.unlink(self.db_path)

    def test_collect_inventory_saves_to_db(self):
        client = _make_client()
        with patch.object(
            client, "get_log_types",
            return_value=["WINDOWS_EVENT", "GCP_CLOUDAUDIT"],
        ):
            count = collect_inventory(client, self.db)
            self.assertEqual(count, 2)

        cursor = self.db.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM log_sources_inventory")
        self.assertEqual(cursor.fetchone()[0], 2)

    def test_collect_inventory_empty(self):
        client = _make_client()
        with patch.object(client, "get_log_types", return_value=[]):
            count = collect_inventory(client, self.db)
            self.assertEqual(count, 0)

    def test_collect_inventory_error(self):
        """Erro na coleta deve retornar 0, não levantar exceção."""
        client = _make_client()
        with patch.object(
            client, "get_log_types", side_effect=RuntimeError("API down")
        ):
            count = collect_inventory(client, self.db)
            self.assertEqual(count, 0)

    def test_update_inventory_from_results(self):
        """Callback deve atualizar inventário com sources dos resultados."""
        metrics = [
            {
                "logsourceid": 42,
                "log_source_name": "Windows (Microsoft)",
                "log_source_type": "WINDOWS_EVENT",
            },
            {
                "logsourceid": 99,
                "log_source_name": "Cloud Audit (Google)",
                "log_source_type": "GCP_CLOUDAUDIT",
            },
        ]
        update_inventory_from_results(self.db, metrics)

        cursor = self.db.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM log_sources_inventory")
        self.assertEqual(cursor.fetchone()[0], 2)

        cursor.execute(
            "SELECT name FROM log_sources_inventory WHERE logsource_id = 42"
        )
        self.assertEqual(cursor.fetchone()[0], "Windows (Microsoft)")

    def test_update_inventory_empty_list(self):
        """Lista vazia não deve gerar erro."""
        update_inventory_from_results(self.db, [])
        cursor = self.db.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM log_sources_inventory")
        self.assertEqual(cursor.fetchone()[0], 0)


# ─────────────────────────────────────────────────────────────────────────────
# 8. create_sample_config
# ─────────────────────────────────────────────────────────────────────────────
class TestCreateSampleConfig(unittest.TestCase):
    """Verifica criação de arquivo de configuração de exemplo."""

    def test_creates_valid_json(self):
        with tempfile.NamedTemporaryFile(
            suffix=".json", delete=False, mode="w"
        ) as f:
            path = f.name
        try:
            create_sample_config(path)
            with open(path, "r", encoding="utf-8") as fp:
                config = json.load(fp)
            self.assertIn("service_account_file", config)
            self.assertIn("region", config)
            self.assertEqual(config["region"], "us")
            self.assertIn("collection_days", config)
            self.assertIn("interval_hours", config)
        finally:
            os.unlink(path)


# ─────────────────────────────────────────────────────────────────────────────
# 9. Google SecOps-specific constants
# ─────────────────────────────────────────────────────────────────────────────
class TestSecOpsConstants(unittest.TestCase):
    """Valida constantes específicas do Google SecOps."""

    def test_scopes(self):
        self.assertEqual(len(SCOPES), 1)
        self.assertIn("chronicle-backstory", SCOPES[0])

    def test_udm_search_max_events(self):
        self.assertEqual(UDM_SEARCH_MAX_EVENTS, 10000)

    def test_udm_search_timeout(self):
        self.assertEqual(UDM_SEARCH_TIMEOUT, 600)

    def test_backstory_endpoints_us_default(self):
        self.assertEqual(
            BACKSTORY_ENDPOINTS["us"], "https://backstory.googleapis.com"
        )

    def test_backstory_endpoints_brazil(self):
        self.assertEqual(
            BACKSTORY_ENDPOINTS["southamerica-east1"],
            "https://southamerica-east1-backstory.googleapis.com",
        )

    def test_backstory_endpoints_count(self):
        """Deve ter 19 endpoints regionais conforme documentação."""
        self.assertEqual(len(BACKSTORY_ENDPOINTS), 19)


if __name__ == "__main__":
    unittest.main()
