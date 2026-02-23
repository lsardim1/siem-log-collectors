#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Testes para o módulo QRadar (collectors/qradar/client.py).

Cobre: QRadarClient auth, AQL queries, Ariel async flow,
_check_response, test_connection, constantes específicas.

Execução:
    python -m pytest tests/test_qradar.py -v
    python -m unittest tests.test_qradar -v
"""

import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collectors.qradar.client import (
    AQL_POLL_INTERVAL,
    AQL_TIMEOUT_SECONDS,
    QRadarClient,
    collect_inventory,
    create_sample_config,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
def _make_mock_response(status_code=200, json_data=None, text="", headers=None):
    """Cria um mock de requests.Response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data or {}
    resp.text = text or json.dumps(json_data or {})
    resp.headers = headers or {}
    resp.raise_for_status = MagicMock()
    if status_code >= 400:
        http_error = requests.exceptions.HTTPError(response=resp)
        resp.raise_for_status.side_effect = http_error
    return resp


# ─────────────────────────────────────────────────────────────────────────────
# 1. AQL query correctness
# ─────────────────────────────────────────────────────────────────────────────
class TestAQLQueries(unittest.TestCase):
    """Verifica que as queries AQL usam as funções e cláusulas corretas."""

    def setUp(self):
        self.client = QRadarClient(
            "https://qradar.test", "FAKE_TOKEN", verify_ssl=False
        )

    @patch.object(QRadarClient, "run_aql_query", return_value=[])
    def test_event_metrics_uses_devicetype_in_logsourcetypename(self, mock_aql):
        """LOGSOURCETYPENAME deve receber devicetype, não logsourceid."""
        self.client.get_event_metrics_window(1000, 2000)
        aql = mock_aql.call_args_list[0][0][0]
        self.assertIn("LOGSOURCETYPENAME(devicetype)", aql)
        self.assertNotIn("LOGSOURCETYPENAME(logsourceid)", aql)

    @patch.object(QRadarClient, "run_aql_query", return_value=[])
    def test_event_metrics_uses_half_open_interval(self, mock_aql):
        """WHERE deve usar starttime >= start AND starttime < end (half-open)."""
        start_ms, end_ms = 1000000, 2000000
        self.client.get_event_metrics_window(start_ms, end_ms)
        aql = mock_aql.call_args_list[0][0][0]
        self.assertIn(f"starttime >= {start_ms}", aql)
        self.assertIn(f"starttime < {end_ms}", aql)
        self.assertNotIn("BETWEEN", aql.upper())

    @patch.object(QRadarClient, "run_aql_query", return_value=[])
    def test_event_metrics_groups_by_logsourceid_and_devicetype(self, mock_aql):
        """GROUP BY deve incluir ambos logsourceid e devicetype."""
        self.client.get_event_metrics_window(1000, 2000)
        aql = mock_aql.call_args_list[0][0][0]
        self.assertIn("GROUP BY logsourceid, devicetype", aql)

    @patch.object(QRadarClient, "run_aql_query", return_value=[])
    def test_deprecated_method_also_correct(self, mock_aql):
        """get_event_counts_by_logsource (deprecated) deve usar devicetype também."""
        self.client.get_event_counts_by_logsource(1000, 2000)
        aql = mock_aql.call_args[0][0]
        self.assertIn("LOGSOURCETYPENAME(devicetype)", aql)
        self.assertIn("GROUP BY logsourceid, devicetype", aql)


# ─────────────────────────────────────────────────────────────────────────────
# 2. Ariel async flow (mocked HTTP)
# ─────────────────────────────────────────────────────────────────────────────
class TestArielAsyncFlow(unittest.TestCase):
    """Simula POST /ariel/searches → poll → GET /results."""

    def setUp(self):
        self.client = QRadarClient(
            "https://qradar.test", "FAKE_TOKEN", verify_ssl=False
        )

    @patch("time.sleep", return_value=None)
    def test_full_aql_flow(self, _mock_sleep):
        """POST cria search → poll WAIT→COMPLETED → GET results."""
        search_id = "abc-123-search"
        expected_events = [
            {
                "logsourceid": 100,
                "log_source_name": "Firewall-A",
                "log_source_type": "Palo Alto",
                "total_event_count": 5000,
                "aggregated_event_count": 4500,
                "total_payload_bytes": 1200000,
                "avg_payload_bytes": 240,
            },
        ]

        post_resp = _make_mock_response(201, {"search_id": search_id})
        status_wait = _make_mock_response(200, {"status": "WAIT", "search_id": search_id})
        status_complete = _make_mock_response(200, {"status": "COMPLETED", "search_id": search_id})
        results_resp = _make_mock_response(200, {"events": expected_events})

        with patch.object(self.client.session, "post", return_value=post_resp):
            with patch.object(self.client.session, "get") as mock_get:
                mock_get.side_effect = [status_wait, status_complete, results_resp]
                events = self.client.run_aql_query("SELECT * FROM events LAST 1 HOURS")

        self.assertIsNotNone(events)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["logsourceid"], 100)
        self.assertEqual(events[0]["total_event_count"], 5000)

    @patch("time.sleep", return_value=None)
    def test_results_request_includes_range_header(self, _mock_sleep):
        """Verifica que o GET /results inclui Range header."""
        search_id = "range-test-id"
        post_resp = _make_mock_response(201, {"search_id": search_id})
        status_complete = _make_mock_response(200, {"status": "COMPLETED", "search_id": search_id})
        results_resp = _make_mock_response(200, {"events": []})

        with patch.object(self.client.session, "post", return_value=post_resp):
            with patch.object(self.client.session, "get") as mock_get:
                mock_get.side_effect = [status_complete, results_resp]
                self.client.run_aql_query("SELECT 1")

        last_get_call = mock_get.call_args_list[-1]
        headers_sent = last_get_call.kwargs.get("headers") or last_get_call[1].get("headers", {})
        self.assertIn("Range", headers_sent or {})


# ─────────────────────────────────────────────────────────────────────────────
# 3. _check_response
# ─────────────────────────────────────────────────────────────────────────────
class TestCheckResponse(unittest.TestCase):
    """Verifica mensagens acionáveis para 401/403."""

    def setUp(self):
        self.client = QRadarClient(
            "https://qradar.test", "FAKE_TOKEN", verify_ssl=False
        )

    def test_401_raises_with_message(self):
        resp = _make_mock_response(401)
        with self.assertRaises(requests.exceptions.HTTPError) as ctx:
            self.client._check_response(resp, "test_endpoint")
        self.assertIn("401", str(ctx.exception))
        self.assertIn("token", str(ctx.exception).lower())

    def test_403_raises_with_message(self):
        resp = _make_mock_response(403)
        with self.assertRaises(requests.exceptions.HTTPError) as ctx:
            self.client._check_response(resp, "test_endpoint")
        self.assertIn("403", str(ctx.exception))
        self.assertIn("permiss", str(ctx.exception).lower())

    def test_200_passes_silently(self):
        resp = _make_mock_response(200)
        self.client._check_response(resp, "test_endpoint")


# ─────────────────────────────────────────────────────────────────────────────
# 4. test_connection
# ─────────────────────────────────────────────────────────────────────────────
class TestTestConnection(unittest.TestCase):
    """Verifica o método test_connection()."""

    def setUp(self):
        self.client = QRadarClient(
            "https://qradar.test", "FAKE_TOKEN", verify_ssl=False
        )

    @patch.object(QRadarClient, "_get")
    def test_successful_connection(self, mock_get):
        mock_get.return_value = {"external_version": "7.5.0"}
        info = self.client.test_connection()
        self.assertEqual(info["external_version"], "7.5.0")
        mock_get.assert_called_once_with("system/about")


# ─────────────────────────────────────────────────────────────────────────────
# 5. QRadar-specific constants
# ─────────────────────────────────────────────────────────────────────────────
class TestQRadarConstants(unittest.TestCase):
    """Valida constantes específicas do QRadar."""

    def test_aql_timeout(self):
        self.assertEqual(AQL_TIMEOUT_SECONDS, 300)

    def test_aql_poll_interval(self):
        self.assertEqual(AQL_POLL_INTERVAL, 5)


# ─────────────────────────────────────────────────────────────────────────────
# 6. QRadar auth
# ─────────────────────────────────────────────────────────────────────────────
class TestQRadarAuth(unittest.TestCase):
    """Verifica que o SEC token é incluído nos headers."""

    def test_sec_header_set(self):
        client = QRadarClient("https://qradar.test", "MY_SEC_TOKEN", verify_ssl=False)
        self.assertEqual(client.session.headers["SEC"], "MY_SEC_TOKEN")

    def test_api_version_header(self):
        client = QRadarClient("https://qradar.test", "TOKEN", api_version="20.0")
        self.assertEqual(client.session.headers["Version"], "20.0")


if __name__ == "__main__":
    unittest.main()
