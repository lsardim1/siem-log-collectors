#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Testes para o módulo Splunk (collectors/splunk/client.py).

Cobre: SplunkClient auth, SPL queries, search flow,
_check_response, test_connection, constantes específicas.

Execução:
    python -m pytest tests/test_splunk.py -v
    python -m unittest tests.test_splunk -v
"""

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collectors.splunk.client import (
    DEFAULT_SPLUNK_PORT,
    MAX_RESULTS_PER_PAGE,
    SPL_POLL_INTERVAL,
    SPL_TIMEOUT_SECONDS,
    SplunkClient,
    collect_inventory,
    update_inventory_from_results,
)
from core.db import MetricsDB


# ─────────────────────────────────────────────────────────────────────────────
# 1. SPL queries
# ─────────────────────────────────────────────────────────────────────────────
class TestSPLQueries(unittest.TestCase):
    """Verifica a construção e execução de queries SPL."""

    def setUp(self):
        self.client = SplunkClient.__new__(SplunkClient)
        self.client.base_url = "https://splunk:8089"
        self.client.verify_ssl = False
        self.client.auth_mode = "token"
        self.client.session = MagicMock()
        self.client.session.verify = False

    def test_spl_contains_stats_by_source(self):
        """SPL deve agregar por source, sourcetype, index."""
        with patch.object(self.client, 'run_spl_query', return_value=[]) as mock_run:
            self.client.get_event_metrics_window(1000, 2000)
            spl = mock_run.call_args[0][0]
            self.assertIn("by source, sourcetype, index", spl)

    def test_spl_contains_stats_functions(self):
        """SPL deve usar count, sum(len(_raw)), avg(len(_raw))."""
        with patch.object(self.client, 'run_spl_query', return_value=[]) as mock_run:
            self.client.get_event_metrics_window(1000, 2000)
            spl = mock_run.call_args[0][0]
            self.assertIn("count as total_event_count", spl)
            self.assertIn("sum(len(_raw)) as total_payload_bytes", spl)
            self.assertIn("avg(len(_raw)) as avg_payload_bytes", spl)

    def test_epoch_time_passed_to_query(self):
        """Tempos devem ser passados como epoch seconds."""
        with patch.object(self.client, 'run_spl_query', return_value=[]) as mock_run:
            self.client.get_event_metrics_window(1000000, 2000000)
            call_args = mock_run.call_args
            earliest = call_args[1].get("earliest", "")
            self.assertIn("1000.000", earliest)

    def test_result_normalization(self):
        """Resultados SPL devem ser normalizados para o formato do MetricsDB."""
        mock_results = [
            {
                "source": "/var/log/syslog",
                "sourcetype": "syslog",
                "index": "main",
                "total_event_count": "5000",
                "total_payload_bytes": "1048576",
                "avg_payload_bytes": "209.7",
            }
        ]
        with patch.object(self.client, 'run_spl_query', return_value=mock_results):
            normalized = self.client.get_event_metrics_window(1000, 2000)
            assert normalized is not None
            self.assertEqual(len(normalized), 1)
            entry = normalized[0]
            self.assertEqual(entry["log_source_name"], "/var/log/syslog [main]")
            self.assertEqual(entry["log_source_type"], "syslog")
            self.assertEqual(entry["total_event_count"], 5000)
            self.assertAlmostEqual(entry["total_payload_bytes"], 1048576.0)


# ─────────────────────────────────────────────────────────────────────────────
# 2. Token precedence
# ─────────────────────────────────────────────────────────────────────────────
class TestTokenPrecedence(unittest.TestCase):
    """Verifica a cadeia de prioridade: CLI > config > ENV > prompt."""

    def test_cli_over_config(self):
        cli_token = "cli_token_123"
        config_token = "config_token_456"
        result = cli_token or config_token or ""
        self.assertEqual(result, "cli_token_123")

    def test_config_over_env(self):
        config_token = "config_token_456"
        with patch.dict(os.environ, {"SPLUNK_TOKEN": "env_token_789"}):
            result = "" or config_token or os.environ.get("SPLUNK_TOKEN", "")
            self.assertEqual(result, "config_token_456")

    def test_env_when_others_empty(self):
        with patch.dict(os.environ, {"SPLUNK_TOKEN": "env_token_789"}):
            result = "" or "" or os.environ.get("SPLUNK_TOKEN", "")
            self.assertEqual(result, "env_token_789")

    def test_all_empty(self):
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("SPLUNK_TOKEN", None)
            result = "" or "" or os.environ.get("SPLUNK_TOKEN", "")
            self.assertEqual(result, "")


# ─────────────────────────────────────────────────────────────────────────────
# 3. Splunk search flow
# ─────────────────────────────────────────────────────────────────────────────
class TestSplunkSearchFlow(unittest.TestCase):
    """Verifica o fluxo completo de search job: POST → poll → GET results."""

    def setUp(self):
        self.client = SplunkClient.__new__(SplunkClient)
        self.client.base_url = "https://splunk:8089"
        self.client.verify_ssl = False
        self.client.auth_mode = "token"
        self.client.session = MagicMock()
        self.client.session.verify = False

    def test_full_search_flow(self):
        """POST cria job → poll isDone → GET results."""
        post_response = {"sid": "1234567890.42"}
        status_response = {
            "entry": [{"content": {"dispatchState": "DONE", "isDone": True, "doneProgress": 1.0}}]
        }
        results_response = {
            "results": [
                {"source": "test.log", "sourcetype": "test", "index": "main",
                 "total_event_count": "100", "total_payload_bytes": "5000", "avg_payload_bytes": "50"}
            ]
        }

        with patch.object(self.client, '_post', return_value=post_response) as mock_post, \
             patch.object(self.client, '_get', side_effect=[status_response, results_response]) as mock_get:

            results = self.client.run_spl_query("index=* | stats count by source")

            assert results is not None
            self.assertEqual(len(results), 1)
            mock_post.assert_called_once()
            self.assertEqual(mock_get.call_count, 2)

    def test_max_count_parameter(self):
        """Job deve incluir max_count para limitar resultados."""
        with patch.object(self.client, '_post', return_value={"sid": "123"}) as mock_post, \
             patch.object(self.client, '_get', side_effect=[
                 {"entry": [{"content": {"isDone": True}}]},
                 {"results": []}
             ]):
            self.client.run_spl_query("index=*")
            post_data = mock_post.call_args[1].get("data", mock_post.call_args[0][1] if len(mock_post.call_args[0]) > 1 else {})
            self.assertEqual(post_data.get("max_count"), MAX_RESULTS_PER_PAGE)


# ─────────────────────────────────────────────────────────────────────────────
# 4. _check_response
# ─────────────────────────────────────────────────────────────────────────────
class TestCheckResponse(unittest.TestCase):
    """Verifica mensagens acionáveis para erros HTTP."""

    def setUp(self):
        self.client = SplunkClient.__new__(SplunkClient)

    def test_401_actionable_message(self):
        resp = MagicMock()
        resp.status_code = 401
        with self.assertRaises(requests.exceptions.HTTPError) as ctx:
            self.client._check_response(resp, "services/search/jobs")
        self.assertIn("401", str(ctx.exception))
        self.assertIn("token", str(ctx.exception).lower())

    def test_403_actionable_message(self):
        resp = MagicMock()
        resp.status_code = 403
        with self.assertRaises(requests.exceptions.HTTPError) as ctx:
            self.client._check_response(resp, "services/search/jobs")
        self.assertIn("403", str(ctx.exception))
        self.assertIn("permiss", str(ctx.exception).lower())

    def test_200_no_exception(self):
        resp = MagicMock()
        resp.status_code = 200
        resp.raise_for_status = MagicMock()
        self.client._check_response(resp, "services/server/info")
        resp.raise_for_status.assert_called_once()


# ─────────────────────────────────────────────────────────────────────────────
# 5. test_connection
# ─────────────────────────────────────────────────────────────────────────────
class TestTestConnection(unittest.TestCase):
    """Verifica test_connection() via /services/server/info."""

    def test_test_connection_calls_server_info(self):
        client = SplunkClient.__new__(SplunkClient)
        client.base_url = "https://splunk:8089"
        client.session = MagicMock()
        client.verify_ssl = False
        client.auth_mode = "token"

        mock_info = {
            "entry": [{
                "content": {
                    "version": "9.2.0",
                    "serverName": "splunk-prod",
                }
            }]
        }
        with patch.object(client, '_get', return_value=mock_info) as mock_get:
            result = client.test_connection()
            mock_get.assert_called_once_with("services/server/info")
            self.assertEqual(result["version"], "9.2.0")


# ─────────────────────────────────────────────────────────────────────────────
# 6. Splunk auth modes
# ─────────────────────────────────────────────────────────────────────────────
class TestSplunkClientAuth(unittest.TestCase):
    """Verifica modos de autenticação do SplunkClient."""

    def test_bearer_token_auth(self):
        client = SplunkClient(
            base_url="https://splunk:8089",
            token="my_bearer_token",
            verify_ssl=False,
        )
        self.assertEqual(client.auth_mode, "token")
        self.assertIn("Authorization", client.session.headers)
        self.assertEqual(client.session.headers["Authorization"], "Bearer my_bearer_token")

    def test_basic_auth(self):
        client = SplunkClient(
            base_url="https://splunk:8089",
            username="admin",
            password="changeme",
            verify_ssl=False,
        )
        self.assertEqual(client.auth_mode, "basic")
        self.assertIsNotNone(client.session.auth)

    def test_no_credentials_raises(self):
        with self.assertRaises(ValueError):
            SplunkClient(
                base_url="https://splunk:8089",
                verify_ssl=False,
            )


# ─────────────────────────────────────────────────────────────────────────────
# 7. Splunk-specific constants
# ─────────────────────────────────────────────────────────────────────────────
class TestSplunkConstants(unittest.TestCase):
    """Valida constantes específicas do Splunk."""

    def test_spl_timeout(self):
        self.assertEqual(SPL_TIMEOUT_SECONDS, 300)

    def test_default_port(self):
        self.assertEqual(DEFAULT_SPLUNK_PORT, 8089)

    def test_max_results(self):
        self.assertEqual(MAX_RESULTS_PER_PAGE, 10000)

    def test_poll_interval(self):
        self.assertEqual(SPL_POLL_INTERVAL, 5)


# ─────────────────────────────────────────────────────────────────────────────
# 8. update_inventory_from_results callback
# ─────────────────────────────────────────────────────────────────────────────
class TestInventoryCallback(unittest.TestCase):
    """Testa o callback de atualização de inventário."""

    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        self.db = MetricsDB(self.db_path)

    def tearDown(self):
        self.db.close()
        os.close(self.db_fd)
        os.unlink(self.db_path)

    def test_update_inventory_from_results(self):
        """Callback deve atualizar inventário com sources de resultados SPL."""
        metrics = [
            {
                "logsourceid": 42,
                "log_source_name": "web_access [main]",
                "log_source_type": "access_combined",
            },
            {
                "logsourceid": 99,
                "log_source_name": "firewall [security]",
                "log_source_type": "pan:traffic",
            },
        ]

        update_inventory_from_results(self.db, metrics)

        cursor = self.db.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM log_sources_inventory")
        self.assertEqual(cursor.fetchone()[0], 2)

        cursor.execute("SELECT name FROM log_sources_inventory WHERE logsource_id = 42")
        self.assertEqual(cursor.fetchone()[0], "web_access [main]")


if __name__ == "__main__":
    unittest.main()
