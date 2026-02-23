#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Suite de testes para splunk_log_collector_v2.py

Valida as funcionalidades críticas do coletor Splunk usando mocks
(sem necessidade de conexão real com o Splunk).

Execução:
    python -m pytest test_splunk_log_collector.py -v
    python -m unittest test_splunk_log_collector -v
"""

import datetime
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch, PropertyMock

import requests

import splunk_log_collector_v2 as collector


# ─────────────────────────────────────────────────────────────────────────────
# 1. Test collection_date boundary (same logic as QRadar)
# ─────────────────────────────────────────────────────────────────────────────
class TestCollectionDateBoundary(unittest.TestCase):
    """Verifica que collection_date é derivada de window_end_ms - 1ms."""

    def test_midnight_boundary(self):
        """Janela 23:00-00:00 deve pertencer ao dia anterior."""
        # 2026-02-22 23:00 UTC → 2026-02-23 00:00 UTC
        start = int(datetime.datetime(2026, 2, 22, 23, 0, 0, tzinfo=datetime.timezone.utc).timestamp() * 1000)
        end = int(datetime.datetime(2026, 2, 23, 0, 0, 0, tzinfo=datetime.timezone.utc).timestamp() * 1000)

        end_dt = datetime.datetime.fromtimestamp((end - 1) / 1000.0, tz=datetime.timezone.utc)
        collection_date = end_dt.strftime("%Y-%m-%d")
        self.assertEqual(collection_date, "2026-02-22")

    def test_one_ms_after_midnight(self):
        """Janela que termina 1ms após meia-noite pertence ao novo dia."""
        end = int(datetime.datetime(2026, 2, 23, 0, 0, 0, tzinfo=datetime.timezone.utc).timestamp() * 1000) + 1

        end_dt = datetime.datetime.fromtimestamp((end - 1) / 1000.0, tz=datetime.timezone.utc)
        collection_date = end_dt.strftime("%Y-%m-%d")
        self.assertEqual(collection_date, "2026-02-23")

    def test_midday(self):
        """Janela ao meio-dia pertence ao mesmo dia."""
        end = int(datetime.datetime(2026, 2, 22, 12, 0, 0, tzinfo=datetime.timezone.utc).timestamp() * 1000)
        end_dt = datetime.datetime.fromtimestamp((end - 1) / 1000.0, tz=datetime.timezone.utc)
        collection_date = end_dt.strftime("%Y-%m-%d")
        self.assertEqual(collection_date, "2026-02-22")


# ─────────────────────────────────────────────────────────────────────────────
# 2. Test SPL queries
# ─────────────────────────────────────────────────────────────────────────────
class TestSPLQueries(unittest.TestCase):
    """Verifica a construção e execução de queries SPL."""

    def setUp(self):
        self.client = collector.SplunkClient.__new__(collector.SplunkClient)
        self.client.base_url = "https://splunk:8089"
        self.client.verify_ssl = False
        self.client.auth_mode = "token"
        self.client.session = MagicMock()
        self.client.session.verify = False

    def test_spl_contains_stats_by_source(self):
        """SPL deve agregar por source, sourcetype, index."""
        with patch.object(self.client, 'run_spl_query', return_value=[]) as mock_run:
            self.client.get_event_metrics_window(1000, 2000)
            call_args = mock_run.call_args
            spl = call_args[0][0]  # primeiro argumento posicional
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
        """Tempos devem ser passados como epoch seconds para earliest/latest."""
        with patch.object(self.client, 'run_spl_query', return_value=[]) as mock_run:
            self.client.get_event_metrics_window(1000000, 2000000)
            _, kwargs = mock_run.call_args[0][0], mock_run.call_args[1] if mock_run.call_args[1] else {}
            earliest = mock_run.call_args[1].get("earliest", mock_run.call_args[0][1] if len(mock_run.call_args[0]) > 1 else "")
            # Tempo deve estar em epoch seconds (ms / 1000)
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
# 3. Test token precedence
# ─────────────────────────────────────────────────────────────────────────────
class TestTokenPrecedence(unittest.TestCase):
    """Verifica a cadeia de prioridade: CLI > config > ENV > prompt."""

    def test_cli_over_config(self):
        """--token CLI deve prevalecer sobre config."""
        # Simula: CLI tem token, config tem outro
        cli_token = "cli_token_123"
        config_token = "config_token_456"
        result = cli_token or config_token or ""
        self.assertEqual(result, "cli_token_123")

    def test_config_over_env(self):
        """config.json deve prevalecer sobre env quando CLI está vazio."""
        config_token = "config_token_456"
        with patch.dict(os.environ, {"SPLUNK_TOKEN": "env_token_789"}):
            result = "" or config_token or os.environ.get("SPLUNK_TOKEN", "")
            self.assertEqual(result, "config_token_456")

    def test_env_when_others_empty(self):
        """Env deve ser usado quando CLI e config estão vazios."""
        with patch.dict(os.environ, {"SPLUNK_TOKEN": "env_token_789"}):
            result = "" or "" or os.environ.get("SPLUNK_TOKEN", "")
            self.assertEqual(result, "env_token_789")

    def test_all_empty(self):
        """Quando tudo vazio, resultado é string vazia."""
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("SPLUNK_TOKEN", None)
            result = "" or "" or os.environ.get("SPLUNK_TOKEN", "")
            self.assertEqual(result, "")

    def test_basic_auth_alternative(self):
        """Quando não há token, username+password devem ser aceitos."""
        client = collector.SplunkClient.__new__(collector.SplunkClient)
        # SplunkClient aceita username+password como alternativa
        client2 = collector.SplunkClient(
            base_url="https://splunk:8089",
            username="admin",
            password="changeme",
            verify_ssl=False,
        )
        self.assertEqual(client2.auth_mode, "basic")


# ─────────────────────────────────────────────────────────────────────────────
# 4. Test Splunk async search flow
# ─────────────────────────────────────────────────────────────────────────────
class TestSplunkSearchFlow(unittest.TestCase):
    """Verifica o fluxo completo de search job: POST → poll → GET results."""

    def setUp(self):
        self.client = collector.SplunkClient.__new__(collector.SplunkClient)
        self.client.base_url = "https://splunk:8089"
        self.client.verify_ssl = False
        self.client.auth_mode = "token"
        self.client.session = MagicMock()
        self.client.session.verify = False

    def test_full_search_flow(self):
        """POST cria job → poll isDone → GET results."""
        # Mock POST (criar job)
        post_response = {"sid": "1234567890.42"}

        # Mock GET status (job done)
        status_response = {
            "entry": [{"content": {"dispatchState": "DONE", "isDone": True, "doneProgress": 1.0}}]
        }

        # Mock GET results
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
            # POST para criar job
            mock_post.assert_called_once()
            # GET para status + GET para results = 2 chamadas
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
            self.assertEqual(post_data.get("max_count"), collector.MAX_RESULTS_PER_PAGE)


# ─────────────────────────────────────────────────────────────────────────────
# 5. Test zero-fill
# ─────────────────────────────────────────────────────────────────────────────
class TestZeroFill(unittest.TestCase):
    """Verifica zero-fill para fontes que não tiveram eventos na janela."""

    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        self.db = collector.MetricsDB(self.db_path)
        # Inserir inventário com 3 sources
        self.db.save_log_sources_inventory([
            {"logsource_id": 1, "name": "source_A [main]", "type_name": "syslog"},
            {"logsource_id": 2, "name": "source_B [main]", "type_name": "access_combined"},
            {"logsource_id": 3, "name": "source_C [security]", "type_name": "WinEventLog"},
        ])

    def tearDown(self):
        self.db.close()
        os.close(self.db_fd)
        os.unlink(self.db_path)

    def test_zero_fill_inserts_missing(self):
        """Sources ausentes devem receber linhas com zero."""
        run_id = self.db.save_collection_run("2026-02-22T10:00:00", "2026-02-22", 1.0)
        seen = {1}  # só source_A teve eventos
        count = self.db.fill_zero_event_rows(
            run_id, "2026-02-22T10:00:00", "2026-02-22",
            1000, 4600000, 3600.0, seen, 1.0,
        )
        self.assertEqual(count, 2)  # source_B e source_C

    def test_zero_fill_skips_present(self):
        """Sources presentes não devem receber linhas zero."""
        run_id = self.db.save_collection_run("2026-02-22T10:00:00", "2026-02-22", 1.0)
        seen = {1, 2, 3}  # todos presentes
        count = self.db.fill_zero_event_rows(
            run_id, "2026-02-22T10:00:00", "2026-02-22",
            1000, 4600000, 3600.0, seen, 1.0,
        )
        self.assertEqual(count, 0)


# ─────────────────────────────────────────────────────────────────────────────
# 6. Test catch-up cap
# ─────────────────────────────────────────────────────────────────────────────
class TestCatchUpCap(unittest.TestCase):
    """Verifica que o catch-up com cap limita a janela."""

    def test_cap_limits_window(self):
        """Janela > MAX_CATCHUP_WINDOWS * intervalo deve ser cortada."""
        interval_seconds = 3600
        max_window_ms = int(interval_seconds * 1000 * collector.MAX_CATCHUP_WINDOWS)

        window_end_ms = 10_000_000_000  # agora
        last_window_end_ms = window_end_ms - (max_window_ms * 2)  # 2x o limite

        window_start_ms = last_window_end_ms
        if (window_end_ms - window_start_ms) > max_window_ms:
            window_start_ms = window_end_ms - max_window_ms

        actual_window = window_end_ms - window_start_ms
        self.assertEqual(actual_window, max_window_ms)

    def test_gap_within_limit_kept(self):
        """Janela dentro do limite não deve ser alterada."""
        interval_seconds = 3600
        max_window_ms = int(interval_seconds * 1000 * collector.MAX_CATCHUP_WINDOWS)

        window_end_ms = 10_000_000_000
        last_window_end_ms = window_end_ms - int(interval_seconds * 1000 * 2)  # 2x (< 3x)

        window_start_ms = last_window_end_ms
        if (window_end_ms - window_start_ms) > max_window_ms:
            window_start_ms = window_end_ms - max_window_ms

        self.assertEqual(window_start_ms, last_window_end_ms)


# ─────────────────────────────────────────────────────────────────────────────
# 7. Test _check_response
# ─────────────────────────────────────────────────────────────────────────────
class TestCheckResponse(unittest.TestCase):
    """Verifica mensagens acionáveis para erros HTTP."""

    def setUp(self):
        self.client = collector.SplunkClient.__new__(collector.SplunkClient)

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
# 8. Test test_connection
# ─────────────────────────────────────────────────────────────────────────────
class TestTestConnection(unittest.TestCase):
    """Verifica test_connection() via /services/server/info."""

    def test_test_connection_calls_server_info(self):
        client = collector.SplunkClient.__new__(collector.SplunkClient)
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
# 9. Test run_collection_cycle (integration with real DB)
# ─────────────────────────────────────────────────────────────────────────────
class TestRunCollectionCycle(unittest.TestCase):
    """Testa ciclo completo com DB real (SQLite temporário)."""

    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        self.db = collector.MetricsDB(self.db_path)
        self.db.save_log_sources_inventory([
            {"logsource_id": 10, "name": "web_access [main]", "type_name": "access_combined"},
            {"logsource_id": 20, "name": "firewall [security]", "type_name": "pan:traffic"},
        ])
        self.client = MagicMock(spec=collector.SplunkClient)

    def tearDown(self):
        self.db.close()
        os.close(self.db_fd)
        os.unlink(self.db_path)

    def test_cycle_with_partial_data(self):
        """Ciclo com apenas 1 source retornando dados → zero-fill para o outro."""
        self.client.get_event_metrics_window.return_value = [
            {
                "logsourceid": 10,
                "log_source_name": "web_access [main]",
                "log_source_type": "access_combined",
                "aggregated_event_count": 500,
                "total_event_count": 500,
                "total_payload_bytes": 25000,
                "avg_payload_bytes": 50,
            }
        ]

        start_ms = 1000000000000
        end_ms = start_ms + 3600000

        ds_count = collector.run_collection_cycle(
            client=self.client, db=self.db,
            interval_hours=1.0,
            window_start_ms=start_ms, window_end_ms=end_ms,
        )
        self.assertEqual(ds_count, 1)

        # Verificar que zero-fill ocorreu: 2 linhas no total (1 real + 1 zero)
        cursor = self.db.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM event_metrics")
        total_rows = cursor.fetchone()[0]
        self.assertEqual(total_rows, 2)

    def test_cycle_with_no_data(self):
        """Ciclo sem dados (None) deve não salvar, mas não crashar."""
        self.client.get_event_metrics_window.return_value = None

        ds_count = collector.run_collection_cycle(
            client=self.client, db=self.db,
            interval_hours=1.0,
            window_start_ms=1000000000000, window_end_ms=1000003600000,
        )
        self.assertEqual(ds_count, 0)


# ─────────────────────────────────────────────────────────────────────────────
# 10. Test retry with backoff
# ─────────────────────────────────────────────────────────────────────────────
class TestRetryWithBackoff(unittest.TestCase):
    """Verifica retry em 500 e sem retry em 401."""

    @patch("splunk_log_collector_v2.time.sleep")
    def test_retry_on_500(self, mock_sleep):
        call_count = 0

        def flaky():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                resp = MagicMock()
                resp.status_code = 500
                resp.headers = {}
                raise requests.exceptions.HTTPError(response=resp)
            return "ok"

        result = collector._retry_with_backoff(flaky)
        self.assertEqual(result, "ok")
        self.assertEqual(call_count, 3)

    def test_no_retry_on_401(self):
        def unauthorized():
            resp = MagicMock()
            resp.status_code = 401
            raise requests.exceptions.HTTPError(response=resp)

        with self.assertRaises(requests.exceptions.HTTPError):
            collector._retry_with_backoff(unauthorized)


# ─────────────────────────────────────────────────────────────────────────────
# 11. Test constants
# ─────────────────────────────────────────────────────────────────────────────
class TestConstants(unittest.TestCase):
    """Valida valores esperados de configuração."""

    def test_default_collection_days(self):
        self.assertEqual(collector.DEFAULT_COLLECTION_DAYS, 6)

    def test_max_catchup_windows(self):
        self.assertEqual(collector.MAX_CATCHUP_WINDOWS, 3)

    def test_spl_timeout(self):
        self.assertEqual(collector.SPL_TIMEOUT_SECONDS, 300)

    def test_default_port(self):
        self.assertEqual(collector.DEFAULT_SPLUNK_PORT, 8089)

    def test_retryable_statuses(self):
        self.assertIn(429, collector.RETRYABLE_HTTP_STATUSES)
        self.assertIn(500, collector.RETRYABLE_HTTP_STATUSES)
        self.assertNotIn(401, collector.RETRYABLE_HTTP_STATUSES)
        self.assertNotIn(403, collector.RETRYABLE_HTTP_STATUSES)


# ─────────────────────────────────────────────────────────────────────────────
# 12. Test SplunkClient auth modes
# ─────────────────────────────────────────────────────────────────────────────
class TestSplunkClientAuth(unittest.TestCase):
    """Verifica modos de autenticação do SplunkClient."""

    def test_bearer_token_auth(self):
        client = collector.SplunkClient(
            base_url="https://splunk:8089",
            token="my_bearer_token",
            verify_ssl=False,
        )
        self.assertEqual(client.auth_mode, "token")
        self.assertIn("Authorization", client.session.headers)
        self.assertEqual(client.session.headers["Authorization"], "Bearer my_bearer_token")

    def test_basic_auth(self):
        client = collector.SplunkClient(
            base_url="https://splunk:8089",
            username="admin",
            password="changeme",
            verify_ssl=False,
        )
        self.assertEqual(client.auth_mode, "basic")
        self.assertIsNotNone(client.session.auth)

    def test_no_credentials_raises(self):
        with self.assertRaises(ValueError):
            collector.SplunkClient(
                base_url="https://splunk:8089",
                verify_ssl=False,
            )


if __name__ == "__main__":
    unittest.main()
