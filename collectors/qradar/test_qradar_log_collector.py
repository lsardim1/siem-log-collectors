#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Testes unitários e de integração para qradar_log_collector_v2.py
======================================================================
Execução:
    python -m pytest test_qradar_log_collector.py -v
    # ou sem pytest instalado:
    python -m unittest test_qradar_log_collector -v
"""

import datetime
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch, PropertyMock

# Importar o módulo sob teste
# (ajuste o nome do módulo se o arquivo foi renomeado)
import qradar_log_collector_v2 as collector


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
def _epoch_ms(year, month, day, hour=0, minute=0, second=0, ms=0):
    """Cria epoch em milissegundos para um datetime UTC."""
    dt = datetime.datetime(year, month, day, hour, minute, second,
                           tzinfo=datetime.timezone.utc)
    return int(dt.timestamp() * 1000) + ms


def _make_mock_response(status_code=200, json_data=None, text="", headers=None):
    """Cria um mock de requests.Response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data or {}
    resp.text = text or json.dumps(json_data or {})
    resp.headers = headers or {}
    resp.raise_for_status = MagicMock()
    if status_code >= 400:
        import requests
        http_error = requests.exceptions.HTTPError(response=resp)
        resp.raise_for_status.side_effect = http_error
    return resp


# ─────────────────────────────────────────────────────────────────────────────
# 1. collection_date boundary: meia-noite exata
# ─────────────────────────────────────────────────────────────────────────────
class TestCollectionDateBoundary(unittest.TestCase):
    """Verifica que collection_date é derivada de (window_end_ms - 1ms),
    de modo que uma janela terminando exatamente à meia-noite (00:00:00.000)
    é atribuída ao dia anterior."""

    def test_midnight_boundary_assigns_previous_day(self):
        """Janela 23:00→00:00 do dia 2026-01-16 deve ter collection_date = 2026-01-15."""
        # window_end_ms = 2026-01-16 00:00:00.000 UTC (meia-noite)
        window_end_ms = _epoch_ms(2026, 1, 16, 0, 0, 0)
        window_start_ms = _epoch_ms(2026, 1, 15, 23, 0, 0)

        # Simular lógica de run_collection_cycle
        window_end_dt = datetime.datetime.fromtimestamp(
            (max(window_end_ms - 1, window_start_ms) / 1000.0),
            tz=datetime.timezone.utc,
        )
        collection_date = window_end_dt.strftime("%Y-%m-%d")
        self.assertEqual(collection_date, "2026-01-15")

    def test_one_ms_after_midnight_assigns_current_day(self):
        """Janela que termina 1ms após meia-noite deve ser atribuída ao dia corrente."""
        window_end_ms = _epoch_ms(2026, 1, 16, 0, 0, 0, ms=1)
        window_start_ms = _epoch_ms(2026, 1, 15, 23, 0, 0)

        window_end_dt = datetime.datetime.fromtimestamp(
            (max(window_end_ms - 1, window_start_ms) / 1000.0),
            tz=datetime.timezone.utc,
        )
        collection_date = window_end_dt.strftime("%Y-%m-%d")
        self.assertEqual(collection_date, "2026-01-16")

    def test_midday_window_same_day(self):
        """Janela 11:00→12:00 deve atribuir ao mesmo dia."""
        window_end_ms = _epoch_ms(2026, 3, 10, 12, 0, 0)
        window_start_ms = _epoch_ms(2026, 3, 10, 11, 0, 0)

        window_end_dt = datetime.datetime.fromtimestamp(
            (max(window_end_ms - 1, window_start_ms) / 1000.0),
            tz=datetime.timezone.utc,
        )
        collection_date = window_end_dt.strftime("%Y-%m-%d")
        self.assertEqual(collection_date, "2026-03-10")


# ─────────────────────────────────────────────────────────────────────────────
# 2. AQL query correctness
# ─────────────────────────────────────────────────────────────────────────────
class TestAQLQueries(unittest.TestCase):
    """Verifica que as queries AQL usam as funções e cláusulas corretas."""

    def setUp(self):
        self.client = collector.QRadarClient(
            "https://qradar.test", "FAKE_TOKEN", verify_ssl=False
        )

    @patch.object(collector.QRadarClient, "run_aql_query", return_value=[])
    def test_event_metrics_uses_devicetype_in_logsourcetypename(self, mock_aql):
        """LOGSOURCETYPENAME deve receber devicetype, não logsourceid."""
        self.client.get_event_metrics_window(1000, 2000)
        # Pegar a AQL enviada (primeira chamada, primeiro argumento posicional)
        aql = mock_aql.call_args_list[0][0][0]
        self.assertIn("LOGSOURCETYPENAME(devicetype)", aql)
        self.assertNotIn("LOGSOURCETYPENAME(logsourceid)", aql)

    @patch.object(collector.QRadarClient, "run_aql_query", return_value=[])
    def test_event_metrics_uses_half_open_interval(self, mock_aql):
        """WHERE deve usar starttime >= start AND starttime < end (half-open)."""
        start_ms, end_ms = 1000000, 2000000
        self.client.get_event_metrics_window(start_ms, end_ms)
        aql = mock_aql.call_args_list[0][0][0]
        self.assertIn(f"starttime >= {start_ms}", aql)
        self.assertIn(f"starttime < {end_ms}", aql)
        # Não deve usar BETWEEN (double-count)
        self.assertNotIn("BETWEEN", aql.upper())

    @patch.object(collector.QRadarClient, "run_aql_query", return_value=[])
    def test_event_metrics_groups_by_logsourceid_and_devicetype(self, mock_aql):
        """GROUP BY deve incluir ambos logsourceid e devicetype."""
        self.client.get_event_metrics_window(1000, 2000)
        aql = mock_aql.call_args_list[0][0][0]
        self.assertIn("GROUP BY logsourceid, devicetype", aql)

    @patch.object(collector.QRadarClient, "run_aql_query", return_value=[])
    def test_deprecated_method_also_correct(self, mock_aql):
        """get_event_counts_by_logsource (deprecated) deve usar devicetype também."""
        self.client.get_event_counts_by_logsource(1000, 2000)
        aql = mock_aql.call_args[0][0]
        self.assertIn("LOGSOURCETYPENAME(devicetype)", aql)
        self.assertIn("GROUP BY logsourceid, devicetype", aql)


# ─────────────────────────────────────────────────────────────────────────────
# 3. Token precedence
# ─────────────────────────────────────────────────────────────────────────────
class TestTokenPrecedence(unittest.TestCase):
    """Verifica a cadeia de prioridade: CLI > config > ENV > getpass.

    Testa a lógica de resolução de token diretamente, sem chamar main(),
    evitando conflitos com gettext/argparse ao mockar builtins.open.
    """

    @staticmethod
    def _resolve_token(cli_token=None, config_token=None, env_token=None):
        """Reproduz a lógica de resolução de token do main()."""
        args_token = cli_token or ""
        cfg_token = config_token or ""
        env = env_token or ""
        # Mesma expressão de main() (linha ~1188):
        #   api_token = args.token or config.get("api_token", "") or os.environ.get("QRADAR_TOKEN", "")
        return args_token or cfg_token or env

    def test_cli_token_takes_precedence(self):
        """--token no CLI deve prevalecer sobre config e ENV."""
        token = self._resolve_token("CLI_TOKEN", "CONFIG_TOKEN", "ENV_TOKEN")
        self.assertEqual(token, "CLI_TOKEN")

    def test_config_token_over_env(self):
        """Config JSON deve prevalecer sobre variável de ambiente."""
        token = self._resolve_token(None, "CONFIG_TOKEN", "ENV_TOKEN")
        self.assertEqual(token, "CONFIG_TOKEN")

    def test_env_token_used_as_fallback(self):
        """Variável QRADAR_TOKEN usada quando CLI e config estão vazios."""
        token = self._resolve_token(None, None, "ENV_TOKEN")
        self.assertEqual(token, "ENV_TOKEN")

    def test_all_empty_returns_empty(self):
        """Sem nenhum token fornecido, resultado é string vazia."""
        token = self._resolve_token(None, None, None)
        self.assertEqual(token, "")

    def test_main_uses_or_chain(self):
        """Confirma que o código-fonte de main() usa a expressão 'or' chain esperada."""
        import inspect
        source = inspect.getsource(collector.main)
        # Verifica que a linha de resolução segue o padrão OR chain
        self.assertIn("args.token or config.get", source)
        self.assertIn('os.environ.get("QRADAR_TOKEN"', source)


# ─────────────────────────────────────────────────────────────────────────────
# 4. Integration: fluxo Ariel assíncrono completo (mocked HTTP)
# ─────────────────────────────────────────────────────────────────────────────
class TestArielAsyncFlow(unittest.TestCase):
    """Simula o fluxo completo:
       POST /ariel/searches → poll WAIT/COMPLETED → GET /results → eventos JSON.
    """

    def setUp(self):
        self.client = collector.QRadarClient(
            "https://qradar.test", "FAKE_TOKEN", verify_ssl=False
        )

    @patch("time.sleep", return_value=None)  # Não dormir durante testes
    def test_full_aql_flow(self, _mock_sleep):
        """POST cria search → poll evolui WAIT→COMPLETED → GET results retorna events."""
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

        # Respostas esperadas
        post_resp = _make_mock_response(201, {"search_id": search_id})
        status_wait = _make_mock_response(200, {"status": "WAIT", "search_id": search_id})
        status_complete = _make_mock_response(200, {"status": "COMPLETED", "search_id": search_id})
        results_resp = _make_mock_response(200, {"events": expected_events})

        # Sequência de chamadas ao session
        with patch.object(self.client.session, "post", return_value=post_resp):
            with patch.object(self.client.session, "get") as mock_get:
                # Sequência GET: status WAIT → status COMPLETED → results
                mock_get.side_effect = [status_wait, status_complete, results_resp]

                aql = "SELECT * FROM events LAST 1 HOURS"
                events = self.client.run_aql_query(aql)

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

        # O último GET é o fetch de resultados
        last_get_call = mock_get.call_args_list[-1]
        headers_sent = last_get_call.kwargs.get("headers") or last_get_call[1].get("headers", {})
        self.assertIn("Range", headers_sent or {})


# ─────────────────────────────────────────────────────────────────────────────
# 5. Zero-fill: fill_zero_event_rows()
# ─────────────────────────────────────────────────────────────────────────────
class TestZeroFill(unittest.TestCase):
    """Verifica que log sources do inventário sem eventos recebem linhas com zero."""

    def setUp(self):
        self.db_path = tempfile.mktemp(suffix=".db")
        self.db = collector.MetricsDB(self.db_path)

    def tearDown(self):
        self.db.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_zero_fill_inserts_missing_sources(self):
        """Log sources no inventário sem dados AQL devem receber linhas com evento = 0."""
        # Simular inventário com 3 log sources
        inventory = [
            {"id": 1, "name": "Source-A", "type_id": 10, "enabled": True, "description": ""},
            {"id": 2, "name": "Source-B", "type_id": 20, "enabled": True, "description": ""},
            {"id": 3, "name": "Source-C", "type_id": 30, "enabled": True, "description": ""},
        ]
        type_map = {10: "TypeA", 20: "TypeB", 30: "TypeC"}
        self.db.save_log_sources_inventory(inventory, type_map)

        # Salvar run
        run_id = self.db.save_collection_run("2026-01-15T12:00:00", "2026-01-15", 1.0)

        # Simular que apenas Source-A (id=1) teve dados na AQL
        seen_ids = {1}

        zero_filled = self.db.fill_zero_event_rows(
            run_id=run_id,
            collection_time="2026-01-15T12:00:00",
            collection_date="2026-01-15",
            window_start_ms=1000000,
            window_end_ms=4600000,
            window_seconds=3600.0,
            seen_logsource_ids=seen_ids,
            interval_hours=1.0,
        )

        # Devem ter sido preenchidos Source-B (2) e Source-C (3)
        self.assertEqual(zero_filled, 2)

        # Verificar no banco
        cursor = self.db.conn.cursor()
        cursor.execute(
            "SELECT logsource_id, total_event_count FROM event_metrics WHERE run_id = ?",
            (run_id,),
        )
        rows = {row[0]: row[1] for row in cursor.fetchall()}
        self.assertIn(2, rows)
        self.assertIn(3, rows)
        self.assertEqual(rows[2], 0)
        self.assertEqual(rows[3], 0)

    def test_zero_fill_skips_seen_sources(self):
        """Log sources que apareceram na AQL NÃO devem ser zero-filled."""
        inventory = [
            {"id": 1, "name": "Source-A", "type_id": 10, "enabled": True, "description": ""},
        ]
        type_map = {10: "TypeA"}
        self.db.save_log_sources_inventory(inventory, type_map)

        run_id = self.db.save_collection_run("2026-01-15T12:00:00", "2026-01-15", 1.0)
        seen_ids = {1}  # Source-A está presente na AQL

        zero_filled = self.db.fill_zero_event_rows(
            run_id=run_id,
            collection_time="2026-01-15T12:00:00",
            collection_date="2026-01-15",
            window_start_ms=1000000,
            window_end_ms=4600000,
            window_seconds=3600.0,
            seen_logsource_ids=seen_ids,
            interval_hours=1.0,
        )

        self.assertEqual(zero_filled, 0)


# ─────────────────────────────────────────────────────────────────────────────
# 6. Catch-up com cap (MAX_CATCHUP_WINDOWS)
# ─────────────────────────────────────────────────────────────────────────────
class TestCatchUpCap(unittest.TestCase):
    """Verifica a lógica de catch-up com limite de janelas."""

    def test_cap_limits_window_size(self):
        """Se o gap exceder MAX_CATCHUP_WINDOWS × intervalo, a janela é recortada."""
        interval_seconds = 3600  # 1h
        max_window_ms = int(interval_seconds * 1000 * collector.MAX_CATCHUP_WINDOWS)

        # Simular 5 intervalos de gap (excede MAX_CATCHUP_WINDOWS=3)
        window_end_ms = 5 * interval_seconds * 1000 + 1000000
        last_window_end_ms = 1000000  # muito atrás

        gap = window_end_ms - last_window_end_ms
        self.assertGreater(gap, max_window_ms)

        # Aplicar a mesma lógica do main()
        window_start_ms = last_window_end_ms
        if (window_end_ms - window_start_ms) > max_window_ms:
            window_start_ms = window_end_ms - max_window_ms

        actual_window = window_end_ms - window_start_ms
        self.assertEqual(actual_window, max_window_ms)

    def test_no_cap_when_within_limit(self):
        """Sem cap quando o gap está dentro do limite permitido."""
        interval_seconds = 3600
        max_window_ms = int(interval_seconds * 1000 * collector.MAX_CATCHUP_WINDOWS)

        # Gap de 2 intervalos (dentro do limite de 3)
        window_end_ms = 2 * interval_seconds * 1000 + 1000000
        last_window_end_ms = 1000000

        window_start_ms = last_window_end_ms
        if (window_end_ms - window_start_ms) > max_window_ms:
            window_start_ms = window_end_ms - max_window_ms

        # Deve manter a janela original
        self.assertEqual(window_start_ms, last_window_end_ms)


# ─────────────────────────────────────────────────────────────────────────────
# 7. _check_response (mensagens acionáveis para 401/403)
# ─────────────────────────────────────────────────────────────────────────────
class TestCheckResponse(unittest.TestCase):
    """Verifica que _check_response gera mensagens claras para erros de autenticação."""

    def setUp(self):
        self.client = collector.QRadarClient(
            "https://qradar.test", "FAKE_TOKEN", verify_ssl=False
        )

    def test_401_raises_with_message(self):
        """HTTP 401 deve gerar HTTPError com mensagem sobre token expirado."""
        import requests
        resp = _make_mock_response(401)
        with self.assertRaises(requests.exceptions.HTTPError) as ctx:
            self.client._check_response(resp, "test_endpoint")
        self.assertIn("401", str(ctx.exception))
        self.assertIn("token", str(ctx.exception).lower())

    def test_403_raises_with_message(self):
        """HTTP 403 deve gerar HTTPError com mensagem sobre permissões."""
        import requests
        resp = _make_mock_response(403)
        with self.assertRaises(requests.exceptions.HTTPError) as ctx:
            self.client._check_response(resp, "test_endpoint")
        self.assertIn("403", str(ctx.exception))
        self.assertIn("permiss", str(ctx.exception).lower())

    def test_200_passes_silently(self):
        """HTTP 200 não deve gerar exceção."""
        resp = _make_mock_response(200)
        # Não deve lançar
        self.client._check_response(resp, "test_endpoint")


# ─────────────────────────────────────────────────────────────────────────────
# 8. test_connection
# ─────────────────────────────────────────────────────────────────────────────
class TestTestConnection(unittest.TestCase):
    """Verifica o método test_connection()."""

    def setUp(self):
        self.client = collector.QRadarClient(
            "https://qradar.test", "FAKE_TOKEN", verify_ssl=False
        )

    @patch.object(collector.QRadarClient, "_get")
    def test_successful_connection(self, mock_get):
        """Deve retornar informações do QRadar quando a conexão for bem-sucedida."""
        mock_get.return_value = {"external_version": "7.5.0"}
        info = self.client.test_connection()
        self.assertEqual(info["external_version"], "7.5.0")
        mock_get.assert_called_once_with("system/about")


# ─────────────────────────────────────────────────────────────────────────────
# 9. run_collection_cycle integration (com DB real)
# ─────────────────────────────────────────────────────────────────────────────
class TestRunCollectionCycle(unittest.TestCase):
    """Testa run_collection_cycle com mock de QRadarClient e DB real (in-memory style)."""

    def setUp(self):
        self.db_path = tempfile.mktemp(suffix=".db")
        self.db = collector.MetricsDB(self.db_path)
        self.client = MagicMock(spec=collector.QRadarClient)

        # Simular inventário
        inventory = [
            {"id": 1, "name": "FW-1", "type_id": 10, "enabled": True, "description": ""},
            {"id": 2, "name": "IDS-1", "type_id": 20, "enabled": True, "description": ""},
        ]
        type_map = {10: "Firewall", 20: "IDS"}
        self.db.save_log_sources_inventory(inventory, type_map)

    def tearDown(self):
        self.db.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_cycle_with_partial_data(self):
        """Se AQL retorna só FW-1, IDS-1 deve ser zero-filled."""
        self.client.get_event_metrics_window.return_value = [
            {
                "logsourceid": 1,
                "log_source_name": "FW-1",
                "log_source_type": "Firewall",
                "aggregated_event_count": 100,
                "total_event_count": 500,
                "total_payload_bytes": 50000,
                "avg_payload_bytes": 500,
            }
        ]

        window_start = _epoch_ms(2026, 1, 15, 11, 0, 0)
        window_end = _epoch_ms(2026, 1, 15, 12, 0, 0)

        ds_count = collector.run_collection_cycle(
            client=self.client,
            db=self.db,
            interval_hours=1.0,
            window_start_ms=window_start,
            window_end_ms=window_end,
        )

        self.assertEqual(ds_count, 1)  # Apenas FW-1 com dados

        # Verificar que IDS-1 (id=2) foi zero-filled
        cursor = self.db.conn.cursor()
        cursor.execute("SELECT logsource_id, total_event_count FROM event_metrics")
        rows = {r[0]: r[1] for r in cursor.fetchall()}

        self.assertEqual(rows.get(1), 500)  # FW-1 com dados
        self.assertEqual(rows.get(2), 0)    # IDS-1 zero-filled

    def test_cycle_with_no_data(self):
        """Se AQL retorna None, nenhum dado salvo mas zero-fill ainda deve ocorrer."""
        self.client.get_event_metrics_window.return_value = None

        window_start = _epoch_ms(2026, 1, 15, 11, 0, 0)
        window_end = _epoch_ms(2026, 1, 15, 12, 0, 0)

        ds_count = collector.run_collection_cycle(
            client=self.client,
            db=self.db,
            interval_hours=1.0,
            window_start_ms=window_start,
            window_end_ms=window_end,
        )

        self.assertEqual(ds_count, 0)

        # Ambos devem ser zero-filled
        cursor = self.db.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM event_metrics")
        count = cursor.fetchone()[0]
        self.assertEqual(count, 2)  # FW-1 e IDS-1 zero-filled


# ─────────────────────────────────────────────────────────────────────────────
# 10. Retry with backoff
# ─────────────────────────────────────────────────────────────────────────────
class TestRetryWithBackoff(unittest.TestCase):
    """Testa a lógica de retry com backoff exponencial."""

    @patch("time.sleep", return_value=None)
    def test_retries_on_500(self, _mock_sleep):
        """Deve fazer retry em HTTP 500 e retornar sucesso na segunda tentativa."""
        import requests
        resp_500 = _make_mock_response(500)
        error_500 = requests.exceptions.HTTPError(response=resp_500)

        call_count = {"n": 0}

        def flaky_func():
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise error_500
            return {"ok": True}

        result = collector._retry_with_backoff(flaky_func)
        self.assertEqual(result, {"ok": True})
        self.assertEqual(call_count["n"], 2)

    def test_no_retry_on_401(self):
        """Não deve fazer retry em HTTP 401 (não-retentável)."""
        import requests
        resp_401 = _make_mock_response(401)
        error_401 = requests.exceptions.HTTPError(response=resp_401)

        def always_401():
            raise error_401

        with self.assertRaises(requests.exceptions.HTTPError):
            collector._retry_with_backoff(always_401)


# ─────────────────────────────────────────────────────────────────────────────
# 11. Constants sanity check
# ─────────────────────────────────────────────────────────────────────────────
class TestConstants(unittest.TestCase):
    """Verifica valores das constantes de configuração."""

    def test_default_collection_days(self):
        self.assertEqual(collector.DEFAULT_COLLECTION_DAYS, 6)

    def test_max_catchup_windows(self):
        self.assertEqual(collector.MAX_CATCHUP_WINDOWS, 3)

    def test_aql_timeout(self):
        self.assertEqual(collector.AQL_TIMEOUT_SECONDS, 300)

    def test_retryable_statuses_include_429(self):
        self.assertIn(429, collector.RETRYABLE_HTTP_STATUSES)

    def test_retryable_statuses_exclude_401(self):
        self.assertNotIn(401, collector.RETRYABLE_HTTP_STATUSES)


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    unittest.main()
