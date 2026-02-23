#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Testes para os módulos compartilhados (core/).

Cobre: MetricsDB, ErrorCounter, _retry_with_backoff, constantes,
collection_date boundary, catch-up cap, zero-fill, run_collection_cycle.

Execução:
    python -m pytest tests/test_core.py -v
    python -m unittest tests.test_core -v
"""

import datetime
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import requests

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.db import MetricsDB
from core.utils import (
    DEFAULT_COLLECTION_DAYS,
    DEFAULT_INTERVAL_HOURS,
    ErrorCounter,
    MAX_CATCHUP_WINDOWS,
    RETRYABLE_HTTP_STATUSES,
    RETRY_BASE_DELAY,
    RETRY_MAX_ATTEMPTS,
    _retry_with_backoff,
    _stable_id,
)
from core.collection import run_collection_cycle
from core.report import ReportGenerator


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
def _epoch_ms(year, month, day, hour=0, minute=0, second=0, ms=0):
    """Cria epoch em milissegundos para um datetime UTC."""
    dt = datetime.datetime(year, month, day, hour, minute, second,
                           tzinfo=datetime.timezone.utc)
    return int(dt.timestamp() * 1000) + ms


# ─────────────────────────────────────────────────────────────────────────────
# 1. collection_date boundary: meia-noite exata
# ─────────────────────────────────────────────────────────────────────────────
class TestCollectionDateBoundary(unittest.TestCase):
    """Verifica que collection_date é derivada de (window_end_ms - 1ms),
    de modo que uma janela terminando exatamente à meia-noite (00:00:00.000)
    é atribuída ao dia anterior."""

    def test_midnight_boundary_assigns_previous_day(self):
        """Janela 23:00→00:00 do dia 2026-01-16 deve ter collection_date = 2026-01-15."""
        window_end_ms = _epoch_ms(2026, 1, 16, 0, 0, 0)
        window_start_ms = _epoch_ms(2026, 1, 15, 23, 0, 0)

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
# 2. ErrorCounter
# ─────────────────────────────────────────────────────────────────────────────
class TestErrorCounter(unittest.TestCase):
    """Testa a classe ErrorCounter."""

    def test_empty_counter(self):
        ec = ErrorCounter()
        self.assertEqual(ec.as_dict(), {})
        self.assertEqual(ec.summary_line(), "sem erros")

    def test_increment_and_dict(self):
        ec = ErrorCounter()
        ec.inc("http_error")
        ec.inc("http_error")
        ec.inc("timeout")
        self.assertEqual(ec.as_dict(), {"http_error": 2, "timeout": 1})

    def test_summary_line(self):
        ec = ErrorCounter()
        ec.inc("b_err")
        ec.inc("a_err", 3)
        # Sorted by key
        self.assertEqual(ec.summary_line(), "a_err=3, b_err=1")


# ─────────────────────────────────────────────────────────────────────────────
# 2b. _stable_id — hash determinístico para logsource_id
# ─────────────────────────────────────────────────────────────────────────────
class TestStableId(unittest.TestCase):
    """Verifica que _stable_id é determinístico e bem distribuído."""

    def test_deterministic_same_input(self):
        """Mesma string deve retornar sempre o mesmo ID."""
        key = "firewall|syslog|main"
        id1 = _stable_id(key)
        id2 = _stable_id(key)
        self.assertEqual(id1, id2)

    def test_deterministic_known_value(self):
        """SHA-256 deve produzir um valor fixo calculável."""
        # hashlib.sha256("test".encode()).hexdigest()[:8] = '9f86d081'
        # int('9f86d081', 16) = 2676412545
        # 2676412545 % (10**9) = 676412545
        self.assertEqual(_stable_id("test"), 676412545)

    def test_range_within_bounds(self):
        """IDs devem estar entre 0 e 999_999_999."""
        for key in ["a", "bb", "ccc", "firewall|PaloAlto|main", "index:_internal"]:
            result = _stable_id(key)
            self.assertGreaterEqual(result, 0)
            self.assertLess(result, 10**9)

    def test_different_inputs_different_ids(self):
        """Inputs diferentes devem gerar IDs diferentes."""
        id1 = _stable_id("source_a|type_a|idx_a")
        id2 = _stable_id("source_b|type_b|idx_b")
        self.assertNotEqual(id1, id2)


# ─────────────────────────────────────────────────────────────────────────────
# 3. Zero-fill: fill_zero_event_rows()
# ─────────────────────────────────────────────────────────────────────────────
class TestZeroFill(unittest.TestCase):
    """Verifica que log sources do inventário sem eventos recebem linhas com zero."""

    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        self.db = MetricsDB(self.db_path)

    def tearDown(self):
        self.db.close()
        os.close(self.db_fd)
        os.unlink(self.db_path)

    def test_zero_fill_inserts_missing_sources(self):
        """Log sources no inventário sem dados devem receber linhas com evento = 0."""
        self.db.save_log_sources_inventory([
            {"logsource_id": 1, "name": "Source-A", "type_name": "TypeA"},
            {"logsource_id": 2, "name": "Source-B", "type_name": "TypeB"},
            {"logsource_id": 3, "name": "Source-C", "type_name": "TypeC"},
        ])

        run_id = self.db.save_collection_run("2026-01-15T12:00:00", "2026-01-15", 1.0)
        seen_ids = {1}  # Apenas Source-A teve dados

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

        self.assertEqual(zero_filled, 2)

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
        """Log sources que apareceram nos dados NÃO devem ser zero-filled."""
        self.db.save_log_sources_inventory([
            {"logsource_id": 1, "name": "Source-A", "type_name": "TypeA"},
        ])

        run_id = self.db.save_collection_run("2026-01-15T12:00:00", "2026-01-15", 1.0)
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
        self.assertEqual(zero_filled, 0)

    def test_zero_fill_skips_disabled_sources(self):
        """Log sources com enabled=0 NÃO devem ser zero-filled.

        Garante que fontes desabilitadas no inventário não inflam
        artificialmente o número de linhas zero-event no banco.
        """
        self.db.save_log_sources_inventory([
            {"logsource_id": 1, "name": "Active-Source", "type_name": "TypeA", "enabled": True},
            {"logsource_id": 2, "name": "Disabled-Source", "type_name": "TypeB", "enabled": False},
            {"logsource_id": 3, "name": "Also-Active", "type_name": "TypeC", "enabled": True},
        ])

        run_id = self.db.save_collection_run("2026-01-15T12:00:00", "2026-01-15", 1.0)
        seen_ids: set = set()  # Nenhuma fonte teve dados

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

        # Apenas fontes enabled (1 e 3) devem ser zero-filled, não a 2
        self.assertEqual(zero_filled, 2, "Apenas fontes enabled devem ser zero-filled")

        cursor = self.db.conn.cursor()
        cursor.execute("SELECT logsource_id FROM event_metrics WHERE run_id = ?", (run_id,))
        filled_ids = {row[0] for row in cursor.fetchall()}
        self.assertIn(1, filled_ids)
        self.assertIn(3, filled_ids)
        self.assertNotIn(2, filled_ids, "Fonte disabled NÃO deve ser zero-filled")


# ─────────────────────────────────────────────────────────────────────────────
# 4. Catch-up cap (MAX_CATCHUP_WINDOWS)
# ─────────────────────────────────────────────────────────────────────────────
class TestCatchUpCap(unittest.TestCase):
    """Verifica a lógica de catch-up com limite de janelas."""

    def test_cap_limits_window_size(self):
        """Se o gap exceder MAX_CATCHUP_WINDOWS × intervalo, a janela é recortada."""
        interval_seconds = 3600
        max_window_ms = int(interval_seconds * 1000 * MAX_CATCHUP_WINDOWS)

        window_end_ms = 10_000_000_000
        last_window_end_ms = window_end_ms - (max_window_ms * 2)

        window_start_ms = last_window_end_ms
        if (window_end_ms - window_start_ms) > max_window_ms:
            window_start_ms = window_end_ms - max_window_ms

        actual_window = window_end_ms - window_start_ms
        self.assertEqual(actual_window, max_window_ms)

    def test_no_cap_when_within_limit(self):
        """Sem cap quando o gap está dentro do limite permitido."""
        interval_seconds = 3600
        max_window_ms = int(interval_seconds * 1000 * MAX_CATCHUP_WINDOWS)

        window_end_ms = 10_000_000_000
        last_window_end_ms = window_end_ms - int(interval_seconds * 1000 * 2)

        window_start_ms = last_window_end_ms
        if (window_end_ms - window_start_ms) > max_window_ms:
            window_start_ms = window_end_ms - max_window_ms

        self.assertEqual(window_start_ms, last_window_end_ms)


# ─────────────────────────────────────────────────────────────────────────────
# 5. Retry with backoff
# ─────────────────────────────────────────────────────────────────────────────
class TestRetryWithBackoff(unittest.TestCase):
    """Testa a lógica de retry com backoff exponencial."""

    @patch("core.utils.time.sleep", return_value=None)
    def test_retries_on_500(self, _mock_sleep):
        """Deve fazer retry em HTTP 500 e retornar sucesso após falhas."""
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

        result = _retry_with_backoff(flaky)
        self.assertEqual(result, "ok")
        self.assertEqual(call_count, 3)

    def test_no_retry_on_401(self):
        """Não deve fazer retry em HTTP 401 (não-retentável)."""
        def unauthorized():
            resp = MagicMock()
            resp.status_code = 401
            raise requests.exceptions.HTTPError(response=resp)

        with self.assertRaises(requests.exceptions.HTTPError):
            _retry_with_backoff(unauthorized)


# ─────────────────────────────────────────────────────────────────────────────
# 6. Constants
# ─────────────────────────────────────────────────────────────────────────────
class TestConstants(unittest.TestCase):
    """Valida valores esperados das constantes compartilhadas."""

    def test_default_collection_days(self):
        self.assertEqual(DEFAULT_COLLECTION_DAYS, 6)

    def test_max_catchup_windows(self):
        self.assertEqual(MAX_CATCHUP_WINDOWS, 3)

    def test_retryable_statuses_include_429_500(self):
        self.assertIn(429, RETRYABLE_HTTP_STATUSES)
        self.assertIn(500, RETRYABLE_HTTP_STATUSES)

    def test_retryable_statuses_exclude_401_403(self):
        self.assertNotIn(401, RETRYABLE_HTTP_STATUSES)
        self.assertNotIn(403, RETRYABLE_HTTP_STATUSES)

    def test_retry_defaults(self):
        self.assertEqual(RETRY_MAX_ATTEMPTS, 3)
        self.assertEqual(RETRY_BASE_DELAY, 2)


# ─────────────────────────────────────────────────────────────────────────────
# 7. run_collection_cycle (integration with real DB)
# ─────────────────────────────────────────────────────────────────────────────
class TestRunCollectionCycle(unittest.TestCase):
    """Testa run_collection_cycle com mock de client e DB real (SQLite temporário)."""

    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        self.db = MetricsDB(self.db_path)
        self.db.save_log_sources_inventory([
            {"logsource_id": 1, "name": "FW-1", "type_name": "Firewall"},
            {"logsource_id": 2, "name": "IDS-1", "type_name": "IDS"},
        ])
        self.client = MagicMock()

    def tearDown(self):
        self.db.close()
        os.close(self.db_fd)
        os.unlink(self.db_path)

    def test_cycle_with_partial_data(self):
        """Se query retorna só FW-1, IDS-1 deve ser zero-filled."""
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

        ds_count = run_collection_cycle(
            client=self.client,
            db=self.db,
            interval_hours=1.0,
            window_start_ms=window_start,
            window_end_ms=window_end,
            siem_name="test",
        )

        self.assertEqual(ds_count, 1)

        cursor = self.db.conn.cursor()
        cursor.execute("SELECT logsource_id, total_event_count FROM event_metrics")
        rows = {r[0]: r[1] for r in cursor.fetchall()}
        self.assertEqual(rows.get(1), 500)
        self.assertEqual(rows.get(2), 0)

    def test_cycle_with_no_data(self):
        """Se query retorna None, nenhum dado salvo mas zero-fill ocorre."""
        self.client.get_event_metrics_window.return_value = None

        window_start = _epoch_ms(2026, 1, 15, 11, 0, 0)
        window_end = _epoch_ms(2026, 1, 15, 12, 0, 0)

        ds_count = run_collection_cycle(
            client=self.client,
            db=self.db,
            interval_hours=1.0,
            window_start_ms=window_start,
            window_end_ms=window_end,
            siem_name="test",
        )

        self.assertEqual(ds_count, 0)

        cursor = self.db.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM event_metrics")
        count = cursor.fetchone()[0]
        self.assertEqual(count, 2)  # FW-1 e IDS-1 zero-filled

    def test_post_collect_callback_called(self):
        """post_collect_callback deve ser chamado após coleta com dados."""
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

        callback = MagicMock()
        window_start = _epoch_ms(2026, 1, 15, 11, 0, 0)
        window_end = _epoch_ms(2026, 1, 15, 12, 0, 0)

        run_collection_cycle(
            client=self.client,
            db=self.db,
            interval_hours=1.0,
            window_start_ms=window_start,
            window_end_ms=window_end,
            siem_name="test",
            post_collect_callback=callback,
        )

        callback.assert_called_once()

    def test_query_failure_returns_negative_one(self):
        """Se get_event_metrics_window lança exceção, retorna -1 (não 0).

        Isso sinaliza ao loop principal que a janela NÃO deve ser avançada,
        permitindo catch-up no próximo ciclo.
        """
        self.client.get_event_metrics_window.side_effect = RuntimeError("AQL timeout")

        error_counter = ErrorCounter()
        window_start = _epoch_ms(2026, 1, 15, 11, 0, 0)
        window_end = _epoch_ms(2026, 1, 15, 12, 0, 0)

        ds_count = run_collection_cycle(
            client=self.client,
            db=self.db,
            interval_hours=1.0,
            window_start_ms=window_start,
            window_end_ms=window_end,
            error_counter=error_counter,
            siem_name="test",
        )

        self.assertEqual(ds_count, -1, "Falha na query deve retornar -1, não 0")
        self.assertIn("test_query_failed", error_counter.as_dict())

    def test_empty_results_returns_zero(self):
        """Se query retorna None (sem dados), retorna 0 (não -1).

        Janela vazia é sucesso — o loop deve avançar last_window_end_ms.
        """
        self.client.get_event_metrics_window.return_value = None

        window_start = _epoch_ms(2026, 1, 15, 11, 0, 0)
        window_end = _epoch_ms(2026, 1, 15, 12, 0, 0)

        ds_count = run_collection_cycle(
            client=self.client,
            db=self.db,
            interval_hours=1.0,
            window_start_ms=window_start,
            window_end_ms=window_end,
            siem_name="test",
        )

        self.assertEqual(ds_count, 0, "Resultado vazio deve retornar 0 (sucesso)")

    def test_failed_run_status_marked(self):
        """Quando query falha, collection_run.status deve ser atualizado para 'failed'.

        Garante que corridas com falha no SIEM sejam distinguíveis de
        coletas bem-sucedidas no banco de dados.
        """
        self.client.get_event_metrics_window.side_effect = RuntimeError("Connection refused")

        window_start = _epoch_ms(2026, 1, 15, 11, 0, 0)
        window_end = _epoch_ms(2026, 1, 15, 12, 0, 0)

        ds_count = run_collection_cycle(
            client=self.client,
            db=self.db,
            interval_hours=1.0,
            window_start_ms=window_start,
            window_end_ms=window_end,
            siem_name="test",
        )

        self.assertEqual(ds_count, -1)

        # Verificar status no banco
        cursor = self.db.conn.cursor()
        cursor.execute("SELECT status FROM collection_runs ORDER BY run_id DESC LIMIT 1")
        status = cursor.fetchone()[0]
        self.assertEqual(status, "failed", "Status da run deve ser 'failed' após erro na query")

    def test_successful_run_keeps_success_status(self):
        """Coleta bem-sucedida deve manter status = 'success' (default)."""
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

        ds_count = run_collection_cycle(
            client=self.client,
            db=self.db,
            interval_hours=1.0,
            window_start_ms=window_start,
            window_end_ms=window_end,
            siem_name="test",
        )

        self.assertEqual(ds_count, 1)

        cursor = self.db.conn.cursor()
        cursor.execute("SELECT status FROM collection_runs ORDER BY run_id DESC LIMIT 1")
        status = cursor.fetchone()[0]
        self.assertEqual(status, "success", "Status da run bem-sucedida deve ser 'success'")


# ─────────────────────────────────────────────────────────────────────────────
# 8. MetricsDB schema
# ─────────────────────────────────────────────────────────────────────────────
class TestMetricsDB(unittest.TestCase):
    """Testa funcionalidades do MetricsDB."""

    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        self.db = MetricsDB(self.db_path)

    def tearDown(self):
        self.db.close()
        os.close(self.db_fd)
        os.unlink(self.db_path)

    def test_save_and_get_collection_dates(self):
        self.db.save_collection_run("2026-01-15T10:00:00", "2026-01-15", 1.0)
        self.db.save_collection_run("2026-01-16T10:00:00", "2026-01-16", 1.0)
        dates = self.db.get_collection_dates()
        self.assertEqual(dates, ["2026-01-15", "2026-01-16"])

    def test_total_runs(self):
        self.db.save_collection_run("2026-01-15T10:00:00", "2026-01-15", 1.0)
        self.db.save_collection_run("2026-01-15T11:00:00", "2026-01-15", 1.0)
        self.assertEqual(self.db.get_total_runs(), 2)

    def test_save_inventory_unified_format(self):
        self.db.save_log_sources_inventory([
            {"logsource_id": 1, "name": "Source-A", "type_name": "TypeA", "type_id": 10},
            {"logsource_id": 2, "name": "Source-B", "type_name": "TypeB"},
        ])
        cursor = self.db.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM log_sources_inventory")
        self.assertEqual(cursor.fetchone()[0], 2)

    def test_group_by_logsource_id_not_name(self):
        """Fontes com mesmo nome mas IDs diferentes devem ficar separadas no resumo."""
        # Duas fontes com MESMO nome mas IDs distintos
        self.db.save_log_sources_inventory([
            {"logsource_id": 100, "name": "Firewall", "type_name": "PaloAlto"},
            {"logsource_id": 200, "name": "Firewall", "type_name": "FortiGate"},
        ])
        run_id = self.db.save_collection_run("2026-01-15T10:00:00", "2026-01-15", 1.0)
        w_start = _epoch_ms(2026, 1, 15, 9, 0, 0)
        w_end = _epoch_ms(2026, 1, 15, 10, 0, 0)
        # Salvar métricas com mesmo nome mas IDs diferentes
        self.db.save_event_metrics(
            run_id, "2026-01-15T10:00:00", "2026-01-15",
            w_start, w_end, 3600.0,
            [
                {"logsourceid": 100, "log_source_name": "Firewall",
                 "log_source_type": "PaloAlto", "total_event_count": 500,
                 "aggregated_event_count": 500, "total_payload_bytes": 1000, "avg_payload_bytes": 2},
                {"logsourceid": 200, "log_source_name": "Firewall",
                 "log_source_type": "FortiGate", "total_event_count": 300,
                 "aggregated_event_count": 300, "total_payload_bytes": 600, "avg_payload_bytes": 2},
            ],
            1.0,
        )
        daily = self.db.get_daily_summary()
        # Devem ser 2 linhas separadas, não 1 linha mesclada
        self.assertEqual(len(daily), 2, "Fontes com mesmo nome mas IDs diferentes devem ficar separadas")
        events = sorted([d["total_events"] for d in daily])
        self.assertEqual(events, [300, 500])

    def test_renamed_source_stays_grouped_by_id(self):
        """Se uma fonte for renomeada entre coletas, dados permanecem agrupados por ID."""
        self.db.save_log_sources_inventory([
            {"logsource_id": 42, "name": "OldName", "type_name": "Syslog"},
        ])
        w1_start = _epoch_ms(2026, 1, 15, 9, 0, 0)
        w1_end = _epoch_ms(2026, 1, 15, 10, 0, 0)
        w2_start = _epoch_ms(2026, 1, 15, 10, 0, 0)
        w2_end = _epoch_ms(2026, 1, 15, 11, 0, 0)

        run1 = self.db.save_collection_run("2026-01-15T10:00:00", "2026-01-15", 1.0)
        self.db.save_event_metrics(
            run1, "2026-01-15T10:00:00", "2026-01-15",
            w1_start, w1_end, 3600.0,
            [{"logsourceid": 42, "log_source_name": "OldName",
              "log_source_type": "Syslog", "total_event_count": 100,
              "aggregated_event_count": 100, "total_payload_bytes": 200, "avg_payload_bytes": 2}],
            1.0,
        )
        run2 = self.db.save_collection_run("2026-01-15T11:00:00", "2026-01-15", 1.0)
        self.db.save_event_metrics(
            run2, "2026-01-15T11:00:00", "2026-01-15",
            w2_start, w2_end, 3600.0,
            [{"logsourceid": 42, "log_source_name": "NewName",
              "log_source_type": "Syslog", "total_event_count": 150,
              "aggregated_event_count": 150, "total_payload_bytes": 300, "avg_payload_bytes": 2}],
            1.0,
        )
        daily = self.db.get_daily_summary()
        # Deve ser 1 única linha (mesmo ID), não 2 (nomes diferentes)
        self.assertEqual(len(daily), 1, "Fonte renomeada deve permanecer agrupada por ID")
        self.assertEqual(daily[0]["total_events"], 250)

    def test_update_collection_run_status(self):
        """Verifica que update_collection_run_status() atualiza o status corretamente."""
        run_id = self.db.save_collection_run("2026-01-15T10:00:00", "2026-01-15", 1.0)

        # Status padrão é 'success'
        cursor = self.db.conn.cursor()
        cursor.execute("SELECT status FROM collection_runs WHERE run_id = ?", (run_id,))
        self.assertEqual(cursor.fetchone()[0], "success")

        # Atualizar para 'failed'
        self.db.update_collection_run_status(run_id, "failed")
        cursor.execute("SELECT status FROM collection_runs WHERE run_id = ?", (run_id,))
        self.assertEqual(cursor.fetchone()[0], "failed")

        # Pode atualizar de volta para 'success'
        self.db.update_collection_run_status(run_id, "success")
        cursor.execute("SELECT status FROM collection_runs WHERE run_id = ?", (run_id,))
        self.assertEqual(cursor.fetchone()[0], "success")


# ─────────────────────────────────────────────────────────────────────────────
# 8. ReportGenerator — NOTAS section per SIEM
# ─────────────────────────────────────────────────────────────────────────────
class TestReportNotasPerSiem(unittest.TestCase):
    """Verifica que a seção NOTAS usa texto correto por SIEM."""

    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        self.db = MetricsDB(self.db_path)
        self.report_dir = tempfile.mkdtemp()

        # Inserir dados mínimos para gerar relatório
        self.db.save_log_sources_inventory([{
            "logsource_id": 1, "name": "test", "type_name": "syslog",
            "enabled": 1, "description": "", "group_ids": "",
        }])
        run_id = self.db.save_collection_run(
            "2025-01-15T10:00:00", "2025-01-15", 1.0
        )
        now_ms = int(datetime.datetime(2025, 1, 15, 10, 0, 0,
                                        tzinfo=datetime.timezone.utc).timestamp() * 1000)
        self.db.save_event_metrics(
            run_id, "2025-01-15T10:00:00", "2025-01-15",
            now_ms - 3600000, now_ms, 3600.0,
            [{"logsourceid": 1, "log_source_name": "test",
              "log_source_type": "syslog", "total_event_count": 10,
              "aggregated_event_count": 10,
              "total_payload_bytes": 100, "avg_payload_bytes": 10}],
            1.0,
        )

    def tearDown(self):
        self.db.close()
        os.close(self.db_fd)
        os.unlink(self.db_path)
        import shutil
        shutil.rmtree(self.report_dir, ignore_errors=True)

    def _get_report_text(self, siem_name: str) -> str:
        rpt = ReportGenerator(self.db, self.report_dir, siem_name=siem_name)
        rpt.generate_all_reports()
        # Encontra o arquivo .txt gerado
        import glob
        txt_files = glob.glob(os.path.join(self.report_dir, "*.txt"))
        self.assertTrue(len(txt_files) > 0, "Relatório TXT deveria ser gerado")
        with open(txt_files[0], "r", encoding="utf-8") as f:
            return f.read()

    def test_qradar_notas(self):
        txt = self._get_report_text("qradar")
        self.assertIn("Ariel", txt)
        self.assertNotIn("sum(len(_raw))", txt)

    def test_splunk_notas(self):
        txt = self._get_report_text("splunk")
        self.assertIn("sum(len(_raw))", txt)
        self.assertNotIn("Ariel", txt)

    def test_secops_notas(self):
        txt = self._get_report_text("secops")
        self.assertIn("UDM Search", txt)
        self.assertIn("zeradas", txt)

    def test_generic_notas(self):
        txt = self._get_report_text("generic_siem")
        self.assertIn("SIEM", txt)
        self.assertNotIn("Ariel", txt)
        self.assertNotIn("sum(len(_raw))", txt)

    def test_zero_fill_enabled_note(self):
        """Todas as variantes devem conter nota sobre enabled=1."""
        for siem in ["qradar", "splunk", "secops", "xyz"]:
            txt = self._get_report_text(siem)
            self.assertIn("enabled=1", txt, f"SIEM '{siem}' deveria mencionar enabled=1")


if __name__ == "__main__":
    unittest.main()
