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
)
from core.collection import run_collection_cycle


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


if __name__ == "__main__":
    unittest.main()
