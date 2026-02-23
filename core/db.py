#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MetricsDB — SQLite storage for SIEM log ingestion metrics.

Shared between all SIEM collectors (QRadar, Splunk, etc.).
Schema é idêntico para todos os SIEMs, garantindo compatibilidade
cruzada de relatórios e queries.
"""

import datetime
import logging
import sqlite3
from typing import Dict, List

logger = logging.getLogger("siem_collector")


class MetricsDB:
    """Armazena métricas coletadas em SQLite local."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self._create_tables()

    def _create_tables(self):
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS collection_runs (
                run_id INTEGER PRIMARY KEY AUTOINCREMENT,
                collection_time TEXT NOT NULL,
                collection_date TEXT NOT NULL,
                interval_hours REAL NOT NULL,
                status TEXT DEFAULT 'success'
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS event_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                collection_time TEXT NOT NULL,
                collection_date TEXT NOT NULL,
                window_start_ms INTEGER,
                window_end_ms INTEGER,
                window_seconds REAL,
                logsource_id INTEGER,
                logsource_name TEXT,
                logsource_type TEXT,
                event_count INTEGER DEFAULT 0,
                aggregated_event_count INTEGER DEFAULT 0,
                total_event_count INTEGER DEFAULT 0,
                unparsed_aggregated_events INTEGER DEFAULT 0,
                unparsed_total_events INTEGER DEFAULT 0,
                total_payload_bytes REAL DEFAULT 0,
                avg_payload_bytes REAL DEFAULT 0,
                interval_hours REAL DEFAULT 1,
                FOREIGN KEY (run_id) REFERENCES collection_runs(run_id)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS log_sources_inventory (
                logsource_id INTEGER,
                name TEXT,
                type_name TEXT,
                type_id INTEGER,
                enabled INTEGER,
                description TEXT,
                last_updated TEXT,
                PRIMARY KEY (logsource_id)
            )
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_event_metrics_date 
            ON event_metrics(collection_date)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_event_metrics_logsource 
            ON event_metrics(logsource_name)
        """)
        self._ensure_event_metrics_schema(cursor)
        self.conn.commit()

    def _ensure_event_metrics_schema(self, cursor: sqlite3.Cursor) -> None:
        """Garante que colunas novas existam em bases antigas (migração leve via ALTER TABLE)."""
        try:
            cursor.execute("PRAGMA table_info(event_metrics)")
            existing = {row[1] for row in cursor.fetchall()}
        except Exception:
            return

        desired = [
            ("window_start_ms", "INTEGER", None),
            ("window_end_ms", "INTEGER", None),
            ("window_seconds", "REAL", None),
            ("aggregated_event_count", "INTEGER", "0"),
            ("total_event_count", "INTEGER", "0"),
            ("unparsed_aggregated_events", "INTEGER", "0"),
            ("unparsed_total_events", "INTEGER", "0"),
        ]

        for col, col_type, default_val in desired:
            if col in existing:
                continue
            try:
                if default_val is None:
                    cursor.execute(f"ALTER TABLE event_metrics ADD COLUMN {col} {col_type}")
                else:
                    cursor.execute(f"ALTER TABLE event_metrics ADD COLUMN {col} {col_type} DEFAULT {default_val}")
            except Exception as exc:
                logger.debug(f"Não foi possível adicionar coluna {col}: {exc}")

    def save_collection_run(self, collection_time: str, collection_date: str, interval_hours: float) -> int:
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO collection_runs (collection_time, collection_date, interval_hours) VALUES (?, ?, ?)",
            (collection_time, collection_date, interval_hours),
        )
        self.conn.commit()
        row_id = cursor.lastrowid
        assert row_id is not None, "INSERT falhou: lastrowid é None"
        return row_id

    def update_collection_run_status(self, run_id: int, status: str) -> None:
        """Atualiza o status de uma collection_run (ex: 'failed').

        Usado para marcar corridas que falharam na consulta ao SIEM,
        permitindo distinguir coletas bem-sucedidas de falhas no relatório.
        """
        cursor = self.conn.cursor()
        cursor.execute(
            "UPDATE collection_runs SET status = ? WHERE run_id = ?",
            (status, run_id),
        )
        self.conn.commit()

    def save_event_metrics(
        self,
        run_id: int,
        collection_time: str,
        collection_date: str,
        window_start_ms: int,
        window_end_ms: int,
        window_seconds: float,
        metrics: List[Dict],
        interval_hours: float,
    ):
        cursor = self.conn.cursor()
        for m in metrics:
            aggregated = int(m.get("aggregated_event_count", m.get("event_count", 0)) or 0)
            total = m.get("total_event_count", None)
            total = int(total) if total is not None else aggregated

            unparsed_agg = int(m.get("unparsed_aggregated_events", 0) or 0)
            unparsed_total = m.get("unparsed_total_events", None)
            unparsed_total = int(unparsed_total) if unparsed_total is not None else 0

            cursor.execute(
                """INSERT INTO event_metrics 
                   (run_id, collection_time, collection_date,
                    window_start_ms, window_end_ms, window_seconds,
                    logsource_id, logsource_name, logsource_type,
                    event_count, aggregated_event_count, total_event_count,
                    unparsed_aggregated_events, unparsed_total_events,
                    total_payload_bytes, avg_payload_bytes, interval_hours)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    run_id,
                    collection_time,
                    collection_date,
                    int(window_start_ms),
                    int(window_end_ms),
                    float(window_seconds),
                    m.get("logsourceid", 0),
                    m.get("log_source_name", "Unknown"),
                    m.get("log_source_type", "Unknown"),
                    aggregated,
                    aggregated,
                    total,
                    unparsed_agg,
                    unparsed_total,
                    m.get("total_payload_bytes", 0) or 0,
                    m.get("avg_payload_bytes", 0) or 0,
                    float(interval_hours),
                ),
            )
        self.conn.commit()
        logger.info(f"Salvos {len(metrics)} registros de métricas (run_id={run_id})")

    def save_log_sources_inventory(self, sources: List[Dict]):
        """Salva inventário de log sources no formato unificado.

        Cada dict deve conter:
        - logsource_id: int
        - name: str
        - type_name: str
        - type_id: int (opcional, padrão 0)
        - enabled: bool (opcional, padrão True)
        - description: str (opcional, padrão "")
        """
        cursor = self.conn.cursor()
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        for src in sources:
            cursor.execute(
                """INSERT OR REPLACE INTO log_sources_inventory 
                   (logsource_id, name, type_name, type_id, enabled, description, last_updated)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    src.get("logsource_id", 0),
                    src.get("name", "Unknown"),
                    src.get("type_name", "Unknown"),
                    src.get("type_id", 0),
                    1 if src.get("enabled", True) else 0,
                    src.get("description", ""),
                    now,
                ),
            )
        self.conn.commit()
        logger.info(f"Inventário de {len(sources)} sources salvo.")

    def fill_zero_event_rows(
        self,
        run_id: int,
        collection_time: str,
        collection_date: str,
        window_start_ms: int,
        window_end_ms: int,
        window_seconds: float,
        seen_logsource_ids: set,
        interval_hours: float,
    ) -> int:
        """Insere linhas com zero eventos para log sources do inventário ausentes na coleta.

        Sem isso, 'covered_seconds' só conta janelas onde houve eventos,
        inflando projeções 24h para fontes intermitentes. Com o zero-fill,
        toda janela observada conta como cobertura — mesmo que sem dados —
        tornando a projeção diária matematicamente correta.
        """
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT logsource_id, name, type_name FROM log_sources_inventory WHERE enabled = 1"
        )
        inventory = cursor.fetchall()

        zero_count = 0
        for ls_id, ls_name, ls_type in inventory:
            if ls_id in seen_logsource_ids:
                continue
            cursor.execute(
                """INSERT INTO event_metrics
                   (run_id, collection_time, collection_date,
                    window_start_ms, window_end_ms, window_seconds,
                    logsource_id, logsource_name, logsource_type,
                    event_count, aggregated_event_count, total_event_count,
                    unparsed_aggregated_events, unparsed_total_events,
                    total_payload_bytes, avg_payload_bytes, interval_hours)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0, 0, 0, 0, 0, ?)""",
                (run_id, collection_time, collection_date,
                 int(window_start_ms), int(window_end_ms), float(window_seconds),
                 ls_id, ls_name or "Unknown", ls_type or "Unknown",
                 float(interval_hours)),
            )
            zero_count += 1

        if zero_count > 0:
            self.conn.commit()
            logger.debug(f"Inseridas {zero_count} linhas zero-event para cobertura completa.")
        return zero_count

    def get_daily_summary(self) -> List[Dict]:
        """Retorna resumo diário por log source.

        Agrupa por logsource_id (não por nome) para evitar mistura quando
        fontes compartilham o mesmo nome ou são renomeadas durante a coleta.
        """
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT 
                collection_date,
                logsource_id,
                MAX(logsource_name) as logsource_name,
                MAX(logsource_type) as logsource_type,
                SUM(total_event_count) as total_events,
                SUM(aggregated_event_count) as aggregated_events,
                SUM(unparsed_total_events) as unparsed_total_events,
                SUM(unparsed_aggregated_events) as unparsed_aggregated_events,
                SUM(total_payload_bytes) as total_bytes,
                CASE 
                    WHEN SUM(total_event_count) > 0 THEN (SUM(total_payload_bytes) / SUM(total_event_count))
                    ELSE 0
                END as avg_event_size_bytes,
                COUNT(DISTINCT collection_time) as collection_count,
                SUM(window_seconds) as covered_seconds
            FROM event_metrics
            GROUP BY collection_date, logsource_id
            ORDER BY collection_date, total_events DESC
        """)
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]

    def get_overall_daily_average(self) -> List[Dict]:
        """Retorna média diária geral por log source (across all days).

        Projeta para 24h baseado no tempo efetivamente coberto.
        Agrupa por logsource_id (não por nome) para evitar mistura.
        """
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT 
                logsource_id,
                MAX(logsource_name) as logsource_name,
                MAX(logsource_type) as logsource_type,
                COUNT(DISTINCT collection_date) as days_collected,

                ROUND(AVG(projected_daily_events), 2) as avg_daily_events,
                ROUND(AVG(projected_daily_bytes), 2) as avg_daily_bytes_total,
                ROUND(AVG(projected_daily_bytes) / (1024.0 * 1024.0), 4) as avg_daily_mb,
                ROUND(AVG(projected_daily_bytes) / (1024.0 * 1024.0 * 1024.0), 6) as avg_daily_gb,

                ROUND(AVG(projected_daily_aggregated_events), 2) as avg_daily_aggregated_events,
                ROUND(AVG(projected_daily_unparsed_events), 2) as avg_daily_unparsed_events,
                ROUND(AVG(coverage_pct), 2) as avg_coverage_pct,

                ROUND(AVG(avg_event_size_bytes), 2) as avg_event_size_bytes
            FROM (
                SELECT 
                    collection_date,
                    logsource_id,
                    MAX(logsource_name) as logsource_name,
                    MAX(logsource_type) as logsource_type,
                    SUM(total_event_count) as daily_events,
                    SUM(aggregated_event_count) as daily_aggregated_events,
                    SUM(unparsed_total_events) as daily_unparsed_events,
                    SUM(total_payload_bytes) as daily_bytes,
                    CASE 
                        WHEN SUM(total_event_count) > 0 THEN (SUM(total_payload_bytes) / SUM(total_event_count))
                        ELSE 0
                    END as avg_event_size_bytes,
                    CASE WHEN SUM(window_seconds) > 0 THEN (SUM(window_seconds) / 86400.0) * 100.0 ELSE 0 END as coverage_pct,
                    CASE WHEN SUM(window_seconds) > 0 THEN (SUM(total_event_count) * 86400.0 / SUM(window_seconds)) ELSE SUM(total_event_count) END as projected_daily_events,
                    CASE WHEN SUM(window_seconds) > 0 THEN (SUM(aggregated_event_count) * 86400.0 / SUM(window_seconds)) ELSE SUM(aggregated_event_count) END as projected_daily_aggregated_events,
                    CASE WHEN SUM(window_seconds) > 0 THEN (SUM(unparsed_total_events) * 86400.0 / SUM(window_seconds)) ELSE SUM(unparsed_total_events) END as projected_daily_unparsed_events,
                    CASE WHEN SUM(window_seconds) > 0 THEN (SUM(total_payload_bytes) * 86400.0 / SUM(window_seconds)) ELSE SUM(total_payload_bytes) END as projected_daily_bytes
                FROM event_metrics
                GROUP BY collection_date, logsource_id
            ) daily
            GROUP BY logsource_id
            ORDER BY avg_daily_bytes_total DESC
        """)
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]

    def get_collection_dates(self) -> List[str]:
        """Retorna lista de datas de coleta únicas."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT DISTINCT collection_date FROM collection_runs ORDER BY collection_date")
        return [row[0] for row in cursor.fetchall()]

    def get_total_runs(self) -> int:
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM collection_runs")
        return cursor.fetchone()[0]

    def close(self):
        self.conn.close()
