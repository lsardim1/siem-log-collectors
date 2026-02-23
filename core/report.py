#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ReportGenerator — CSV and text reports for SIEM log ingestion metrics.

Parametrizado por SIEM para gerar relatórios com nomes e colunas
apropriados (QRadar, Splunk, etc.).
"""

import csv
import datetime
import logging
from pathlib import Path
from typing import List

from core.db import MetricsDB

logger = logging.getLogger("siem_collector")


class ReportGenerator:
    """Gera relatórios em CSV e texto a partir dos dados coletados."""

    def __init__(
        self,
        db: MetricsDB,
        report_dir: str,
        siem_name: str = "siem",
        siem_display_name: str = "SIEM",
        source_label: str = "Log Source",
        type_label: str = "Tipo",
        include_unparsed: bool = False,
        include_aggregated: bool = False,
    ):
        self.db = db
        self.report_dir = Path(report_dir)
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.siem_name = siem_name
        self.siem_display_name = siem_display_name
        self.source_label = source_label
        self.type_label = type_label
        self.include_unparsed = include_unparsed
        self.include_aggregated = include_aggregated

    def _format_bytes(self, bytes_val: float) -> str:
        """Formata bytes em unidade legível."""
        if bytes_val is None or bytes_val == 0:
            return "0 B"
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if abs(bytes_val) < 1024.0:
                return f"{bytes_val:.2f} {unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.2f} PB"

    def generate_all_reports(self):
        """Gera todos os relatórios (CSV diário, CSV resumo, TXT completo)."""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        logger.info("=" * 70)
        logger.info("GERANDO RELATÓRIOS FINAIS")
        logger.info("=" * 70)

        self._generate_daily_csv(timestamp)
        self._generate_summary_csv(timestamp)
        self._generate_text_report(timestamp)

        logger.info(f"Relatórios salvos em: {self.report_dir.absolute()}")

    def _generate_daily_csv(self, timestamp: str):
        """Gera CSV com detalhamento diário."""
        filepath = self.report_dir / f"{self.siem_name}_daily_report_{timestamp}.csv"
        daily_data = self.db.get_daily_summary()

        with open(filepath, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f, delimiter=";")

            # Header
            headers = ["Data", "Source ID", self.source_label, self.type_label, "Total Eventos"]
            if self.include_aggregated:
                headers.append("Eventos Agregados (COUNT(*))")
                headers.append("Coalescing Ratio")
            if self.include_unparsed:
                headers.extend(["Eventos Unparsed (SUM)", "Unparsed % (sobre total)"])
            headers.extend([
                "Cobertura (segundos)", "Cobertura % (do dia)",
                "Total Payload (Bytes)", "Total Payload (MB)", "Total Payload (GB)",
                "Tamanho Médio Evento (Bytes)", "Qtd Coletas no Dia",
            ])
            writer.writerow(headers)

            for row in daily_data:
                total_bytes = row.get("total_bytes", 0) or 0
                values = [
                    row["collection_date"],
                    row.get("logsource_id", ""),
                    row["logsource_name"],
                    row["logsource_type"],
                    int(row.get("total_events", 0) or 0),
                ]
                if self.include_aggregated:
                    agg = int(row.get("aggregated_events", 0) or 0)
                    values.append(agg)
                    # Coalescing ratio: quantos eventos reais cada registro Ariel representa
                    total_ev = int(row.get("total_events", 0) or 0)
                    ratio = f"{total_ev / agg:.2f}" if agg > 0 else "N/A"
                    values.append(ratio)
                if self.include_unparsed:
                    values.append(int(row.get("unparsed_total_events", 0) or 0))
                    values.append("{:.2f}".format(
                        (float(row.get('unparsed_total_events', 0) or 0) /
                         float(row.get('total_events', 1) or 1)) * 100.0
                    ))
                values.extend([
                    float(row.get("covered_seconds", 0) or 0),
                    "{:.2f}".format((float(row.get('covered_seconds', 0) or 0) / 86400.0) * 100.0),
                    f"{total_bytes:.0f}",
                    f"{total_bytes / (1024 * 1024):.4f}",
                    f"{total_bytes / (1024 * 1024 * 1024):.6f}",
                    f"{row.get('avg_event_size_bytes', 0):.2f}",
                    row["collection_count"],
                ])
                writer.writerow(values)

        logger.info(f"Relatório diário CSV: {filepath}")

    def _generate_summary_csv(self, timestamp: str):
        """Gera CSV com resumo de médias por data source."""
        filepath = self.report_dir / f"{self.siem_name}_summary_report_{timestamp}.csv"
        summary = self.db.get_overall_daily_average()

        with open(filepath, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f, delimiter=";")

            headers = ["Source ID", self.source_label, self.type_label, "Dias Coletados",
                       "Média Diária de Eventos (projetado 24h)"]
            if self.include_aggregated:
                headers.append("Média Diária Eventos Agregados (projetado 24h)")
                headers.append("Coalescing Ratio Médio")
            if self.include_unparsed:
                headers.append("Média Diária Eventos Unparsed (projetado 24h)")
            headers.extend([
                "Cobertura média % (do dia)",
                "Média Diária Volume (Bytes) (projetado 24h)",
                "Média Diária Volume (MB)", "Média Diária Volume (GB)",
                "Tamanho Médio por Evento (Bytes)",
            ])
            writer.writerow(headers)

            for row in summary:
                values = [
                    row.get("logsource_id", ""),
                    row["logsource_name"],
                    row["logsource_type"],
                    row["days_collected"],
                    f"{row['avg_daily_events']:.0f}",
                ]
                if self.include_aggregated:
                    avg_agg = float(row.get('avg_daily_aggregated_events', 0) or 0)
                    values.append(f"{avg_agg:.0f}")
                    # Coalescing ratio médio
                    avg_ev = float(row.get('avg_daily_events', 0) or 0)
                    ratio = f"{avg_ev / avg_agg:.2f}" if avg_agg > 0 else "N/A"
                    values.append(ratio)
                if self.include_unparsed:
                    values.append(f"{row.get('avg_daily_unparsed_events', 0):.0f}")
                values.extend([
                    f"{row.get('avg_coverage_pct', 0):.2f}",
                    f"{row['avg_daily_bytes_total']:.0f}",
                    f"{row['avg_daily_mb']:.4f}",
                    f"{row['avg_daily_gb']:.6f}",
                    f"{row['avg_event_size_bytes']:.2f}",
                ])
                writer.writerow(values)

        logger.info(f"Relatório resumo CSV: {filepath}")

    def _generate_text_report(self, timestamp: str):
        """Gera relatório em texto formatado."""
        filepath = self.report_dir / f"{self.siem_name}_full_report_{timestamp}.txt"
        dates = self.db.get_collection_dates()
        daily_data = self.db.get_daily_summary()
        summary = self.db.get_overall_daily_average()
        total_runs = self.db.get_total_runs()

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("=" * 100 + "\n")
            f.write(f"  RELATÓRIO DE INGESTÃO DE LOGS - {self.siem_display_name}\n")
            f.write(f"  Gerado em: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 100 + "\n\n")

            f.write("─" * 100 + "\n")
            f.write("  INFORMAÇÕES DA COLETA\n")
            f.write("─" * 100 + "\n")
            f.write(f"  Período de coleta: {dates[0] if dates else 'N/A'} a {dates[-1] if dates else 'N/A'}\n")
            f.write(f"  Total de dias coletados: {len(dates)}\n")
            f.write(f"  Total de execuções de coleta: {total_runs}\n")
            f.write(f"  Total de data sources identificados: {len(summary)}\n\n")

            # ── Detalhamento diário ──────────────────────────────────────
            f.write("=" * 100 + "\n")
            f.write("  DETALHAMENTO DIÁRIO POR DATA SOURCE\n")
            f.write("=" * 100 + "\n\n")

            for date in dates:
                date_data = [d for d in daily_data if d["collection_date"] == date]
                total_events_day = sum(d.get("total_events", 0) for d in date_data)
                total_bytes_day = sum(d.get("total_bytes", 0) or 0 for d in date_data)

                f.write(f"┌{'─' * 98}┐\n")
                f.write(f"│  DATA: {date:<89}│\n")
                f.write(f"│  Total de Eventos: {total_events_day:>15,}  │  "
                        f"Volume Total: {self._format_bytes(total_bytes_day):>15}  │\n")
                f.write(f"├{'─' * 98}┤\n")
                f.write(f"│ {self.source_label:<35} │ {self.type_label:<20} │ {'Eventos':>12} │ "
                        f"{'Volume Total':>15} │ {'Avg/Evento':>12} │\n")
                f.write(f"├{'─' * 98}┤\n")

                for d in date_data:
                    name = (d["logsource_name"] or "Unknown")[:35]
                    ltype = (d["logsource_type"] or "Unknown")[:20]
                    events = d.get("total_events", 0)
                    total_b = d.get("total_bytes", 0) or 0
                    avg_b = d.get("avg_event_size_bytes", 0) or 0
                    f.write(f"│ {name:<35} │ {ltype:<20} │ {events:>12,} │ "
                            f"{self._format_bytes(total_b):>15} │ {self._format_bytes(avg_b):>12} │\n")

                f.write(f"└{'─' * 98}┘\n\n")

            # ── Resumo Geral ─────────────────────────────────────────────
            f.write("=" * 100 + "\n")
            f.write("  RESUMO - MÉDIA DIÁRIA DE INGESTÃO POR DATA SOURCE\n")
            f.write("=" * 100 + "\n\n")

            f.write(f"┌{'─' * 98}┐\n")
            f.write(f"│ {self.source_label:<30} │ {self.type_label:<18} │ {'Dias':>4} │ "
                    f"{'Avg Eventos/Dia':>15} │ {'Avg Volume/Dia':>15} │ {'Avg/Evento':>10} │\n")
            f.write(f"├{'─' * 98}┤\n")

            grand_total_avg_events = 0
            grand_total_avg_bytes = 0

            for s in summary:
                name = (s["logsource_name"] or "Unknown")[:30]
                ltype = (s["logsource_type"] or "Unknown")[:18]
                days = s.get("days_collected", 0)
                avg_ev = s.get("avg_daily_events", 0)
                avg_bytes = s.get("avg_daily_bytes_total", 0) or 0
                avg_evt_size = s.get("avg_event_size_bytes", 0) or 0
                grand_total_avg_events += avg_ev
                grand_total_avg_bytes += avg_bytes

                f.write(f"│ {name:<30} │ {ltype:<18} │ {days:>4} │ "
                        f"{avg_ev:>15,.0f} │ {self._format_bytes(avg_bytes):>15} │ "
                        f"{self._format_bytes(avg_evt_size):>10} │\n")

            f.write(f"├{'─' * 98}┤\n")
            f.write(f"│ {'TOTAL (soma das médias)':<30} │ {'':18} │ {'':>4} │ "
                    f"{grand_total_avg_events:>15,.0f} │ "
                    f"{self._format_bytes(grand_total_avg_bytes):>15} │ {'':>10} │\n")
            f.write(f"└{'─' * 98}┘\n\n")

            # ── Estimativa mensal ────────────────────────────────────────
            f.write("─" * 100 + "\n")
            f.write("  ESTIMATIVA DE VOLUME MENSAL (baseada nas médias diárias)\n")
            f.write("─" * 100 + "\n\n")

            for s in summary:
                name = s["logsource_name"] or "Unknown"
                avg_daily_bytes = s.get("avg_daily_bytes_total", 0) or 0
                monthly_bytes = avg_daily_bytes * 30
                f.write(f"  {name:<40}  "
                        f"Diário: {self._format_bytes(avg_daily_bytes):>12}  │  "
                        f"Mensal (30d): {self._format_bytes(monthly_bytes):>12}\n")

            total_monthly = grand_total_avg_bytes * 30
            f.write(f"\n  {'TOTAL ESTIMADO':<40}  "
                    f"Diário: {self._format_bytes(grand_total_avg_bytes):>12}  │  "
                    f"Mensal (30d): {self._format_bytes(total_monthly):>12}\n")

            f.write("\n" + "─" * 100 + "\n")
            f.write("  NOTAS\n")
            f.write("─" * 100 + "\n")
            if self.siem_name == "qradar":
                f.write("  • Volumes de bytes referem-se ao payload armazenado no Ariel (pode diferir do\n")
                f.write("    log bruto on-wire devido a coalescing, truncamento e configurações de storage).\n")
            elif self.siem_name == "splunk":
                f.write("  • Volumes de bytes são calculados via sum(len(_raw)) — tamanho bruto do evento\n")
                f.write("    no index (não comprimido). Para bytes licenciados, use get_license_usage().\n")
            elif self.siem_name == "secops":
                f.write("  • Volumes de bytes NÃO estão disponíveis via UDM Search do Google SecOps.\n")
                f.write("    Todas as colunas de bytes estão zeradas. Use o console do SecOps para volumes.\n")
            else:
                f.write("  • Volumes de bytes referem-se ao payload armazenado no SIEM (pode diferir do\n")
                f.write("    log bruto on-wire devido a coalescing, truncamento e configurações de storage).\n")
            if self.include_aggregated:
                f.write("  • Coalescing Ratio (Total Eventos / COUNT(*)) indica quantos eventos reais\n")
                f.write("    cada registro armazenado representa. Valores > 1 indicam coalescing ativo.\n")
            f.write("  • Projeções 24h são normalizadas pelo tempo efetivamente coberto (zero-fill).\n")
            f.write("  • Zero-fill aplica-se apenas a fontes habilitadas (enabled=1) no inventário.\n")

            f.write("\n" + "=" * 100 + "\n")
            f.write("  FIM DO RELATÓRIO\n")
            f.write("=" * 100 + "\n")

        logger.info(f"Relatório completo em texto: {filepath}")
