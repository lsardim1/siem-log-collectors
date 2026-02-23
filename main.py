#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SIEM Log Collectors — Unified Entry Point.

Uso:
    python main.py qradar --url https://qradar:443 --token SEC_TOKEN
    python main.py splunk --url https://splunk:8089 --token BEARER_TOKEN
    python main.py splunk --url https://splunk:8089 --username admin --password PASS
    python main.py qradar --report-only --db-file mydb.db
    python main.py splunk --create-config
"""

import argparse
import logging
import os
import sys

from core.collection import load_config, main_collection_loop
from core.db import MetricsDB
from core.report import ReportGenerator
from core.utils import (
    DEFAULT_COLLECTION_DAYS,
    DEFAULT_INTERVAL_HOURS,
    DEFAULT_REPORT_DIR,
    install_signal_handlers,
)

logger = logging.getLogger("siem_collector")


# ─── Logging setup ───────────────────────────────────────────────────────────
def setup_logging(siem_name: str, verbose: bool = False):
    """Configura logging com saída para console e arquivo."""
    level = logging.DEBUG if verbose else logging.INFO
    root_logger = logging.getLogger("siem_collector")
    root_logger.setLevel(level)

    if root_logger.handlers:
        return  # Já configurado

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    root_logger.addHandler(sh)

    fh = logging.FileHandler(f"{siem_name}_collector.log", encoding="utf-8")
    fh.setFormatter(fmt)
    root_logger.addHandler(fh)


# ─── QRadar ──────────────────────────────────────────────────────────────────
def run_qradar(args):
    """Executa coletor QRadar."""
    from collectors.qradar.client import QRadarClient, collect_inventory, create_sample_config

    setup_logging("qradar", args.verbose)

    if args.create_config:
        create_sample_config(args.config or "qradar_config.json")
        return

    # Carregar configuração
    config = load_config(args.config or "")
    url = args.url or config.get("qradar_url", "")
    token = args.token or config.get("api_token", "")
    verify_ssl = config.get("verify_ssl", False)
    api_version = config.get("api_version", "26.0")
    collection_days = args.days or config.get("collection_days", DEFAULT_COLLECTION_DAYS)
    interval_hours = args.interval or config.get("interval_hours", DEFAULT_INTERVAL_HOURS)
    db_file = args.db_file or config.get("db_file", "qradar_metrics.db")
    report_dir = args.report_dir or config.get("report_dir", DEFAULT_REPORT_DIR)

    db = MetricsDB(db_file)

    if args.report_only:
        reporter = ReportGenerator(
            db, report_dir,
            siem_name="qradar",
            siem_display_name="IBM QRadar",
            source_label="Log Source",
            type_label="Tipo Log Source",
            include_unparsed=True,
            include_aggregated=True,
        )
        reporter.generate_all_reports()
        db.close()
        return

    if not url or not token:
        logger.error("URL e token são obrigatórios. Use --url e --token ou arquivo de config.")
        sys.exit(1)

    client = QRadarClient(url, token, verify_ssl=verify_ssl, api_version=api_version)
    client.test_connection()

    reporter = ReportGenerator(
        db, report_dir,
        siem_name="qradar",
        siem_display_name="IBM QRadar",
        source_label="Log Source",
        type_label="Tipo Log Source",
        include_unparsed=True,
        include_aggregated=True,
    )

    logger.info("=" * 70)
    logger.info("  IBM QRadar Log Ingestion Collector")
    logger.info("=" * 70)
    logger.info(f"  URL:                {url}")
    logger.info(f"  Período de coleta:  {collection_days} dias")
    logger.info(f"  Intervalo:          {interval_hours}h")
    logger.info(f"  Banco de dados:     {db_file}")
    logger.info(f"  Relatórios:         {report_dir}")

    install_signal_handlers()

    main_collection_loop(
        client=client,
        db=db,
        reporter=reporter,
        collection_days=float(collection_days),
        interval_hours=float(interval_hours),
        siem_name="qradar",
        siem_display_name="IBM QRadar",
        collect_inventory_func=collect_inventory,
    )


# ─── Splunk ──────────────────────────────────────────────────────────────────
def run_splunk(args):
    """Executa coletor Splunk."""
    from collectors.splunk.client import (
        SplunkClient,
        collect_inventory,
        create_sample_config,
        update_inventory_from_results,
    )

    setup_logging("splunk", args.verbose)

    if args.create_config:
        create_sample_config(args.config or "splunk_config.json")
        return

    # Carregar configuração
    config = load_config(args.config or "")
    url = args.url or config.get("splunk_url", "")
    token = args.token or config.get("auth_token", "")
    username = args.username or config.get("username", "")
    password = args.password or config.get("password", "")
    verify_ssl = config.get("verify_ssl", False)
    collection_days = args.days or config.get("collection_days", DEFAULT_COLLECTION_DAYS)
    interval_hours = args.interval or config.get("interval_hours", DEFAULT_INTERVAL_HOURS)
    db_file = args.db_file or config.get("db_file", "splunk_metrics.db")
    report_dir = args.report_dir or config.get("report_dir", DEFAULT_REPORT_DIR)

    db = MetricsDB(db_file)

    if args.report_only:
        reporter = ReportGenerator(
            db, report_dir,
            siem_name="splunk",
            siem_display_name="Splunk",
            source_label="Source [Index]",
            type_label="Sourcetype",
        )
        reporter.generate_all_reports()
        db.close()
        return

    if not url:
        logger.error("URL é obrigatória. Use --url ou arquivo de config.")
        sys.exit(1)

    if not token and not (username and password):
        logger.error("Forneça --token ou --username + --password.")
        sys.exit(1)

    client = SplunkClient(url, token=token, username=username, password=password,
                           verify_ssl=verify_ssl)
    client.test_connection()

    reporter = ReportGenerator(
        db, report_dir,
        siem_name="splunk",
        siem_display_name="Splunk",
        source_label="Source [Index]",
        type_label="Sourcetype",
    )

    logger.info("=" * 70)
    logger.info("  Splunk Log Ingestion Collector")
    logger.info("=" * 70)
    logger.info(f"  URL:                {url}")
    logger.info(f"  Auth:               {'Bearer Token' if token else 'Basic Auth'}")
    logger.info(f"  Período de coleta:  {collection_days} dias")
    logger.info(f"  Intervalo:          {interval_hours}h")
    logger.info(f"  Banco de dados:     {db_file}")
    logger.info(f"  Relatórios:         {report_dir}")

    install_signal_handlers()

    main_collection_loop(
        client=client,
        db=db,
        reporter=reporter,
        collection_days=float(collection_days),
        interval_hours=float(interval_hours),
        siem_name="splunk",
        siem_display_name="Splunk",
        collect_inventory_func=collect_inventory,
        post_collect_callback=update_inventory_from_results,
    )


# ─── CLI ─────────────────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    """Constrói o parser de argumentos."""
    parser = argparse.ArgumentParser(
        description="SIEM Log Collectors — Coleta métricas de ingestão de logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  python main.py qradar --url https://qradar:443 --token SEC_TOKEN
  python main.py splunk --url https://splunk:8089 --token BEARER_TOKEN
  python main.py splunk --url https://splunk:8089 --username admin --password PASS
  python main.py qradar --report-only --db-file qradar_metrics.db
  python main.py splunk --create-config
        """
    )

    subparsers = parser.add_subparsers(dest="siem", help="SIEM a ser coletado")

    # --- QRadar subcommand ---
    qradar_parser = subparsers.add_parser("qradar", help="Coletar do IBM QRadar")
    qradar_parser.add_argument("--url", help="URL base do QRadar (ex: https://qradar:443)")
    qradar_parser.add_argument("--token", help="Token API (SEC header)")
    qradar_parser.add_argument("--config", help="Arquivo de configuração JSON")
    qradar_parser.add_argument("--days", type=float, help=f"Dias de coleta (default: {DEFAULT_COLLECTION_DAYS})")
    qradar_parser.add_argument("--interval", type=float, help=f"Intervalo em horas (default: {DEFAULT_INTERVAL_HOURS})")
    qradar_parser.add_argument("--db-file", help="Arquivo SQLite (default: qradar_metrics.db)")
    qradar_parser.add_argument("--report-dir", help=f"Diretório de relatórios (default: {DEFAULT_REPORT_DIR})")
    qradar_parser.add_argument("--report-only", action="store_true", help="Apenas gerar relatório do DB existente")
    qradar_parser.add_argument("--create-config", action="store_true", help="Criar arquivo de config de exemplo")
    qradar_parser.add_argument("--verbose", action="store_true", help="Logging em modo DEBUG")

    # --- Splunk subcommand ---
    splunk_parser = subparsers.add_parser("splunk", help="Coletar do Splunk")
    splunk_parser.add_argument("--url", help="URL base do Splunk (ex: https://splunk:8089)")
    splunk_parser.add_argument("--token", help="Bearer Token para autenticação")
    splunk_parser.add_argument("--username", help="Usuário do Splunk (para Basic Auth)")
    splunk_parser.add_argument("--password", help="Senha do Splunk (para Basic Auth)")
    splunk_parser.add_argument("--config", help="Arquivo de configuração JSON")
    splunk_parser.add_argument("--days", type=float, help=f"Dias de coleta (default: {DEFAULT_COLLECTION_DAYS})")
    splunk_parser.add_argument("--interval", type=float, help=f"Intervalo em horas (default: {DEFAULT_INTERVAL_HOURS})")
    splunk_parser.add_argument("--db-file", help="Arquivo SQLite (default: splunk_metrics.db)")
    splunk_parser.add_argument("--report-dir", help=f"Diretório de relatórios (default: {DEFAULT_REPORT_DIR})")
    splunk_parser.add_argument("--report-only", action="store_true", help="Apenas gerar relatório do DB existente")
    splunk_parser.add_argument("--create-config", action="store_true", help="Criar arquivo de config de exemplo")
    splunk_parser.add_argument("--verbose", action="store_true", help="Logging em modo DEBUG")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.siem:
        parser.print_help()
        sys.exit(1)

    if args.siem == "qradar":
        run_qradar(args)
    elif args.siem == "splunk":
        run_splunk(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
