#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Collection engine — shared collection cycle and main loop.

Fornece run_collection_cycle() e main_collection_loop() que são
usados por todos os coletores SIEM.
"""

import datetime
import json
import logging
import math
import os
import time
from typing import Any, Callable, Dict, List, Optional

import requests

from core.db import MetricsDB
from core.report import ReportGenerator
from core.utils import (
    DEFAULT_COLLECTION_DAYS,
    DEFAULT_INTERVAL_HOURS,
    MAX_CATCHUP_WINDOWS,
    ErrorCounter,
    is_stopped,
)

logger = logging.getLogger("siem_collector")


def run_collection_cycle(
    client: Any,
    db: MetricsDB,
    interval_hours: float,
    window_start_ms: int,
    window_end_ms: int,
    error_counter: Optional[ErrorCounter] = None,
    siem_name: str = "siem",
    post_collect_callback: Optional[Callable] = None,
) -> int:
    """Executa um ciclo de coleta de métricas para uma janela exata.

    Args:
        client: SIEM client com método get_event_metrics_window(start_ms, end_ms).
        db: MetricsDB para persistência.
        interval_hours: Intervalo entre coletas em horas.
        window_start_ms: Início da janela (epoch ms).
        window_end_ms: Fim da janela (epoch ms).
        error_counter: Contador de erros (opcional).
        siem_name: Nome do SIEM (para chaves de erro).
        post_collect_callback: Callback(db, metrics) chamado após coletar dados.

    Returns:
        Número de data sources com dados na janela.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    collection_time = now.isoformat()
    window_end_dt = datetime.datetime.fromtimestamp(
        (max(window_end_ms - 1, window_start_ms) / 1000.0), tz=datetime.timezone.utc
    )
    collection_date = window_end_dt.strftime("%Y-%m-%d")
    window_seconds = max(0.0, (window_end_ms - window_start_ms) / 1000.0)

    logger.info(
        f"Iniciando ciclo de coleta: {collection_time} | "
        f"janela: {window_seconds:.1f}s ({window_start_ms} -> {window_end_ms})"
    )

    run_id = db.save_collection_run(collection_time, collection_date, float(interval_hours))

    try:
        metrics = client.get_event_metrics_window(window_start_ms, window_end_ms)
    except Exception as exc:
        if error_counter:
            error_counter.inc(f"{siem_name}_query_failed")
        logger.error(f"Falha ao coletar métricas: {exc}")
        return 0

    seen_ids: set = set()
    ds_count = 0

    if metrics:
        db.save_event_metrics(
            run_id, collection_time, collection_date,
            int(window_start_ms), int(window_end_ms), float(window_seconds),
            metrics, float(interval_hours),
        )
        seen_ids = {int(m.get("logsourceid", 0)) for m in metrics}
        ds_count = len(metrics)
        logger.info(f"Coleta #{run_id} concluída: {ds_count} data sources com dados.")

        # Callback pós-coleta (ex: Splunk atualiza inventário a partir dos resultados SPL)
        if post_collect_callback:
            post_collect_callback(db, metrics)
    else:
        logger.warning(f"Coleta #{run_id} sem resultados (janela vazia ou fontes silenciosas).")
        if error_counter:
            error_counter.inc(f"{siem_name}_no_results")

    # Zero-fill: garante que log sources inativos contam como "observados com 0"
    zero_filled = db.fill_zero_event_rows(
        run_id, collection_time, collection_date,
        int(window_start_ms), int(window_end_ms), float(window_seconds),
        seen_ids, float(interval_hours),
    )
    if zero_filled > 0:
        logger.debug(f"Zero-fill: {zero_filled} sources sem eventos nesta janela.")

    return ds_count


def main_collection_loop(
    client: Any,
    db: MetricsDB,
    reporter: ReportGenerator,
    collection_days: float,
    interval_hours: float,
    siem_name: str = "siem",
    siem_display_name: str = "SIEM",
    post_collect_callback: Optional[Callable] = None,
    collect_inventory_func: Optional[Callable] = None,
):
    """Loop principal de coleta que roda por N dias.

    Args:
        client: SIEM client.
        db: MetricsDB.
        reporter: ReportGenerator configurado.
        collection_days: Duração total em dias.
        interval_hours: Intervalo entre coletas.
        siem_name: Nome curto do SIEM (para chaves de erro).
        siem_display_name: Nome longo do SIEM (para logs).
        post_collect_callback: Callback(db, metrics) pós-coleta.
        collect_inventory_func: Callable(client, db) -> int para inventário inicial.
    """
    total_hours = collection_days * 24
    total_collections = math.ceil(total_hours / interval_hours)
    interval_seconds = interval_hours * 3600

    logger.info(f"  Total estimado de coletas: {total_collections}")
    logger.info(f"  Término estimado: {datetime.datetime.now() + datetime.timedelta(days=collection_days)}")
    logger.info("  Pressione Ctrl+C para parar (relatório será gerado)")
    logger.info("=" * 70)

    # Inventário inicial
    if collect_inventory_func:
        try:
            inv_count = collect_inventory_func(client, db)
            logger.info(f"Inventário inicial: {inv_count} items")
        except Exception as e:
            logger.warning(f"Não foi possível coletar inventário: {e}")

    # Loop de coleta
    start_monotonic = time.monotonic()
    end_monotonic = start_monotonic + (total_hours * 3600)
    collection_count = 0
    error_counter = ErrorCounter()

    last_window_end_ms: Optional[int] = None

    while not is_stopped():
        now_monotonic = time.monotonic()
        if now_monotonic >= end_monotonic:
            logger.info("Período de coleta concluído!")
            break

        window_end_ms = int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000)
        if last_window_end_ms is None:
            window_start_ms = window_end_ms - int(interval_seconds * 1000)
        else:
            window_start_ms = last_window_end_ms
            max_window_ms = int(interval_seconds * 1000 * MAX_CATCHUP_WINDOWS)
            if (window_end_ms - window_start_ms) > max_window_ms:
                lost_start = window_start_ms
                window_start_ms = window_end_ms - max_window_ms
                logger.warning(
                    f"Catch-up excedeu limite ({MAX_CATCHUP_WINDOWS}x intervalo). "
                    f"Dados de {lost_start} a {window_start_ms} serão perdidos."
                )

        try:
            ds_count = run_collection_cycle(
                client=client, db=db,
                interval_hours=float(interval_hours),
                window_start_ms=int(window_start_ms),
                window_end_ms=int(window_end_ms),
                error_counter=error_counter,
                siem_name=siem_name,
                post_collect_callback=post_collect_callback,
            )
            collection_count += 1
            last_window_end_ms = window_end_ms

            remaining_seconds = max(0.0, end_monotonic - time.monotonic())
            remaining_hours = remaining_seconds / 3600.0
            remaining_collections = max(0, total_collections - collection_count)

            logger.info(
                f"Progresso: coleta {collection_count}/{total_collections} | "
                f"Data sources: {ds_count} | "
                f"Restante: {remaining_hours:.2f}h ({remaining_collections} coletas) | "
                f"Erros: {error_counter.summary_line()}"
            )

        except requests.exceptions.ConnectionError as e:
            error_counter.inc("connection_error")
            collection_count += 1
            logger.error(f"Erro de conexão com {siem_display_name}: {e}")
            logger.info("Tentando novamente no próximo intervalo (catch-up automático)...")
        except requests.exceptions.HTTPError as e:
            error_counter.inc("http_error")
            collection_count += 1
            logger.error(f"Erro HTTP da API {siem_display_name}: {e}")
            if hasattr(e, "response") and e.response is not None:
                logger.error(f"Status: {e.response.status_code}, Body: {e.response.text[:500]}")
        except Exception as e:
            error_counter.inc("unexpected_error")
            collection_count += 1
            logger.error(f"Erro inesperado durante coleta: {e}", exc_info=True)

        if is_stopped():
            break

        next_run_monotonic = start_monotonic + (collection_count * interval_seconds)
        sleep_seconds = max(0.0, next_run_monotonic - time.monotonic())
        if sleep_seconds > 0:
            logger.info(f"Próxima coleta em ~{sleep_seconds/3600.0:.2f}h. Aguardando...")
            wait_start = time.monotonic()
            while (time.monotonic() - wait_start) < sleep_seconds and not is_stopped():
                time.sleep(min(30.0, sleep_seconds))

    # ── Gerar relatório final ────────────────────────────────────────────
    logger.info("\n")
    logger.info("Coleta finalizada. Gerando relatórios...")

    reporter.generate_all_reports()
    db.close()

    logger.info("\n")
    logger.info("=" * 70)
    if error_counter.as_dict():
        logger.warning("  COLETA FINALIZADA COM ALERTAS/ERROS!")
        logger.warning(f"  Contadores: {error_counter.summary_line()}")
    else:
        logger.info("  COLETA FINALIZADA COM SUCESSO!")
    logger.info(f"  Total de coletas realizadas: {collection_count}")
    logger.info(f"  Relatórios gerados em: {os.path.abspath(str(reporter.report_dir))}")
    logger.info("=" * 70)


def load_config(config_path: str) -> Dict:
    """Carrega configurações de um arquivo JSON."""
    if config_path and os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}
