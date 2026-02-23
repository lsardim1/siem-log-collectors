#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Shared utilities for SIEM log collectors.

Contains: ErrorCounter, retry logic, signal handling, shared constants.
"""

import logging
import signal
import sys
import time
from typing import Any, Dict, Optional

try:
    import requests  # type: ignore[import-untyped]
    import urllib3  # type: ignore[import-untyped]
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("ERRO: Módulo 'requests' não encontrado. Instale com: pip install requests")
    sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# Shared constants
# ─────────────────────────────────────────────────────────────────────────────
DEFAULT_COLLECTION_DAYS = 6
DEFAULT_INTERVAL_HOURS = 1
DEFAULT_REPORT_DIR = "reports"
RETRY_MAX_ATTEMPTS = 3
RETRY_BASE_DELAY = 2
RETRYABLE_HTTP_STATUSES = (429, 500, 502, 503, 504)
MAX_CATCHUP_WINDOWS = 3

# Logger compartilhado
logger = logging.getLogger("siem_collector")


# ─────────────────────────────────────────────────────────────────────────────
# Graceful stop (Ctrl+C / SIGTERM)
# ─────────────────────────────────────────────────────────────────────────────
STOP_SIGNAL = False


def _signal_handler(signum, frame):
    """Handler para parada graciosa via Ctrl+C."""
    global STOP_SIGNAL
    logger.warning("Sinal de parada recebido (Ctrl+C). Finalizando após coleta atual...")
    STOP_SIGNAL = True


def install_signal_handlers():
    """Instala handlers para SIGINT e SIGTERM."""
    signal.signal(signal.SIGINT, _signal_handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _signal_handler)


def is_stopped() -> bool:
    """Retorna True se sinal de parada foi recebido."""
    return STOP_SIGNAL


# ─────────────────────────────────────────────────────────────────────────────
# ErrorCounter
# ─────────────────────────────────────────────────────────────────────────────
class ErrorCounter:
    """Contador simples de erros/avisos por categoria."""

    def __init__(self) -> None:
        self._counts: Dict[str, int] = {}

    def inc(self, key: str, amount: int = 1) -> None:
        self._counts[key] = self._counts.get(key, 0) + amount

    def as_dict(self) -> Dict[str, int]:
        return dict(self._counts)

    def summary_line(self) -> str:
        if not self._counts:
            return "sem erros"
        parts = [f"{k}={v}" for k, v in sorted(self._counts.items())]
        return ", ".join(parts)


# ─────────────────────────────────────────────────────────────────────────────
# Retry with exponential backoff
# ─────────────────────────────────────────────────────────────────────────────
def _retry_with_backoff(
    func,
    max_retries: int = RETRY_MAX_ATTEMPTS,
    base_delay: int = RETRY_BASE_DELAY,
):
    """
    Executa func() com retry e backoff exponencial em falhas transitórias.
    Não faz retry em HTTP 401, 403, 404.
    """
    last_exc: Optional[BaseException] = None
    for attempt in range(max_retries + 1):
        try:
            return func()
        except requests.exceptions.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else 0
            if status not in RETRYABLE_HTTP_STATUSES:
                raise
            last_exc = exc
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
            last_exc = exc
        except Exception:
            raise

        if attempt == max_retries:
            assert last_exc is not None
            raise last_exc

        # Respeitar Retry-After se disponível (HTTP 429)
        retry_after = None
        if isinstance(last_exc, requests.exceptions.HTTPError) and getattr(last_exc, "response", None) is not None:
            try:
                ra = last_exc.response.headers.get("Retry-After")
                if ra is not None:
                    retry_after = int(float(ra))
            except Exception:
                retry_after = None

        delay = retry_after if (retry_after is not None and retry_after > 0) else base_delay * (2 ** attempt)
        logger.debug(f"Retry {attempt + 1}/{max_retries} em {delay}s: {last_exc}")
        time.sleep(delay)

    assert last_exc is not None
    raise last_exc
