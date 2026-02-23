#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Abstract base class for SIEM clients.

Todos os clientes SIEM devem implementar esta interface para serem
compatíveis com o motor de coleta compartilhado (core.collection).
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional


class SIEMClient(ABC):
    """Interface que todos os clientes SIEM devem implementar."""

    @abstractmethod
    def test_connection(self) -> Dict:
        """Testa conectividade com o SIEM.

        Returns:
            Dict com informações do SIEM (versão, nome, etc.)

        Raises:
            requests.exceptions.HTTPError: em caso de falha de autenticação.
            requests.exceptions.ConnectionError: se não conseguir conectar.
        """
        ...

    @abstractmethod
    def get_event_metrics_window(
        self, start_time_ms: int, end_time_ms: int
    ) -> Optional[List[Dict]]:
        """Coleta métricas de ingestão para um intervalo exato.

        Args:
            start_time_ms: Início da janela (epoch milliseconds, inclusivo).
            end_time_ms: Fim da janela (epoch milliseconds, exclusivo).

        Returns:
            Lista de dicts com formato unificado:
            - logsourceid: int
            - log_source_name: str
            - log_source_type: str
            - aggregated_event_count: int
            - total_event_count: int
            - total_payload_bytes: float
            - avg_payload_bytes: float
            Ou None em caso de erro.
        """
        ...
