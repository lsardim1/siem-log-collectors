# 🔜 Google SecOps (Chronicle) Log Collector

> **Status:** Em desenvolvimento

## Objetivo

Coletor de ingestão histórica para o **Google SecOps** (antigo Chronicle), seguindo a mesma arquitetura dos coletores de [QRadar](../qradar/) e [Splunk](../splunk/).

## API Alvo

- **Chronicle Backstory API** — Search / UDM Events
- **Chronicle Ingestion API** — Feed metadata e log types
- Autenticação via **Service Account** (OAuth 2.0 / ADC)

## Funcionalidades planejadas

- [ ] Autenticação com Service Account JSON
- [ ] Listagem de log types disponíveis
- [ ] Coleta de volume por log type em janelas de 1h
- [ ] MetricsDB (SQLite) para persistência
- [ ] ReportGenerator (CSV + TXT)
- [ ] Zero-fill para janelas sem dados
- [ ] Catch-up cap (MAX_CATCHUP_WINDOWS=3)
- [ ] Retry com backoff exponencial
- [ ] Parada graciosa (Ctrl+C)
- [ ] Suíte de testes unitários (100% mocked)

## Como contribuir

Se você tem acesso a um ambiente Google SecOps e quer ajudar, veja o [CONTRIBUTING.md](../../CONTRIBUTING.md) na raiz do repositório.

## Referências

- [Chronicle API Documentation](https://cloud.google.com/chronicle/docs/reference)
- [Chronicle Backstory API](https://cloud.google.com/chronicle/docs/reference/search-api)
- [Google Auth Library for Python](https://google-auth.readthedocs.io/)
