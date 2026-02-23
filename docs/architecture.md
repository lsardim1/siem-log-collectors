# 🏗️ Arquitetura dos Coletores

Este documento detalha a arquitetura modular do projeto **siem-log-collectors**.

---

## Visão Geral

O projeto utiliza uma arquitetura modular onde código compartilhado vive em `core/` e cada SIEM tem apenas o código específico da sua API em `collectors/<siem>/client.py`. Um entry point unificado (`main.py`) orquestra a execução.

```
                    main.py
                      │
         ┌────────────┼────────────┬────────────┐
         │                         │                 │
    qradar subcommand         splunk subcommand  secops subcommand
         │                         │                 │
         ▼                         ▼                 ▼
  QRadarClient              SplunkClient     GoogleSecOpsClient
  (AQL + Ariel)             (SPL + Search    (UDM Search +
         │                  Jobs v2)          Backstory API)
         │                         │                 │
         └────────┬────────────────┘─────────────┘
                  │
         ┌────────┼────────┐
         │        │        │
    core/utils  core/db  core/report
    (retry,     (SQLite) (CSV+TXT)
     signals)      │
                   │
              core/collection
              (cycle engine)
```

---

## Componentes

### 1. `core/utils.py` — Utilitários Compartilhados

- **ErrorCounter:** Contador de erros por categoria
- **_retry_with_backoff():** Retry exponencial (2s → 4s → 8s) com suporte a Retry-After
- **Signal handlers:** Parada graciosa via SIGINT/SIGTERM
- **Constantes:** `DEFAULT_COLLECTION_DAYS=6`, `MAX_CATCHUP_WINDOWS=3`, `RETRYABLE_HTTP_STATUSES`

### 2. `core/db.py` — MetricsDB (SQLite)

Banco local unificado com três tabelas:

| Tabela | Chaves | Descrição |
|--------|--------|-----------|
| `collection_runs` | `run_id` (PK) | Registro de cada execução de coleta (status: `success`/`failed`) |
| `event_metrics` | `id` (PK), FK `run_id` | Métricas por log source por janela |
| `log_sources_inventory` | `logsource_id` (PK) | Inventário de sources/indexes |

Formato unificado para inventário:
```python
{"logsource_id": int, "name": str, "type_name": str,
 "type_id": int, "enabled": bool, "description": str}
```

### 3. `core/report.py` — ReportGenerator

Gera relatórios parametrizados por SIEM:

| Parâmetro | QRadar | Splunk | Google SecOps |
|-----------|--------|--------|---------------|
| `siem_name` | `"qradar"` | `"splunk"` | `"secops"` |
| `source_label` | `"Log Source"` | `"Source [Index]"` | `"Log Type"` |
| `type_label` | `"Tipo Log Source"` | `"Sourcetype"` | `"Log Type"` |
| `include_unparsed` | ✅ | ❌ | ❌ |
| `include_aggregated` | ✅ | ❌ | ❌ |

Formatos:
- **CSV** — UTF-8 BOM, separador `;`, Excel-ready
- **TXT** — Tabela formatada com resumo diário e estimativa mensal

### 4. `core/collection.py` — Collection Engine

- `run_collection_cycle()` — executa um ciclo para uma janela exata. Retorna número de sources com dados (≥ 0) ou **-1 em caso de falha na query** (sinaliza ao loop para não avançar a janela)
- `main_collection_loop()` — loop principal com inventário, coleta, catch-up e relatório. Só avança `last_window_end_ms` quando `ds_count >= 0`

Features:
- **Janelas contíguas de 1h** `[start, end)` — sem sobreposição
- **Catch-up cap** — máximo `MAX_CATCHUP_WINDOWS=3` janelas por ciclo
- **Zero-fill** — registra `0` para sources sem eventos na janela- **GROUP BY logsource_id** — evita mistura quando fontes têm nomes iguais ou são renomeadas
- **Falha ≠ avança** — query failure retorna -1; a janela é re-tentada no próximo ciclo
- **Status tracking** — runs com falha são marcadas `status='failed'` via `update_collection_run_status()`
- **Enabled-only zero-fill** — apenas fontes com `enabled=1` participam do zero-fill (fontes desabilitadas são excluídas)
- **post_collect_callback** — Splunk usa para atualizar inventário de SPL results

### 5. `collectors/base.py` — SIEMClient ABC

Interface que todo client SIEM deve implementar:

```python
class SIEMClient(ABC):
    def test_connection(self) -> Dict: ...
    def get_event_metrics_window(self, start_ms, end_ms) -> Optional[List[Dict]]: ...
```

### 6. `collectors/qradar/client.py` — QRadarClient

- **Auth:** SEC token via header
- **Queries:** AQL via `/api/ariel/searches` (async polling)
- **Inventário:** `/api/config/event_sources/log_source_management/`
- **Paginação:** Range headers (`ARIEL_MAX_RESULTS=50000`; warning se atingido)
- **Coalescing Ratio:** Relatórios incluem coluna com ratio `total_events / aggregated_events` (indica coalescing do QRadar)
- **Bytes:** Volumes de bytes referem-se ao **payload armazenado no Ariel** (pode diferir do log bruto on-wire)
- **Unparsed:** `isunparsed` via AQL com fallback

### 7. `collectors/splunk/client.py` — SplunkClient

- **Auth:** Bearer Token ou Basic Auth (username:password)
- **Queries:** SPL via Search Jobs API v2
- **Inventário:** `/services/data/indexes` + SPL metadata
- **Extras:** license_usage.log, forwarder list, data inputs via `| rest`

### 8. `collectors/google_secops/client.py` — GoogleSecOpsClient

- **Auth:** Service Account JSON (`google-auth`) ou Bearer Token
- **Scope:** `https://www.googleapis.com/auth/chronicle-backstory`
- **API:** Backstory API v1 — `GET /v1/events:udmSearch`
- **Endpoints:** 19 regiões (US default: `backstory.googleapis.com`)
- **Agregação:** Client-side por `metadata.logType` + `metadata.productName`
- **Limite:** 10.000 eventos/query, 360 queries/hora, 10 min timeout
- **Inventário:** Log types descobertos via UDM Search (últimas 24h)
- **Nota:** Payload bytes não disponíveis via UDM Search (preenchidos com 0.0)

### 9. `main.py` — Entry Point Unificado

```bash
python main.py qradar --url ... --token ...
python main.py splunk --url ... --token ...
python main.py splunk --url ... --username ... --password ...
python main.py secops --sa-file ... --region us
python main.py secops --token ... --region southamerica-east1
python main.py qradar --report-only --db-file metrics.db
python main.py splunk --create-config
```

---

## Fluxo de Dados

```
SIEM API ──► SIEMClient ──► run_collection_cycle ──► MetricsDB (SQLite)
                                                          │
                                                          ▼
                                                    ReportGenerator
                                                     │          │
                                                     ▼          ▼
                                                    CSV        TXT
                                                (Excel)    (Terminal)
```

---

## Tratamento de Erros

| Cenário | Comportamento |
|---------|---------------|
| API timeout | Retry com backoff (2s → 4s → 8s) |
| HTTP 401/403 | Erro fatal — token inválido |
| HTTP 429 | Retry respeitando `Retry-After` header |
| HTTP 5xx | Retry com backoff |
| Rede indisponível | Retry com backoff |
| Ctrl+C / SIGINT | Parada graciosa — salva estado e gera relatório |
| Query AQL/SPL/UDM falha | Retorna -1; janela não avança; catch-up no próximo ciclo |
| SIEM reiniciando | Retry com backoff — recupera nas janelas seguintes |
| Rate limit (429) | Retry respeitando `Retry-After`; Google SecOps: 360 QPH |
| Disco cheio | Erro fatal — SQLite não consegue escrever |

---

## Como Adicionar um Novo SIEM

1. Crie `collectors/<nome>/client.py` com uma classe que herda de `SIEMClient`
2. Implemente `test_connection()` e `get_event_metrics_window()`
3. Adicione `collect_inventory()` e `create_sample_config()`
4. Adicione o subcommand em `main.py`
5. Crie `tests/test_<nome>.py` com testes unitários
6. Atualize `README.md`
