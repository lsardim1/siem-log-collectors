# 🏗️ Arquitetura dos Coletores

Este documento detalha a arquitetura compartilhada entre todos os coletores do projeto **siem-log-collectors**.

---

## Visão Geral

Cada coletor é um script Python standalone que:

1. **Conecta** ao SIEM de origem via REST API
2. **Coleta** metadados de volume (event count, byte count) por log source type
3. **Armazena** as métricas em um banco SQLite local
4. **Gera** relatórios CSV e TXT para análise de sizing

```
┌──────────────┐     REST API      ┌──────────────┐
│  SIEM Legado │ ◄──────────────── │   Coletor    │
│  (QRadar,    │   Autenticação    │   Python     │
│   Splunk,    │   + Queries       │              │
│   etc.)      │                   │              │
└──────────────┘                   └──────┬───────┘
                                          │
                              ┌───────────┼───────────┐
                              │           │           │
                         ┌────▼────┐ ┌────▼────┐ ┌────▼────┐
                         │ SQLite  │ │  CSV    │ │  TXT    │
                         │ metrics │ │ report  │ │ summary │
                         └─────────┘ └─────────┘ └─────────┘
```

---

## Componentes

### 1. CLI (Interface de Linha de Comando)

- **Biblioteca:** `argparse`
- **Credenciais:** `getpass.getpass()` — nunca expõe senhas no histórico do shell
- **Parâmetros universais:**

| Parâmetro | Tipo | Descrição |
|-----------|------|-----------|
| `--url` | str | URL base do SIEM |
| `--collection-days` | int | Dias de coleta (padrão: 6) |
| `--interval` | int | Intervalo entre ciclos em segundos (padrão: 60) |
| `--no-verify-ssl` | flag | Desabilita verificação SSL |
| `--report-only` | flag | Gera relatório a partir do SQLite sem coletar |

### 2. API Client

Cada SIEM tem seu próprio client, mas todos implementam:

- **Autenticação:** Token, Basic Auth, ou OAuth 2.0 conforme o SIEM
- **Retry com backoff exponencial:**
  ```
  Tentativa 1 → falha → espera 2s
  Tentativa 2 → falha → espera 4s
  Tentativa 3 → falha → erro fatal
  ```
- **SSL configurável:** `--no-verify-ssl` para ambientes com certificados self-signed
- **Timeout:** 30s para conexão, 300s para leitura (queries pesadas)

### 3. Collection Engine

O motor de coleta segue um loop principal:

```python
while not stop_event.is_set():
    # 1. Determinar janela atual (1 hora)
    window_start, window_end = calculate_window()
    
    # 2. Para cada log source type:
    for source_type in source_types:
        # 2a. Consultar volume na janela
        events, bytes = query_volume(source_type, window_start, window_end)
        
        # 2b. Salvar no SQLite (INSERT OR REPLACE)
        db.save_metric(source_type, window_start, window_end, events, bytes)
    
    # 3. Zero-fill: registrar 0 para janelas sem dados
    db.zero_fill_missing_windows()
    
    # 4. Catch-up: processar até MAX_CATCHUP_WINDOWS por ciclo
    if pending_windows > MAX_CATCHUP_WINDOWS:
        process_only(MAX_CATCHUP_WINDOWS)
    
    # 5. Dormir até próximo ciclo
    sleep(SLEEP_BETWEEN_CYCLES)
```

#### Janelas Contíguas

- Cada janela tem exatamente **3600 segundos** (1 hora)
- As janelas são **contíguas** (sem sobreposição nem lacuna)
- Formato: `[window_start, window_end)` — início inclusivo, fim exclusivo

#### Zero-Fill

Quando uma janela não retorna dados (0 eventos), o coletor **registra explicitamente** `event_count=0, byte_count=0` no SQLite. Isso garante:

- O relatório mostra **todas** as horas, mesmo as sem atividade
- As médias diárias são calculadas corretamente
- Não há "buracos" no CSV

#### Catch-Up Cap

Se o coletor ficou parado por horas (ex: reinício do servidor), ele precisa recuperar as janelas perdidas. Para não sobrecarregar a API:

- Máximo **3 janelas** são processadas por ciclo (`MAX_CATCHUP_WINDOWS=3`)
- As janelas mais antigas são processadas primeiro (FIFO)
- O catch-up continua nos ciclos seguintes até ficar em dia

### 4. MetricsDB (SQLite)

Banco local com duas tabelas:

#### `hourly_metrics`

| Coluna | Tipo | Descrição |
|--------|------|-----------|
| `source_type` | TEXT | Nome do log source type |
| `window_start` | TEXT | Início da janela (ISO 8601) |
| `window_end` | TEXT | Fim da janela (ISO 8601) |
| `event_count` | INTEGER | Quantidade de eventos |
| `byte_count` | INTEGER | Bytes coletados |

**PK:** `(source_type, window_start)`

#### `collection_state`

| Coluna | Tipo | Descrição |
|--------|------|-----------|
| `key` | TEXT PK | Chave de estado |
| `value` | TEXT | Valor serializado |

Chaves comuns:
- `last_window_end` — fim da última janela processada
- `collection_start` — início da coleta
- `source_types` — JSON com lista de source types

#### Idempotência

Todas as inserções usam `INSERT OR REPLACE`, garantindo que:
- Re-processar uma janela **sobrescreve** os dados anteriores
- Não há duplicatas no banco
- A coleta pode ser interrompida e retomada sem efeitos colaterais

### 5. ReportGenerator

Gera dois tipos de relatório:

#### CSV (Excel-ready)

- **Encoding:** UTF-8 com BOM (`\xEF\xBB\xBF`)
- **Separador:** `;` (compatível com Excel em pt-BR)
- **Colunas:**
  ```
  source_type;total_events;total_bytes;total_gb;avg_gb_per_day;peak_gb_per_day;collection_days;first_seen;last_seen
  ```

#### TXT (Resumo terminal)

- Tabela formatada com os top source types
- Totais gerais (eventos, GB, média diária)
- Informações de coleta (período, janelas processadas)

---

## Fluxo de Dados

```
SIEM API ──► Collection Engine ──► MetricsDB (SQLite)
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
| SIEM reiniciando | Retry com backoff — recupera nas janelas seguintes |
| Disco cheio | Erro fatal — SQLite não consegue escrever |

---

## Parâmetros de Tuning

| Constante | Valor | Ajustável? | Impacto |
|-----------|-------|------------|---------|
| `COLLECTION_DAYS` | 6 | Sim (CLI) | Mais dias = média mais precisa, mas coleta mais longa |
| `WINDOW_SECONDS` | 3600 | Não | Janela menor = mais queries, maior granularidade |
| `MAX_CATCHUP_WINDOWS` | 3 | Não | Maior = recuperação mais rápida, mas mais carga na API |
| `MAX_RETRIES` | 3 | Não | Mais retries = mais tolerante, mas mais lento em falhas |
| `INITIAL_BACKOFF` | 2 | Não | Backoff menor = retry mais rápido |
| `SLEEP_BETWEEN_CYCLES` | 60 | Sim (CLI) | Menor = mais real-time, mas mais requisições |
