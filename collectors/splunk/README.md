# Splunk Log Ingestion Collector

Script Python para coleta automatizada de métricas de ingestão de logs do Splunk via REST API.  
Projetado para **sizing e planejamento de migração para Microsoft Sentinel / Defender for Cloud**.

Roda continuamente por N dias (padrão: **6**), coleta métricas a cada intervalo configurável (padrão: **1 hora**) e gera relatórios detalhados (CSV + TXT) com médias diárias, projeções 24h e estimativas mensais por data source.

---

## Índice

1. [Pré-requisitos](#pré-requisitos)
2. [Instalação](#instalação)
3. [Modos de Execução](#modos-de-execução)
4. [Parâmetros de Linha de Comando](#parâmetros-de-linha-de-comando)
5. [Precedência de Credenciais](#precedência-de-credenciais)
6. [O Que o Script Coleta](#o-que-o-script-coleta)
7. [Comportamento em Tempo de Execução](#comportamento-em-tempo-de-execução)
8. [Relatórios Gerados](#relatórios-gerados)
9. [Arquitetura do Script](#arquitetura-do-script)
10. [Suite de Testes](#suite-de-testes)
11. [Troubleshooting](#troubleshooting)
12. [Licença](#licença)

---

## Pré-requisitos

### Ambiente de Execução
- **Python 3.8+** (recomendado 3.10+)
- **Módulo `requests`** para HTTP
- Acesso de rede (HTTPS/8089) da máquina de execução até o Splunk Management API
- Sessão persistente recomendada (`screen`, `tmux` no Linux, ou tarefa em background no Windows)

### Credenciais do Splunk

O script suporta duas formas de autenticação:

#### Opção A: Bearer Token (recomendado)

| Permissão necessária | Endpoint REST |
|---|---|
| Executar search jobs | `/services/search/jobs` |
| Ler informações do servidor | `/services/server/info` |
| Ler lista de indexes | `/services/data/indexes` |

**Como gerar o token no Splunk:**

1. Acesse a interface web do Splunk como Administrador
2. Navegue até **Settings** → **Tokens** (ou **Settings** → **Users** → selecione o usuário → **Edit Tokens**)
3. Clique em **New Token**
4. Selecione o **Audience** e defina uma expiração (recomendado: 30 dias)
5. Clique em **Create** e **copie o token** — ele não será exibido novamente

> **Nota:** Em Splunk Cloud, tokens são gerenciados em **Settings → Tokens**. A capability `edit_tokens_settings` precisa estar habilitada.

#### Opção B: Basic Auth (usuário e senha)

Use username e password de uma conta com as roles `search` e `admin` (ou equivalente). Menos seguro que tokens — evitar em produção.

---

## Instalação

```bash
# 1. Copiar os arquivos para a máquina com acesso ao Splunk
cd splunk_log_collector

# 2. Instalar dependências
pip install -r requirements.txt
```

### Estrutura de arquivos do projeto

```
splunk_log_collector/
├── splunk_log_collector_v2.py       # Script principal (v2)
├── test_splunk_log_collector.py     # Suite de testes (31 testes)
├── requirements.txt                 # Dependências Python
├── LICENSE                          # Licença MIT
└── README.md                        # Este documento
```

### Arquivos gerados durante execução

```
splunk_log_collector/
├── splunk_metrics.db                # Banco SQLite com todas as métricas
├── splunk_collector.log             # Log de execução detalhado
├── config.json                      # (opcional) Criado via --create-config
└── reports/
    ├── splunk_daily_report_<ts>.csv
    ├── splunk_summary_report_<ts>.csv
    └── splunk_full_report_<ts>.txt
```

---

## Modos de Execução

### Modo 1: Interativo (mais fácil)

Executa sem parâmetros — o script pergunta o modo de autenticação (token ou usuário/senha) de forma segura:

```bash
python splunk_log_collector_v2.py
```

### Modo 2: Bearer Token via CLI

Ideal para rodar em background via `tmux`/`screen`:

```bash
# Coleta padrão (6 dias, a cada 1 hora)
python splunk_log_collector_v2.py --url https://splunk:8089 --token SEU_TOKEN

# Coleta customizada (10 dias, a cada 2 horas)
python splunk_log_collector_v2.py --url https://splunk:8089 --token SEU_TOKEN --days 10 --interval 2

# Com verificação SSL
python splunk_log_collector_v2.py --url https://splunk:8089 --token SEU_TOKEN --verify-ssl
```

### Modo 3: Basic Auth via CLI

```bash
python splunk_log_collector_v2.py --url https://splunk:8089 --username admin --password SENHA
```

### Modo 4: Arquivo de Configuração

```bash
# Criar template
python splunk_log_collector_v2.py --create-config

# Editar config.json e rodar
python splunk_log_collector_v2.py --config config.json
```

Exemplo de `config.json`:
```json
{
    "splunk_url": "https://splunk.empresa.com:8089",
    "auth_token": "SEU_TOKEN_AQUI",
    "username": "",
    "password": "",
    "verify_ssl": false,
    "collection_days": 6,
    "interval_hours": 1,
    "db_file": "splunk_metrics.db",
    "report_dir": "reports"
}
```

> **Segurança:** Não versione `config.json` em repositórios Git — ele contém credenciais.

### Modo 5: Variável de Ambiente (automação / CI)

```bash
export SPLUNK_TOKEN="SEU_TOKEN_AQUI"
python splunk_log_collector_v2.py --url https://splunk:8089
```

### Modo 6: Somente Relatório

Se a coleta já foi realizada (total ou parcial), gera relatórios sem iniciar nova coleta:

```bash
python splunk_log_collector_v2.py --report-only
```

---

## Parâmetros de Linha de Comando

| Parâmetro | Descrição | Padrão |
|---|---|---|
| `--url` | URL base do Splunk Management API (ex: `https://splunk:8089`) | *(obrigatório)* |
| `--token` | Bearer Token de autenticação | *(prompt se omitido)* |
| `--username` | Username para Basic Auth | — |
| `--password` | Password para Basic Auth | — |
| `--config` | Caminho para arquivo `config.json` | — |
| `--days` | Dias de coleta contínua | **6** |
| `--interval` | Intervalo entre coletas (horas) | **1** |
| `--db` | Arquivo SQLite para armazenamento | `splunk_metrics.db` |
| `--report-dir` | Diretório para relatórios | `reports/` |
| `--verify-ssl` | Verificar certificado SSL | `False` |
| `--report-only` | Gera relatório sem coletar | `False` |
| `--create-config` | Cria `config.json` de exemplo e sai | — |
| `--verbose` | Modo debug (logging detalhado) | `False` |

---

## Precedência de Credenciais

### Bearer Token

| Prioridade | Fonte | Quando usar |
|---|---|---|
| **1 (maior)** | `--token` na CLI | Execução ad-hoc rápida |
| **2** | `auth_token` no `config.json` | Operação controlada (não versionar o arquivo!) |
| **3** | Variável de ambiente `SPLUNK_TOKEN` | Automação, pipelines CI/CD |
| **4 (menor)** | Prompt interativo (`getpass`) | Execução manual segura |

### Basic Auth

Se nenhum token for encontrado, o modo interativo pergunta se deseja usar usuário/senha. Via CLI, use `--username` e `--password`.

---

## O Que o Script Coleta

### Métricas por data source (a cada intervalo)

| Métrica | Fonte SPL | Descrição |
|---|---|---|
| `source` | Campo nativo | Caminho/nome da fonte de dados |
| `sourcetype` | Campo nativo | Tipo da fonte (ex: syslog, WinEventLog, pan:traffic) |
| `index` | Campo nativo | Índice do Splunk onde os dados estão armazenados |
| `total_event_count` | `count` | Total de eventos no intervalo |
| `total_payload_bytes` | `sum(len(_raw))` | Volume total dos eventos brutos |
| `avg_payload_bytes` | `avg(len(_raw))` | Tamanho médio por evento |

### Query SPL utilizada

```spl
index=*
| stats count as total_event_count,
        sum(len(_raw)) as total_payload_bytes,
        avg(len(_raw)) as avg_payload_bytes
  by source, sourcetype, index
```

> **Nota:** A query usa `earliest` e `latest` como epoch seconds para definir o intervalo exato da janela, evitando sobreposição entre coletas consecutivas.

### Inventário de Indexes

Na inicialização, o script coleta a lista de indexes via REST:
- `/services/data/indexes` — nome, total de eventos, tamanho atual em MB, status

---

## Comportamento em Tempo de Execução

### Fluxo principal

```
1. Teste de conexão        → GET /services/server/info (valida URL + credenciais)
2. Inventário              → Lista indexes e sourcetypes
3. Loop de coleta          → Para cada intervalo:
   a. Calcula janela exata (window_start_ms → window_end_ms)
   b. Executa SPL via search job (POST → poll → GET results)
   c. Salva métricas no SQLite
   d. Atualiza inventário com sources descobertos
   e. Zero-fill: insere linhas com 0 para sources inativos
   f. Aguarda próximo intervalo
4. Relatório final         → Gera CSV + TXT ao encerrar
```

Os dados são salvos no SQLite (`splunk_metrics.db`) **a cada ciclo de coleta**. Se o script for interrompido por qualquer motivo (queda de energia, fechamento do terminal, crash), todos os dados coletados até aquele momento estão preservados e podem ser extraídos com `--report-only`.

> **Dica:** Como o script roda por vários dias, é altamente recomendável executá-lo em uma sessão que não feche ao desconectar — ex: `screen` ou `tmux` no Linux, ou como tarefa em background no Windows.

### Janelas contíguas sem sobreposição

O script mantém janelas **contíguas** usando epoch em milissegundos:
- Cada ciclo usa `window_start_ms = last_window_end_ms`
- Isso elimina gaps e sobreposições entre coletas consecutivas
- A `collection_date` é derivada de `window_end_ms - 1ms` (janela 23:00-00:00 pertence ao dia anterior)

### Zero-fill para cobertura completa

Após cada coleta SPL, o script insere linhas com **zero eventos** para todos os sources do inventário que **não apareceram nos resultados**. Isso é essencial porque:

- Sem zero-fill: fontes intermitentes teriam apenas janelas com dados → projeção 24h inflada
- Com zero-fill: toda janela observada conta como cobertura → projeção diária matematicamente correta

### Inventário incremental

Diferente do QRadar (que tem um endpoint dedicado de log sources), o Splunk não possui um equivalente exato. O script constrói o inventário **incrementalmente** a partir dos resultados SPL: cada source/sourcetype/index novo descoberto é adicionado automaticamente ao inventário.

### Catch-up com cap (recuperação após falhas)

Se uma coleta falha (erro de rede, timeout, etc.):
1. O script **não avança** `last_window_end_ms` — a janela perdida será retentada
2. Um **cap de segurança** (`MAX_CATCHUP_WINDOWS = 3`) limita a janela a no máximo 3× o intervalo
3. Dados além do limite são registrados como perdidos no log

### Retry com backoff exponencial

Falhas HTTP transitórias (429, 500, 502, 503, 504) disparam retry automático:
- Até 3 tentativas com delay exponencial (2s, 4s, 8s)
- Respeita header `Retry-After` quando presente
- Erros 401/403/404 **não** são retentados

### Parada graciosa

O script aceita `Ctrl+C` (SIGINT):
- A coleta atual é finalizada
- O relatório final é gerado automaticamente
- Todos os dados já coletados são preservados no SQLite

Se o script for interrompido abruptamente (kill, crash), rode `--report-only` para gerar relatórios do que já foi coletado.

---

## Relatórios Gerados

Ao final da coleta (ou via `--report-only`), três arquivos são gerados em `reports/`:

### 1. `splunk_daily_report_<timestamp>.csv`

Detalhamento granular, dia a dia, por data source. Útil para investigar picos de ingestão em dias específicos:

| Coluna | Descrição |
|---|---|
| `Data` | Data da coleta (YYYY-MM-DD) |
| `Source [Index]` | Source e index de origem |
| `Sourcetype` | Tipo do data source |
| `Total Eventos` | Total de eventos no dia |
| `Total Payload (Bytes/MB/GB)` | Volume total |
| `Tamanho Médio Evento` | Bytes por evento |

### 2. `splunk_summary_report_<timestamp>.csv`

Resumo consolidado em CSV (separado por ponto e vírgula `;`, pronto para abrir no Excel). Ideal para sizing:

| Coluna | Descrição |
|---|---|
| `Source [Index]` | Source e index |
| `Sourcetype` | Tipo do data source |
| `Dias Coletados` | Dias com dados |
| `Média Diária de Eventos` | Projeção 24h |
| `Média Diária Volume` | Bytes/MB/GB por dia |

### 3. `splunk_full_report_<timestamp>.txt`

Relatório completo formatado em texto, fácil de ler. Contém:
- Informações da coleta (período, total de execuções)
- Detalhamento diário com tabelas por dia
- Resumo de médias diárias por data source
- **Estimativa de volume mensal** (projeção 30 dias — **o dado mais importante para o sizing do Sentinel**)

---

## Arquitetura do Script

```
splunk_log_collector_v2.py  (~1100 linhas)
│
├── Constantes
│   ├── DEFAULT_COLLECTION_DAYS = 6
│   ├── MAX_CATCHUP_WINDOWS = 3
│   ├── SPL_TIMEOUT_SECONDS = 300
│   ├── DEFAULT_SPLUNK_PORT = 8089
│   └── RETRYABLE_HTTP_STATUSES = (429, 500, 502, 503, 504)
│
├── _retry_with_backoff()        → Retry exponencial com Retry-After
│
├── SplunkClient                 → Cliente REST API (Management port 8089)
│   ├── __init__()               → Sessão HTTP (Bearer Token ou Basic Auth)
│   ├── _check_response()        → Mensagens acionáveis para 401/403
│   ├── _get() / _post()         → GET/POST com retry e output_mode=json
│   ├── test_connection()        → Valida via /services/server/info
│   ├── get_indexes()            → Lista indexes (nome, tamanho, eventos)
│   ├── get_sourcetypes()        → Lista sourcetypes registrados
│   ├── get_data_inputs_summary()→ Lista data inputs configurados
│   ├── run_spl_query()          → POST job → poll isDone → GET results
│   ├── get_event_metrics_window()→ Query principal (stats by source/sourcetype/index)
│   ├── get_license_usage()      → Volume via _internal license_usage.log
│   └── get_forwarder_list()     → Lista forwarders conectados
│
├── MetricsDB                    → Armazenamento SQLite local
│   ├── collection_runs          → Registro de cada execução
│   ├── event_metrics            → Métricas por data source por janela
│   ├── log_sources_inventory    → Inventário incremental de sources
│   ├── save_event_metrics()     → Persiste resultados SPL
│   ├── fill_zero_event_rows()   → Zero-fill para fontes inativas
│   ├── get_daily_summary()      → Agregação diária
│   └── get_overall_daily_average() → Médias com projeção 24h
│
├── ReportGenerator              → Geração de relatórios
│   ├── daily CSV                → Detalhamento diário
│   ├── summary CSV              → Médias consolidadas
│   └── full text report         → Relatório com projeções mensais
│
├── ErrorCounter                 → Contadores de erros por categoria
│
├── run_collection_cycle()       → Um ciclo: SPL + save + zero-fill
├── collect_inventory()          → Coleta indexes na inicialização
│
└── main()                       → Orquestração completa
    ├── Parse args + config + env + prompt
    ├── test_connection()
    ├── collect_inventory()
    ├── Loop de coleta (janelas contíguas + catch-up com cap)
    └── Geração de relatórios
```

---

## Suite de Testes

### Por que o arquivo de testes existe?

O `test_splunk_log_collector.py` é a **rede de segurança** do projeto. Como o script opera contra a REST API do Splunk — que exige infraestrutura e credenciais — não é viável validar cada alteração manualmente. A suite usa **mocks** para reproduzir o comportamento da API sem depender de um Splunk real.

### Pré-requisitos para executar os testes

| Requisito | Detalhes |
|---|---|
| **Python 3.8+** | Mesmo requisito do script principal |
| **`requests`** | Já instalado via `requirements.txt` |
| **`pytest`** (opcional) | Recomendado para saída mais legível (`pip install pytest`) |
| **Acesso ao Splunk** | **Não é necessário** — todos os testes usam mocks |
| **Arquivo do script** | `splunk_log_collector_v2.py` deve estar na mesma pasta |

### Como executar

```bash
# Com pytest (recomendado)
pip install pytest
python -m pytest test_splunk_log_collector.py -v

# Sem pytest (usando unittest nativo)
python -m unittest test_splunk_log_collector -v
```

### Cobertura dos testes

| Classe de Teste | Testes | O que valida |
|---|---|---|
| `TestCollectionDateBoundary` | 3 | `collection_date` via `window_end_ms - 1ms` (meia-noite, +1ms, meio-dia) |
| `TestSPLQueries` | 4 | stats by source/sourcetype/index, epoch times, normalização de resultados |
| `TestTokenPrecedence` | 5 | Cadeia CLI > config > ENV > vazio + Basic Auth como alternativa |
| `TestSplunkSearchFlow` | 2 | Fluxo completo POST→poll→results + max_count |
| `TestZeroFill` | 2 | Zero-fill para fontes ausentes, skip para presentes |
| `TestCatchUpCap` | 2 | Cap limita janela, gap dentro do limite mantido |
| `TestCheckResponse` | 3 | Mensagens acionáveis 401/403, 200 silencioso |
| `TestTestConnection` | 1 | `test_connection()` via `/services/server/info` |
| `TestRunCollectionCycle` | 2 | Integração com DB real: dados parciais + sem dados |
| `TestRetryWithBackoff` | 2 | Retry em 500, sem retry em 401 |
| `TestConstants` | 5 | Valores: `DEFAULT_COLLECTION_DAYS=6`, `DEFAULT_SPLUNK_PORT=8089`, etc. |
| `TestSplunkClientAuth` | 3 | Bearer token, Basic Auth, sem credenciais (ValueError) |

---

## Troubleshooting

| Problema | Causa provável | Solução |
|---|---|---|
| `HTTP 401 Unauthorized` | Token expirado, revogado, ou credenciais incorretas | Gere novo token em Settings → Tokens, ou verifique user/password |
| `HTTP 403 Forbidden` | Credenciais válidas mas sem capabilities (roles) suficientes | Role precisa de `search`, `list_indexes` e acesso ao index desejado |
| `ConnectionError` | URL/porta incorreta ou sem acesso de rede | Porta padrão é **8089** (Management); verificar firewalls |
| `SSL Error` | Certificado auto-assinado | Não use `--verify-ssl` (padrão: desabilitado) |
| `Módulo 'requests' não encontrado` | Dependência não instalada | `pip install -r requirements.txt` |
| `SPL job timeout` | Splunk sobrecarregado ou intervalo muito grande | Aumente `SPL_TIMEOUT_SECONDS` ou reduza `--interval` |
| `Catch-up excedeu limite` | Falhas consecutivas acumularam gap > 3 intervalos | Dados do gap são perdidos (registrado no log); coleta continua |
| Script parou/crashou — perdi tudo? | Queda de energia, terminal fechado, crash | **Não.** Rode `--report-only` na mesma pasta para extrair relatórios |
| Dados vazios / sem resultados | Nenhum evento no período, ou indexes vazios | Verifique no Splunk se há eventos; use `--verbose` |
| `Porta 8089 recusada` | Splunk Web (8000) vs Management (8089) | A REST API roda na **8089**, não na 8000 |

---

## Diferenças em relação ao coletor QRadar

| Aspecto | QRadar | Splunk |
|---|---|---|
| **Porta da API** | 443 (HTTPS padrão) | 8089 (Management) |
| **Autenticação** | SEC Token | Bearer Token ou Basic Auth |
| **Linguagem de query** | AQL (SQL-like) | SPL (pipe-based) |
| **Fluxo async** | POST `/ariel/searches` → poll → GET results | POST `/search/jobs` → poll isDone → GET results |
| **Inventário** | Endpoint dedicado (`/log_sources`) | Construído incrementalmente dos resultados SPL |
| **Volume por evento** | `STRLEN(UTF8(payload))` | `len(_raw)` |
| **Unparsed events** | Campo `isunparsed` (com fallback) | Não aplicável (Splunk não tem conceito equivalente) |
| **License usage** | Não disponível via API padrão | Disponível via `_internal` + `license_usage.log` |

---

## Licença

Este projeto é licenciado sob a [MIT License](LICENSE).
