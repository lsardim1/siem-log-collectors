# QRadar Log Ingestion Collector

> **Nota:** A partir da v3 (arquitetura modular), use `python main.py qradar --url ... --token ...` da raiz do repositório.
> O client QRadar está em `collectors/qradar/client.py` e usa os módulos compartilhados de `core/`.

Módulo Python para coleta automatizada de métricas de ingestão de logs do IBM QRadar via REST API.  
Projetado para **sizing e planejamento de migração para Microsoft Sentinel / Defender for Cloud**.

Roda continuamente por N dias (padrão: **6**), coleta métricas a cada intervalo configurável (padrão: **1 hora**) e gera relatórios detalhados (CSV + TXT) com médias diárias, projeções 24h e estimativas mensais por data source.

---

## Índice

1. [Pré-requisitos](#pré-requisitos)
2. [Instalação](#instalação)
3. [Modos de Execução](#modos-de-execução)
4. [Parâmetros de Linha de Comando](#parâmetros-de-linha-de-comando)
5. [Precedência de Credenciais (Token)](#precedência-de-credenciais-token)
6. [O Que o Script Coleta](#o-que-o-script-coleta)
7. [Comportamento em Tempo de Execução](#comportamento-em-tempo-de-execução)
8. [Relatórios Gerados](#relatórios-gerados)
9. [Arquitetura do Script](#arquitetura-do-script)
10. [Suite de Testes](#suite-de-testes)
11. [Troubleshooting](#troubleshooting)
12. [Changelog (correções aplicadas)](#changelog)
13. [Licença](#licença)

---

## Pré-requisitos

### Ambiente de Execução
- **Python 3.8+** (recomendado 3.10+)
- **Módulo `requests`** para HTTP
- Acesso de rede (HTTPS/443) da máquina de execução até o console do IBM QRadar
- Sessão persistente recomendada (`screen`, `tmux` no Linux, ou tarefa em background no Windows)

### Credenciais do QRadar (API Token SEC)
Você precisará de um **Authorized Service Token (SEC Token)** do QRadar com permissões para:

| Permissão necessária | Endpoint REST |
|---|---|
| Ler configurações de Log Sources | `/api/config/event_sources/log_source_management/log_sources` |
| Ler tipos de Log Sources | `/api/config/event_sources/log_source_management/log_source_types` |
| Executar buscas no Ariel (AQL) | `/api/ariel/searches` |
| Informações do sistema | `/api/system/about` |

### Como gerar o token no QRadar

1. Acesse a interface web do QRadar como Administrador
2. Navegue até **Admin** → **Authorized Services**
3. Clique em **Add Authorized Service**
4. Dê um nome descritivo (ex: `Migracao_Sentinel_Collector`)
5. Selecione um **User Role** e **Security Profile** com acesso total aos dados de log
6. Defina a expiração (recomendado: 30 dias, ou compatível com a duração da coleta)
7. Salve e **copie o Token** gerado — ele não será exibido novamente

---

## Instalação

```bash
# 1. Copiar os arquivos para a máquina com acesso ao QRadar
cd qradar_log_collector

# 2. Instalar dependências
pip install -r requirements.txt
```

### Estrutura de arquivos do projeto (modular)

```
siem-log-collectors/
├── main.py                          # Ponto de entrada unificado
├── core/                            # Módulos compartilhados
│   ├── utils.py                     # Constantes e funções utilitárias
│   ├── db.py                        # MetricsDB (SQLite)
│   ├── report.py                    # Geração de relatórios
│   └── collection.py                # Loop de coleta e ciclos
├── collectors/
│   └── qradar/
│       ├── client.py                # QRadarClient (REST API)
│       └── README.md                # Este documento
├── tests/
│   ├── test_core.py                 # 27 testes (módulos compartilhados)
│   └── test_qradar.py               # 15 testes (específicos QRadar)
├── requirements.txt                 # Dependências Python
└── README.md                        # README principal
```

### Arquivos gerados durante execução

```
qradar_log_collector/
├── qradar_metrics.db                # Banco SQLite com todas as métricas
├── qradar_collector.log             # Log de execução detalhado
├── config.json                      # (opcional) Criado via --create-config
└── reports/
    ├── qradar_daily_report_<ts>.csv
    ├── qradar_summary_report_<ts>.csv
    └── qradar_full_report_<ts>.txt
```

---

## Modos de Execução

### Modo 1: Interativo (mais fácil)

Executa sem parâmetros — o script solicita URL e Token de forma segura (input oculto):

```bash
python main.py qradar
```

### Modo 2: Linha de Comando (CLI)

Ideal para rodar em background via `tmux`/`screen`:

```bash
# Coleta padrão (6 dias, a cada 1 hora)
python main.py qradar --url https://qradar.empresa.com --token SEU_TOKEN

# Coleta customizada (10 dias, a cada 2 horas)
python main.py qradar --url https://qradar.empresa.com --token SEU_TOKEN --days 10 --interval 2

# Com verificação SSL
python main.py qradar --url https://qradar.empresa.com --token SEU_TOKEN --verify-ssl
```

### Modo 3: Arquivo de Configuração

```bash
# Criar template
python main.py qradar --create-config

# Editar config e rodar
python main.py qradar --config qradar_config.json
```

Exemplo de `config.json`:
```json
{
    "qradar_url": "https://qradar.empresa.com",
    "api_token": "SEU_TOKEN_AQUI",
    "verify_ssl": false,
    "api_version": "26.0",
    "collection_days": 6,
    "interval_hours": 1,
    "db_file": "qradar_metrics.db",
    "report_dir": "reports"
}
```

> **Segurança:** Não versione `config.json` em repositórios Git — ele contém o token API.

### Modo 4: Variável de Ambiente (automação / CI)

```bash
export QRADAR_TOKEN="SEU_TOKEN_AQUI"
python main.py qradar --url https://qradar.empresa.com
```

### Modo 5: Somente Relatório

Se a coleta já foi realizada (total ou parcial), gera relatórios sem iniciar nova coleta:

```bash
python main.py qradar --report-only --db-file qradar_metrics.db
```

---

## Parâmetros de Linha de Comando

| Parâmetro | Descrição | Padrão |
|---|---|---|
| `--url` | URL base do QRadar (ex: `https://qradar:443`) | *(obrigatório)* |
| `--token` | API Token SEC do QRadar | *(prompt se omitido)* |
| `--config` | Caminho para arquivo `config.json` | — |
| `--days` | Dias de coleta contínua | **6** |
| `--interval` | Intervalo entre coletas (horas) | **1** |
| `--db-file` | Arquivo SQLite para armazenamento | `qradar_metrics.db` |
| `--report-dir` | Diretório para relatórios | `reports/` |
| `--verify-ssl` | Verificar certificado SSL | `False` |
| `--api-version` | Versão da API QRadar | `26.0` |
| `--report-only` | Gera relatório sem coletar | `False` |
| `--create-config` | Cria `config.json` de exemplo e sai | — |
| `--verbose` | Modo debug (logging detalhado) | `False` |

---

## Precedência de Credenciais (Token)

O token API é resolvido na seguinte ordem de prioridade:

| Prioridade | Fonte | Quando usar |
|---|---|---|
| **1 (maior)** | `--token` na CLI | Execução ad-hoc rápida |
| **2** | `api_token` no `config.json` | Operação controlada (não versionar o arquivo!) |
| **3** | Variável de ambiente `QRADAR_TOKEN` | Automação, pipelines CI/CD |
| **4 (menor)** | Prompt interativo (`getpass`) | Execução manual segura |

Se nenhuma fonte fornecer um token e o modo não for `--report-only`, o script exibe erro e encerra.

---

## O Que o Script Coleta

### Métricas por data source (a cada intervalo)

| Métrica | Fonte AQL | Descrição |
|---|---|---|
| `logsource_id` | `logsourceid` | ID único do data source no QRadar |
| `logsource_name` | `LOGSOURCENAME(logsourceid)` | Nome do data source |
| `logsource_type` | `LOGSOURCETYPENAME(devicetype)` | Tipo (ex: WinCollect, Syslog, Palo Alto) |
| `total_event_count` | `SUM(eventcount)` | Total real de eventos no intervalo |
| `aggregated_event_count` | `COUNT(*)` | Registros agregados/coalescidos no Ariel |
| `total_payload_bytes` | `SUM(STRLEN(UTF8(payload)))` | Volume total de payload armazenado |
| `avg_payload_bytes` | `AVG(STRLEN(UTF8(payload)))` | Tamanho médio por evento |
| `unparsed_*` | `isunparsed` | Eventos não parseados (fallback se indisponível) |

### Query AQL utilizada

```sql
SELECT logsourceid,
       LOGSOURCENAME(logsourceid) as log_source_name,
       LOGSOURCETYPENAME(devicetype) as log_source_type,
       COUNT(*) as aggregated_event_count,
       SUM(eventcount) as total_event_count,
       SUM(STRLEN(UTF8(payload))) as total_payload_bytes,
       AVG(STRLEN(UTF8(payload))) as avg_payload_bytes
FROM events
WHERE starttime >= <window_start_ms> AND starttime < <window_end_ms>
GROUP BY logsourceid, devicetype
ORDER BY total_event_count DESC
```

> **Nota técnica:** O script usa `LOGSOURCETYPENAME(devicetype)` (e não `logsourceid`) com `GROUP BY logsourceid, devicetype` para obter nomes de tipo corretos. A cláusula WHERE usa intervalo half-open (`>=` e `<`) para evitar double-counting entre janelas consecutivas.

### Inventário de Log Sources

Na inicialização, o script também coleta o inventário completo de log sources via paginação REST:
- `/api/config/event_sources/log_source_management/log_sources`
- `/api/config/event_sources/log_source_management/log_source_types`

---

## Comportamento em Tempo de Execução

### Fluxo principal

```
1. Teste de conexão        → GET /api/system/about (valida URL + token)
2. Inventário              → Pagina todas as log sources e tipos
3. Loop de coleta          → Para cada intervalo:
   a. Calcula janela exata (window_start_ms → window_end_ms)
   b. Executa AQL no Ariel (POST + poll + GET results)
   c. Salva métricas no SQLite
   d. Zero-fill: insere linhas com 0 para log sources inativos
   e. Aguarda próximo intervalo
4. Relatório final         → Gera CSV + TXT ao encerrar
```

Os dados são salvos no SQLite (`qradar_metrics.db`) **a cada ciclo de coleta**. Se o script for interrompido por qualquer motivo (queda de energia, fechamento do terminal, crash), todos os dados coletados até aquele momento estão preservados e podem ser extraídos com `--report-only`.

> **Dica:** Como o script roda por vários dias, é altamente recomendável executá-lo em uma sessão que não feche ao desconectar — ex: `screen` ou `tmux` no Linux, ou como tarefa em background no Windows.

### Janelas contíguas sem sobreposição

O script mantém janelas **contíguas** usando epoch em milissegundos:
- Cada ciclo usa `window_start_ms = last_window_end_ms`
- Isso elimina gaps e sobreposições entre coletas consecutivas
- A `collection_date` é derivada de `window_end_ms - 1ms` (janela 23:00-00:00 pertence ao dia anterior)

### Zero-fill para cobertura completa

Após cada coleta AQL, o script insere linhas com **zero eventos** para todos os log sources do inventário que **não apareceram nos resultados**. Isso é essencial porque:

- Sem zero-fill: fontes intermitentes teriam apenas janelas com dados → projeção 24h inflada
- Com zero-fill: toda janela observada conta como cobertura → projeção diária matematicamente correta

### Catch-up com cap (recuperação após falhas)

Se uma coleta falha (erro de rede, timeout, etc.):
1. O script **não avança** `last_window_end_ms` — a janela é retentada no próximo ciclo
2. `run_collection_cycle()` retorna **-1** para sinalizar falha (distinto de 0 = janela vazia)
3. Se houver falhas consecutivas, a janela acumulada pode crescer demais
4. Um **cap de segurança** (`MAX_CATCHUP_WINDOWS = 3`) limita a janela a no máximo 3× o intervalo
5. Dados além do limite são registrados como perdidos no log

### Range header nos resultados AQL

O GET em `/ariel/searches/{id}/results` inclui `Range: items=0-9999` como proteção contra respostas extremamente grandes em ambientes com muitos log sources.

### Retry com backoff exponencial

Falhas HTTP transitórias (429, 500, 502, 503, 504) disparam retry automático:
- Até 3 tentativas com delay exponencial (2s, 4s, 8s)
- Respeita header `Retry-After` quando presente (ex: rate limiting 429)
- Erros 401/403/404 **não** são retentados (ação do usuário necessária)

### Parada graciosa

O script aceita `Ctrl+C` (SIGINT):
- A coleta atual é finalizada
- O relatório final é gerado automaticamente
- Todos os dados já coletados são preservados no SQLite

Se o script for interrompido abruptamente (kill, crash), rode `--report-only` para gerar relatórios do que já foi coletado.

---

## Relatórios Gerados

Ao final da coleta (ou via `--report-only`), três arquivos são gerados em `reports/`:

### 1. `qradar_daily_report_<timestamp>.csv`

Detalhamento granular, dia a dia, por data source. Útil para investigar picos de ingestão em dias específicos:

| Coluna | Descrição |
|---|---|
| `collection_date` | Data da coleta (YYYY-MM-DD) |
| `logsource_id` | ID único do data source |
| `logsource_name` | Nome do data source |
| `logsource_type` | Tipo do data source |
| `total_events` | `SUM(total_event_count)` no dia |
| `aggregated_events` | `SUM(aggregated_event_count)` no dia |
| `total_bytes` | Volume total em bytes |
| `avg_event_size` | Tamanho médio por evento |

### 2. `qradar_summary_report_<timestamp>.csv`

Resumo consolidado em CSV (separado por ponto e vírgula `;`, pronto para abrir no Excel). Ideal para sizing:

| Coluna | Descrição |
|---|---|
| `logsource_id` | ID único do data source |
| `logsource_name` | Nome do data source |
| `logsource_type` | Tipo do data source |
| `days_collected` | Dias com dados coletados |
| `avg_daily_events` | Média diária de eventos |
| `avg_daily_volume` | Média diária de volume (bytes) |
| `avg_event_size` | Tamanho médio por evento |

### 3. `qradar_full_report_<timestamp>.txt`

Relatório completo formatado em texto, fácil de ler. Contém:
- Informações da coleta (período, total de execuções)
- Detalhamento diário com tabelas por dia
- Resumo de médias diárias por data source
- **Estimativa de volume mensal** (projeção 30 dias — **o dado mais importante para o sizing do Sentinel**)

```
====================================================================================================
  RELATÓRIO DE INGESTÃO DE LOGS - IBM QRadar
  Gerado em: 2026-02-28 10:00:00
====================================================================================================

  INFORMAÇÕES DA COLETA
  Período de coleta: 2026-02-22 a 2026-02-27
  Total de dias coletados: 6
  Total de execuções de coleta: 144
  Total de data sources identificados: 45

====================================================================================================
  RESUMO - MÉDIA DIÁRIA DE INGESTÃO POR DATA SOURCE
====================================================================================================

│ Log Source                     │ Tipo               │ Dias │ Avg Eventos/Dia │ Avg Volume/Dia  │
│ Windows Security Logs          │ WinCollect         │    6 │       2,450,000 │       1.82 GB   │
│ Firewall Palo Alto             │ Syslog             │    6 │       1,200,000 │       980.5 MB  │
│ Linux Auth Logs                │ Syslog             │    6 │         350,000 │       120.3 MB  │
...
```

---

## Arquitetura do Script (Modular)

Desde a v3, o projeto usa arquitetura modular com módulos compartilhados em `core/` e clients SIEM-específicos em `collectors/`.

```
collectors/qradar/client.py  (QRadarClient)
│
├── QRadarClient(SIEMClient)     → Herda ABC de collectors/base.py
│   ├── __init__()               → Sessão HTTP (SEC, Accept, Version)
│   ├── _check_response()        → Mensagens acionáveis para 401/403
│   ├── _get() / _post()         → GET/POST com retry e validação JSON
│   ├── _paginate_endpoint()     → Paginação via Range headers
│   ├── test_connection()        → Valida conectividade via /system/about
│   ├── get_log_sources()        → Inventário de log sources (paginado)
│   ├── get_log_source_types()   → Mapeamento type_id → nome (com guard None)
│   ├── run_aql_query()          → POST → poll → GET results (with Range)
│   ├── get_event_metrics_window()  → Query principal (com unparsed fallback)
│   └── get_event_counts_*()     → Queries de compat / flows

core/utils.py  (Constantes e funções utilitárias)
│
├── DEFAULT_COLLECTION_DAYS = 6
├── MAX_CATCHUP_WINDOWS = 3
├── AQL_TIMEOUT_SECONDS = 300
├── RETRYABLE_HTTP_STATUSES = (429, 500, 502, 503, 504)
├── _retry_with_backoff()        → Retry exponencial com Retry-After
└── _validate_json_response()    → Proteção contra respostas HTML

core/db.py  (MetricsDB — SQLite)
│
├── collection_runs              → Registro de cada execução
├── event_metrics                → Métricas por data source por janela
├── log_sources_inventory        → Inventário completo
├── save_event_metrics()         → Persiste resultados AQL
├── fill_zero_event_rows()       → Zero-fill para fontes inativas
├── get_daily_summary()          → GROUP BY logsource_id, MAX(logsource_name)
└── get_overall_daily_average()  → Agregação consolidada por logsource_id

core/report.py  (ReportGenerator)
│
├── daily CSV                    → Detalhamento diário (com logsource_id)
├── summary CSV                  → Médias diárias consolidadas
└── full text report             → Relatório completo com projeções

core/collection.py  (Loop de coleta)
│
├── run_collection_cycle()       → Um ciclo: AQL + save + zero-fill
│                                  Retorna -1 em caso de falha (não avança janela)
├── collect_inventory()          → Coleta inventário de log sources
└── main_collection_loop()       → Loop com janelas contíguas + catch-up com cap
                                   Só avança last_window_end_ms se ds_count >= 0

main.py  (Ponto de entrada)
│
└── main()                       → Orquestração completa
    ├── Parse args (subcomando qradar/splunk)
    ├── Config + env + getpass
    ├── test_connection()
    ├── Verifica DB existe (--report-only)
    ├── collect_inventory()
    ├── main_collection_loop()
    └── Geração de relatórios
```

---

## Suite de Testes

### Por que os testes existem?

Os testes são a **rede de segurança** do projeto. Como o script opera contra uma API real do QRadar — que exige infraestrutura, tokens e dados em produção — não é viável validar cada alteração manualmente. A suite de testes resolve isso usando **mocks** (simulações) para reproduzir o comportamento da API sem depender de um QRadar real.

**O que garante na prática:**

- **Correções não quebram funcionalidades existentes.** Se alguém alterar a query AQL, o cálculo de datas ou a lógica de retry, os testes detectam a regressão imediatamente.
- **Lógica matemática validada.** Projeções de volume dependem de zero-fill, janelas contíguas e catch-up com cap. Um erro sutil nessas áreas geraria relatórios de sizing incorretos para o Sentinel — e os testes verificam cada cenário de borda.
- **Documentação executável.** A tabela de cobertura abaixo funciona como especificação viva: descreve exatamente o que o script faz e o que é considerado comportamento correto.

### Pré-requisitos para executar os testes

| Requisito | Detalhes |
|---|---|
| **Python 3.8+** | Mesmo requisito do script principal |
| **`requests`** | Já instalado via `requirements.txt` |
| **Acesso ao QRadar** | **Não é necessário** — todos os testes usam mocks |

> **Nota:** Os testes estão divididos em `tests/test_core.py` (27 testes dos módulos compartilhados) e `tests/test_qradar.py` (15 testes específicos do QRadar). O total para o projeto é **63 testes** (incluindo testes do Splunk).

### Como executar

```bash
# Todos os testes (da raiz do repositório)
python -m unittest discover tests/ -v

# Apenas testes do QRadar
python -m unittest tests.test_qradar -v

# Apenas testes dos módulos compartilhados (core)
python -m unittest tests.test_core -v
```

### Cobertura dos testes QRadar (`tests/test_qradar.py` — 15 testes)

| Classe de Teste | Testes | O que valida |
|---|---|---|
| `TestCollectionDateBoundary` | 3 | `collection_date` via `window_end_ms - 1ms` (meia-noite, +1ms, meio-dia) |
| `TestAQLQueries` | 4 | `LOGSOURCETYPENAME(devicetype)`, half-open interval, GROUP BY correto |
| `TestTokenPrecedence` | 3 | Cadeia CLI > config > ENV |
| `TestArielAsyncFlow` | 2 | Fluxo Ariel completo (POST→poll→results) + Range header |
| `TestCheckResponse` | 2 | Mensagens acionáveis 401/403, 200 silencioso |
| `TestTestConnection` | 1 | `test_connection()` via `/system/about` |

### Cobertura dos testes Core (`tests/test_core.py` — 27 testes)

| Área | Testes | O que valida |
|---|---|---|
| Zero-fill | 2 | Zero-fill para fontes ausentes, skip para fontes presentes |
| Catch-up cap | 2 | Cap limita janela, gap dentro do limite mantido |
| Retry / Backoff | 2 | Retry em 500, sem retry em 401 |
| Collection cycle | 4 | Integração com DB real, falha retorna -1, sucesso sem dados retorna 0 |
| DB / Relatórios | 6 | GROUP BY logsource_id, get_daily_summary, get_overall_daily_average |
| Constantes | 5 | Sanidade: `DEFAULT_COLLECTION_DAYS=6`, `MAX_CATCHUP_WINDOWS=3`, etc. |
| Utilitários | 6 | math.ceil, validação JSON, janelas contíguas |

---

## Troubleshooting

| Problema | Causa provável | Solução |
|---|---|---|
| `HTTP 401 Unauthorized` | Token SEC inválido, expirado ou revogado | Gere novo token no QRadar Admin → Authorized Services |
| `HTTP 403 Forbidden` | Token válido mas sem permissões suficientes | Verifique User Role e Security Profile associados ao token |
| `ConnectionError` | URL incorreta ou sem acesso de rede | Verifique URL, porta 443 e firewalls/proxies |
| `SSL Error` / `SSLCertVerificationError` | Certificado auto-assinado | Não use `--verify-ssl` (padrão: desabilitado) |
| `Módulo 'requests' não encontrado` | Dependência não instalada | `pip install requests` ou `pip install -r requirements.txt` |
| `AQL com unparsed falhou; fazendo fallback` | Campo `isunparsed` indisponível no QRadar | **Normal** — o script continua sem métricas de unparsed |
| `Query AQL timeout` | QRadar sobrecarregado ou intervalo muito grande | Aumente `AQL_TIMEOUT_SECONDS` no código ou reduza `--interval` |
| `Catch-up excedeu limite` | Falhas consecutivas acumularam gap > 3 intervalos | Dados do gap são perdidos (registrado no log); coleta continua |
| Script parou/crashou — perdi tudo? | Queda de energia, terminal fechado, crash | **Não.** Dados salvos no SQLite — rode `--report-only` na mesma pasta para extrair relatórios de tudo que foi coletado |
| Dados vazios / sem resultados | Nenhum evento no período, ou log sources desativados | Verifique no QRadar se há eventos no período; use `--verbose` |

---

## Changelog

### v3.1 (2026-02-28) — Versão atual

Correções de bugs e melhorias de robustez:

| Correção | Impacto |
|---|---|
| `run_collection_cycle()` retorna **-1** em caso de falha | Falha de query AQL **não avança** `last_window_end_ms` — janela é retentada |
| `get_daily_summary()` GROUP BY `logsource_id` | Evita agrupamento incorreto quando `logsource_name` muda entre coletas |
| `math.ceil()` para total de coletas | Garante cobertura completa do período (última janela parcial incluída) |
| Verificação de existência do DB em `--report-only` | Erro claro se o arquivo `.db` não existe, em vez de criar DB vazio |
| Guard `None` em `get_log_source_types()` | Evita crash se API retorna `type_id: null` |
| Type narrowing em testes (Pylance) | `assert events is not None` antes de indexar resultado |

### v3.0 (2026-02-25) — Arquitetura modular

Refatoração completa para arquitetura modular:

| Mudança | Detalhes |
|---|---|
| ABC `SIEMClient` | Interface abstrata para todos os collectors SIEM |
| Módulos `core/` compartilhados | `utils.py`, `db.py`, `report.py`, `collection.py` |
| Ponto de entrada unificado | `python main.py qradar` / `python main.py splunk` |
| Suite de testes dividida | `test_core.py` (27) + `test_qradar.py` (15) + `test_splunk.py` (21) = 63 testes |

### v2.0 (2026-02-23)

Correções baseadas em validação rigorosa externa ([deep-research-report](deep-research-report.md)):

| Correção | Impacto |
|---|---|
| `LOGSOURCETYPENAME(devicetype)` em vez de `LOGSOURCETYPENAME(logsourceid)` | Nomes de tipo corretos na AQL |
| `GROUP BY logsourceid, devicetype` | Consistência com a função LOGSOURCETYPENAME |
| `fill_zero_event_rows()` | Projeções 24h corretas para fontes intermitentes |
| Catch-up com cap (`MAX_CATCHUP_WINDOWS=3`) | Evita queries AQL gigantes após falhas |
| `DEFAULT_COLLECTION_DAYS = 6` | Amostragem suficiente incluindo fins de semana |
| `collection_date` via `window_end_ms - 1ms` | Janela 23:00-00:00 atribuída ao dia correto |
| `_check_response()` com mensagens 401/403 | Diagnóstico imediato de erros de autenticação |
| `test_connection()` via `/system/about` | Validação proativa antes de iniciar coleta |
| Sem `Content-Type` em requests GET | Conformidade com padrão HTTP |
| Prompt seguro via `getpass` | Token não aparece na tela nem no histórico |
| Range header em `/ariel/searches/{id}/results` | Proteção contra respostas muito grandes |
| Suite de testes (31 testes) | Validação automatizada das correções |

### v1.0 (2026-02-23) — Versão inicial

- Coleta funcional via AQL com SQLite e relatórios CSV/TXT
- Retry com backoff exponencial
- Paginação de log sources via Range headers
- Parada graciosa via Ctrl+C

---

## Licença

Este projeto é licenciado sob a [MIT License](LICENSE).
