# Google SecOps Log Ingestion Collector

> **Nota:** A partir da v3 (arquitetura modular), use `python main.py secops --sa-file ... --region ...` da raiz do repositório.
> O client Google SecOps está em `collectors/google_secops/client.py` e usa os módulos compartilhados de `core/`.

Módulo Python para coleta automatizada de métricas de ingestão de logs do **Google SecOps** (antigo Chronicle) via **Backstory API (UDM Search)**.
Projetado para **sizing e planejamento de migração para Microsoft Sentinel / Defender for Cloud**.

Roda continuamente por N dias (padrão: **6**), coleta métricas a cada intervalo configurável (padrão: **1 hora**) e gera relatórios detalhados (CSV + TXT) com médias diárias, projeções 24h e estimativas mensais por log type.

---

## Índice

1. [Pré-requisitos](#pré-requisitos)
2. [Instalação](#instalação)
3. [Modos de Execução](#modos-de-execução)
4. [Parâmetros de Linha de Comando](#parâmetros-de-linha-de-comando)
5. [Autenticação](#autenticação)
6. [O Que o Script Coleta](#o-que-o-script-coleta)
7. [Endpoints Regionais](#endpoints-regionais)
8. [Comportamento em Tempo de Execução](#comportamento-em-tempo-de-execução)
9. [Limites e Considerações da API](#limites-e-considerações-da-api)
10. [Relatórios Gerados](#relatórios-gerados)
11. [Arquitetura do Módulo](#arquitetura-do-módulo)
12. [Suite de Testes](#suite-de-testes)
13. [Troubleshooting](#troubleshooting)
14. [Referências](#referências)
15. [Licença](#licença)

---

## Pré-requisitos

### Ambiente de Execução
- **Python 3.8+** (recomendado 3.10+)
- **Módulo `requests`** para HTTP
- **Módulo `google-auth`** para autenticação via Service Account (recomendado)
- Acesso de rede (HTTPS/443) ao endpoint `backstory.googleapis.com` (ou endpoint regional)
- Sessão persistente recomendada (`screen`, `tmux` no Linux, ou tarefa em background no Windows)

### Credenciais do Google SecOps

Você precisará de uma **Service Account** do Google Cloud com permissões para acessar a API do Google SecOps.

| Permissão necessária | Escopo / Role |
|---|---|
| Chronicle Backstory API | `https://www.googleapis.com/auth/chronicle-backstory` |
| Acesso ao Google SecOps | Role `Chronicle API Viewer` ou superior |
| UDM Search | Incluído no escopo chronicle-backstory |

### Como criar a Service Account

1. Acesse o [Google Cloud Console](https://console.cloud.google.com/)
2. Navegue até **IAM & Admin** → **Service Accounts**
3. Clique em **Create Service Account**
4. Dê um nome descritivo (ex: `secops-log-collector`)
5. Atribua a role **Chronicle API Viewer** (ou `roles/chronicle.viewer`)
6. Clique em **Create Key** → **JSON** e baixe o arquivo
7. Guarde o arquivo JSON em local seguro — ele contém as credenciais

### Alternativa: Bearer Token

Para testes rápidos, você pode usar um Bearer Token pré-gerado:

```bash
# Gerar token via gcloud CLI (válido por ~1h)
gcloud auth print-access-token --scopes=https://www.googleapis.com/auth/chronicle-backstory
```

---

## Instalação

```bash
# 1. Clonar o repositório
git clone https://github.com/lsardim1/siem-log-collectors.git
cd siem-log-collectors

# 2. Instalar dependências base
pip install -r requirements.txt

# 3. Instalar google-auth (necessário para Service Account)
pip install google-auth
```

### Estrutura de arquivos do módulo

```
siem-log-collectors/
├── main.py                          # Ponto de entrada unificado
├── core/                            # Módulos compartilhados
│   ├── utils.py                     # Constantes e funções utilitárias
│   ├── db.py                        # MetricsDB (SQLite)
│   ├── report.py                    # Geração de relatórios
│   └── collection.py                # Loop de coleta e ciclos
├── collectors/
│   └── google_secops/
│       ├── __init__.py              # Package init
│       ├── client.py                # GoogleSecOpsClient (Backstory API)
│       └── README.md                # Este documento
├── tests/
│   ├── test_core.py                 # 40 testes (módulos compartilhados)
│   └── test_google_secops.py        # 45 testes (específicos Google SecOps)
├── requirements.txt                 # Dependências Python
└── README.md                        # README principal
```

### Arquivos gerados durante execução

```
siem-log-collectors/
├── secops_metrics.db                # Banco SQLite com todas as métricas
├── secops_collector.log             # Log de execução detalhado
├── config.json                      # (opcional) Criado via --create-config
└── reports/
    ├── secops_daily_report_<ts>.csv
    ├── secops_summary_report_<ts>.csv
    └── secops_full_report_<ts>.txt
```

---

## Modos de Execução

### Modo 1: Service Account JSON (recomendado para produção)

```bash
python main.py secops --sa-file /path/to/service-account.json --region us
```

### Modo 2: Bearer Token (para testes rápidos)

```bash
TOKEN=$(gcloud auth print-access-token --scopes=https://www.googleapis.com/auth/chronicle-backstory)
python main.py secops --token "$TOKEN" --region us
```

### Modo 3: Arquivo de configuração

```bash
# 1. Criar config de exemplo
python main.py secops --create-config

# 2. Editar config.json com suas credenciais

# 3. Executar com config
python main.py secops --config config.json
```

### Modo 4: Apenas relatórios (sem coleta)

```bash
python main.py secops --report-only --db-file secops_metrics.db
```

---

## Parâmetros de Linha de Comando

| Parâmetro | Tipo | Default | Descrição |
|---|---|---|---|
| `--sa-file` | str | — | Caminho para o arquivo JSON da Service Account |
| `--token` | str | — | Bearer Token pré-gerado (para testes) |
| `--region` | str | `us` | Região do Google SecOps (ver tabela abaixo) |
| `--config` | str | — | Arquivo de configuração JSON |
| `--days` | int | `6` | Duração da coleta em dias |
| `--interval` | float | `1` | Intervalo entre coletas em horas |
| `--db-file` | str | `secops_metrics.db` | Arquivo do banco SQLite |
| `--report-dir` | str | `reports` | Diretório para relatórios |
| `--report-only` | flag | — | Apenas gera relatórios (não coleta) |
| `--create-config` | flag | — | Cria arquivo de configuração de exemplo |
| `--verbose` | flag | — | Habilita logs detalhados (DEBUG) |

---

## Autenticação

### Prioridade de credenciais

O módulo segue a seguinte cadeia de prioridade para autenticação:

1. **CLI `--sa-file`** — Service Account JSON via argumento de linha de comando
2. **CLI `--token`** — Bearer Token via argumento de linha de comando
3. **Config `service_account_file`** — Service Account JSON via arquivo de configuração
4. **Config `auth_token`** — Bearer Token via arquivo de configuração

### Service Account (recomendado)

- Usa a biblioteca `google-auth` para gerenciar tokens automaticamente
- Tokens são renovados automaticamente antes de expirar
- Requer: `pip install google-auth`

### Bearer Token

- Token pré-gerado via `gcloud auth print-access-token`
- Não requer bibliotecas adicionais (apenas `requests`)
- **Atenção:** Tokens expiram após ~1 hora — use apenas para testes

---

## O Que o Script Coleta

### Fluxo de coleta

1. **Conexão:** Testa conectividade via UDM Search simples (1 evento, última 1h)
2. **Inventário:** Descobre log types existentes via UDM Search (últimas 24h)
3. **Métricas:** A cada intervalo (padrão 1h):
   - Executa UDM Search com query `metadata.event_type != ""` para toda a janela
   - Agrega eventos client-side por `metadata.logType` + `metadata.productName`
   - Salva contagens no SQLite por log type
4. **Zero-fill:** Log types sem dados na janela recebem contagem = 0
5. **Relatórios:** Gera CSV + TXT com médias diárias e projeções

### Campos coletados por log type

| Campo | Descrição |
|---|---|
| `logsourceid` | ID único determinístico via SHA-256(`log_type + product_name`) — estável entre reinícios |
| `log_source_name` | Nome: `"{product_name} ({vendor_name})"` |
| `log_source_type` | Log Type do Google SecOps (ex: `WINDOWS_EVENT`) |
| `aggregated_event_count` | Total de eventos no intervalo |
| `total_event_count` | Igual a `aggregated_event_count` |
| `total_payload_bytes` | `0.0` — não disponível via UDM Search |
| `avg_payload_bytes` | `0.0` — não disponível via UDM Search |

> **Nota:** A API UDM Search não retorna tamanho de payload por evento. As colunas de bytes são preenchidas com `0.0` mas a contagem de eventos é precisa (até o limite de 10.000 por janela).

---

## Endpoints Regionais

O Google SecOps suporta 19 endpoints regionais. Use o parâmetro `--region` para selecionar:

| Região | Endpoint |
|---|---|
| `us` (default) | `backstory.googleapis.com` |
| `europe` | `europe-backstory.googleapis.com` |
| `europe-west2` | `europe-west2-backstory.googleapis.com` |
| `europe-west3` | `europe-west3-backstory.googleapis.com` |
| `europe-west6` | `europe-west6-backstory.googleapis.com` |
| `europe-west9` | `europe-west9-backstory.googleapis.com` |
| `europe-west12` | `europe-west12-backstory.googleapis.com` |
| `europe-central2` | `europe-central2-backstory.googleapis.com` |
| `asia-south1` | `asia-south1-backstory.googleapis.com` |
| `asia-southeast1` | `asia-southeast1-backstory.googleapis.com` |
| `asia-southeast2` | `asia-southeast2-backstory.googleapis.com` |
| `asia-northeast1` | `asia-northeast1-backstory.googleapis.com` |
| `australia-southeast1` | `australia-southeast1-backstory.googleapis.com` |
| `me-central1` | `me-central1-backstory.googleapis.com` |
| `me-central2` | `me-central2-backstory.googleapis.com` |
| `me-west1` | `me-west1-backstory.googleapis.com` |
| `northamerica-northeast2` | `northamerica-northeast2-backstory.googleapis.com` |
| `southamerica-east1` | `southamerica-east1-backstory.googleapis.com` |
| `africa-south1` | `africa-south1-backstory.googleapis.com` |

### Exemplo para Brasil (São Paulo)

```bash
python main.py secops --sa-file sa.json --region southamerica-east1
```

---

## Comportamento em Tempo de Execução

### Ciclo típico (a cada intervalo)

```
[14:00:00] Coleta #1 — UDM Search [13:00:00 → 14:00:00]
           → 4 log types encontrados, 2.500 eventos totais
           → Salvando no SQLite...
           → Zero-fill: 2 log types sem dados nesta janela
           → Próxima coleta em 3600s (15:00:00)

[15:00:00] Coleta #2 — UDM Search [14:00:00 → 15:00:00]
           → ...
```

### Catch-up automático

Se o coletor for pausado e retomado, ele automaticamente busca dados das janelas perdidas:

- Máximo de **3 janelas** de catch-up por vez (configurável via `MAX_CATCHUP_WINDOWS`)
- Janelas são processadas sequencialmente com intervalo entre elas

### Parada graciosa

Pressione **Ctrl+C** para parar a coleta graciosamente. O coletor:
1. Finaliza a janela de coleta corrente
2. Gera relatórios finais
3. Fecha a conexão com o banco de dados

---

## Limites e Considerações da API

| Limite | Valor | Impacto |
|---|---|---|
| **Rate Limit** | 360 queries/hora | ~6 queries/min — suficiente para coleta horária |
| **Max eventos/query** | 10.000 | Ambientes de alto volume podem ter contagens truncadas |
| **Timeout** | 10 minutos | Queries grandes podem demorar — retry automático |
| **Janela máxima** | 90 dias | Queries não podem cobrir mais de 90 dias |

### Recomendações para alto volume

Se o ambiente Google SecOps processa mais de 10.000 eventos por hora:

```bash
# Use intervalos menores (15 min ao invés de 1h)
python main.py secops --sa-file sa.json --interval 0.25

# Ou intervalos de 30 min
python main.py secops --sa-file sa.json --interval 0.5
```

O coletor exibe um **warning** no log quando `moreDataAvailable=True`, indicando que a contagem pode estar truncada.

---

## Relatórios Gerados

### 1. Relatório diário (CSV)
```
reports/secops_daily_report_<timestamp>.csv
```
Contém médias por log type por dia de coleta.

### 2. Relatório resumo (CSV)
```
reports/secops_summary_report_<timestamp>.csv
```
Contém projeções 24h e estimativas mensais por log type.

### 3. Relatório completo (TXT)
```
reports/secops_full_report_<timestamp>.txt
```
Combinação dos dados diários e resumo em formato legível.

---

## Arquitetura do Módulo

```
GoogleSecOpsClient (client.py)
    ├── __init__()        → Auth: Service Account JSON ou Bearer Token
    ├── _init_service_account()  → google.oauth2 + AuthorizedSession
    ├── _check_response() → 401/403/429 com mensagens acionáveis
    ├── _get()            → GET com retry e backoff exponencial
    ├── test_connection() → UDM Search (1 evento, última 1h)
    ├── udm_search()      → GET /v1/events:udmSearch
    ├── get_event_metrics_window()  → Agregação client-side por log_type
    └── get_log_types()   → Descoberta de log types (UDM Search 24h)

Module functions:
    ├── collect_inventory()         → Salva log types no SQLite
    ├── update_inventory_from_results()  → Callback pós-coleta
    └── create_sample_config()      → Gera config.json de exemplo
```

### Dependências internas

```
collectors/google_secops/client.py
    → collectors/base.py     (ABC SIEMClient)
    → core/utils.py          (_retry_with_backoff, ErrorCounter)
    → core/db.py             (MetricsDB)
    → core/collection.py     (run_collection_cycle, main_collection_loop)
    → core/report.py         (ReportGenerator)
```

---

## Suite de Testes

45 testes unitários cobrindo todas as funcionalidades:

```bash
# Rodar apenas testes do Google SecOps
python -m pytest tests/test_google_secops.py -v

# Ou via unittest
python -m unittest tests.test_google_secops -v
```

### Categorias de teste

| Categoria | Testes | Cobertura |
|---|---|---|
| Auth modes | 6 | Token, Service Account, sem credenciais, import error, region |
| _check_response | 4 | 401, 403, 429, 200 |
| test_connection | 5 | Sucesso, vazio, HTTP 401/403, erro de conexão |
| UDM Search | 4 | Sucesso, limit cap, HTTP error, erro inesperado |
| get_event_metrics_window | 8 | Agregação single/multi, vazio, None, truncamento, formato, keys, ISO time |
| get_log_types | 4 | Descoberta, vazio, None, tipos vazios |
| Inventory | 5 | Coleta, vazio, erro, update callback, lista vazia |
| Config | 1 | JSON válido |
| Constants | 6 | Scopes, max events, timeout, endpoints |
| _stable_id | 1 | logsourceid determinístico via SHA-256 |
| Bytes zero | 1 | bytes sempre 0 (não disponível via UDM) |
| **Total** | **45** | |

Todos os testes são 100% mocked — não fazem chamadas reais à API.

---

## Troubleshooting

### Erros comuns

| Erro | Causa | Solução |
|---|---|---|
| `ImportError: google-auth` | Pacote não instalado | `pip install google-auth` |
| `HTTP 401 Unauthorized` | Credenciais inválidas ou expiradas | Verifique o arquivo Service Account ou gere novo token |
| `HTTP 403 Forbidden` | Service Account sem permissões | Atribua a role `Chronicle API Viewer` no IAM |
| `HTTP 429 RESOURCE_EXHAUSTED` | Rate limit excedido (360 QPH) | Aumente o intervalo de coleta (`--interval 2`) |
| `ValueError: Forneça service_account_file...` | Nenhuma credencial fornecida | Passe `--sa-file` ou `--token` |
| `moreDataAvailable warning` | Mais de 10.000 eventos na janela | Use `--interval 0.25` para janelas de 15 min |
| `ConnectionError` | Sem acesso ao endpoint | Verifique firewall/proxy para `backstory.googleapis.com` |

### Verificar conectividade

```bash
# Testar acesso ao endpoint (sem autenticação)
curl -I https://backstory.googleapis.com

# Testar com token
curl -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://backstory.googleapis.com/v1/events:udmSearch?query=metadata.event_type+!%3D+%22%22&limit=1&time_range.start_time=$(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ)&time_range.end_time=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
```

---

## Referências

- [Google SecOps API Documentation](https://cloud.google.com/chronicle/docs/reference)
- [Backstory Search API](https://cloud.google.com/chronicle/docs/reference/search-api)
- [UDM Search API](https://cloud.google.com/chronicle/docs/reference/search-api#udm_search)
- [Regional Endpoints](https://cloud.google.com/chronicle/docs/reference/search-api#regional_endpoints)
- [Google Auth Library for Python](https://google-auth.readthedocs.io/)
- [Service Account Authentication](https://cloud.google.com/iam/docs/service-accounts)

---

## Licença

MIT License — Copyright (c) 2025 lsardim1. Veja [LICENSE](../../LICENSE).
