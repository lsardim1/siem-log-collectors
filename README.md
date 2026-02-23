# 📊 SIEM Log Collectors

**Coletores de ingestão histórica para migração de SIEMs legados para o Microsoft Sentinel.**

Cada coletor extrai logs do SIEM de origem via API REST, gera relatórios de volume (CSV + TXT) e armazena métricas em SQLite — tudo isso para dimensionar corretamente o workspace do Sentinel antes da migração.

---

## 🎯 Para que serve?

Quando você está migrando de um SIEM (QRadar, Splunk, etc.) para o **Microsoft Sentinel**, a primeira pergunta é:

> _"Quantos GB/dia eu ingiro por log source? Qual o tamanho do meu ambiente?"_

Esses coletores respondem essa pergunta automaticamente, gerando um relatório detalhado de volume por log source type, pronto para importar no Excel e calcular o custo do Sentinel.

---

## 📋 Matriz de SIEMs Suportados

| SIEM | Status | Pasta | API | Testes |
|------|--------|-------|-----|--------|
| **IBM QRadar** | ✅ Pronto | [`collectors/qradar/`](collectors/qradar/) | REST API v26.0 (AQL + Ariel) | 18 testes |
| **Splunk Enterprise** | ✅ Pronto | [`collectors/splunk/`](collectors/splunk/) | REST API v2 (SPL + Search Jobs) | 24 testes |
| **Google SecOps** | ✅ Pronto | [`collectors/google_secops/`](collectors/google_secops/) | Backstory API v1 (UDM Search) | 45 testes |
| **Core Compartilhado** | ✅ Pronto | [`core/`](core/) | — | 40 testes |
| **Elastic Security** | 📋 Planejado | — | Elasticsearch API | — |

---

## 🏗️ Arquitetura Modular

O projeto utiliza uma **arquitetura modular** com código compartilhado em `core/` e módulos SIEM-específicos em `collectors/`:

```
┌─────────────────────────────────────────────┐
│        main.py (Unified Entry Point)        │
│  python main.py qradar --url ... --token .. │
│  python main.py splunk --url ... --token .. │
│  python main.py secops --sa-file ... --rg.. │
├─────────────────────────────────────────────┤
│        core/ (Shared Modules)               │
│  ├── utils.py      ErrorCounter, retry,     │
│  │                 signal handlers          │
│  ├── db.py         MetricsDB (SQLite)       │
│  ├── report.py     ReportGenerator (CSV+TXT)│
│  └── collection.py run_collection_cycle,    │
│                    main_collection_loop      │
├─────────────────────────────────────────────┤
│        collectors/ (SIEM-specific)          │
│  ├── base.py       SIEMClient ABC           │
│  ├── qradar/       QRadarClient (AQL)       │
│  ├── splunk/       SplunkClient (SPL)       │
│  └── google_secops/ GoogleSecOpsClient(UDM) │
└─────────────────────────────────────────────┘
```

### Características comuns

| Feature | Detalhe |
|---------|---------|
| **Janelas de 1h** | Coleta hora a hora para granularidade e resiliência |
| **Zero-fill** | Registra `0 bytes` para janelas sem eventos (evita buracos no relatório) |
| **Catch-up cap** | Máximo 3 janelas por ciclo ao recuperar atraso |
| **Retry com backoff** | 3 tentativas com espera exponencial (2s → 4s → 8s) |
| **Parada graciosa** | Ctrl+C salva estado no SQLite — retoma de onde parou |
| **Relatório CSV** | Pronto para Excel com BOM UTF-8 e separador `;` |
| **Métricas SQLite** | Banco local sobrevive a quedas e permite re-geração de relatórios |
| **collection_days** | Padrão 6 dias (evita "dia parcial" nas médias) |
| **GROUP BY id** | Agrupamento por `logsource_id` (evita mistura se fontes tiverem nomes iguais ou forem renomeadas) |
| **Falha ≠ avança** | Se a query falha, a janela **não avança** — catch-up automático no próximo ciclo |
| **Status tracking** | Corridas com falha são marcadas como `status='failed'` no banco |
| **Enabled-only zero-fill** | Apenas fontes com `enabled=1` participam do zero-fill |
| **Ariel results limit** | Máximo 50.000 resultados por query AQL; warning se atingido |
| **SPL results limit** | Máximo 10.000 resultados por query SPL; warning se atingido |
| **logsource_id estável** | Splunk e SecOps usam SHA-256 (`_stable_id()`) em vez de `hash()` — IDs determinísticos entre reinícios |
| **NOTAS por SIEM** | Seção NOTAS no relatório .txt com texto específico por SIEM (bytes, coalescing, limitações) |

### ⚠️ Trade-off: Catch-up cap

Após falhas consecutivas de conexão, o coletor tenta recuperar ("catch-up") a janela de tempo perdida. Porém, para evitar queries AQL/SPL gigantes que sobrecarregariam o SIEM, existe um **cap de segurança** (`MAX_CATCHUP_WINDOWS = 3`):

- Se o gap acumulado for **≤ 3× o intervalo** (ex: ≤ 3h com intervalo de 1h), o catch-up coleta toda a janela perdida normalmente.
- Se o gap **exceder 3× o intervalo**, a janela é recortada e **os dados do período mais antigo são descartados**. O coletor registra o range perdido no log e segue em frente.

**Isso é intencional:** prioriza-se "andar para frente" com dados recentes em vez de tentar um backfill total que poderia causar timeout ou erro de memória no SIEM. Se precisar de backfill completo, ajuste `MAX_CATCHUP_WINDOWS` em `core/utils.py` ou execute o coletor com janela retroativa manual.

---

## 🚀 Quick Start

### 1. Clone o repositório

```bash
git clone https://github.com/lsardim1/siem-log-collectors.git
cd siem-log-collectors
pip install -r requirements.txt
```

### 2. Execute o coletor

```bash
# QRadar
python main.py qradar --url https://qradar:443 --token SEU_TOKEN

# Splunk (Bearer Token)
python main.py splunk --url https://splunk:8089 --token SEU_TOKEN

# Splunk (Basic Auth)
python main.py splunk --url https://splunk:8089 --username admin --password SENHA

# Google SecOps (Service Account)
python main.py secops --sa-file /path/to/sa.json --region us

# Google SecOps (Bearer Token)
python main.py secops --token $(gcloud auth print-access-token) --region southamerica-east1

# Gerar apenas relatório de DB existente
python main.py qradar --report-only --db-file qradar_metrics.db

# Criar config de exemplo
python main.py splunk --create-config
```

### 3. Confira os relatórios

```
reports/
├── <siem>_daily_report_YYYYMMDD_HHMMSS.csv    ← Detalhamento diário (Excel-ready)
├── <siem>_summary_report_YYYYMMDD_HHMMSS.csv  ← Média diária por source
└── <siem>_full_report_YYYYMMDD_HHMMSS.txt     ← Resumo completo em texto
```

---

## 🧪 Rodando os Testes

Todos os 127 testes rodam offline com `unittest.mock`:

```bash
python -m unittest discover tests/ -v
```

> **Nota:** Não é necessário ter QRadar, Splunk ou Google SecOps para rodar os testes.

---

## 📁 Estrutura do Repositório

```
siem-log-collectors/
├── main.py                      ← Entry point unificado
├── requirements.txt             ← Dependências (requests, urllib3)
├── README.md                    ← Você está aqui
├── LICENSE                      ← MIT
├── CONTRIBUTING.md              ← Como contribuir / adicionar novo SIEM
├── core/                        ← Módulos compartilhados
│   ├── __init__.py
│   ├── utils.py                 ← ErrorCounter, retry, signal handlers
│   ├── db.py                    ← MetricsDB (SQLite)
│   ├── report.py                ← ReportGenerator (CSV + TXT)
│   └── collection.py            ← run_collection_cycle, main_loop
├── collectors/                  ← Módulos SIEM-específicos
│   ├── __init__.py
│   ├── base.py                  ← SIEMClient ABC (interface)
│   ├── qradar/
│   │   ├── __init__.py
│   │   ├── client.py            ← QRadarClient (AQL, Ariel)
│   │   └── README.md
│   ├── splunk/
│   │   ├── __init__.py
│   │   ├── client.py            ← SplunkClient (SPL, Search Jobs v2)
│   │   └── README.md
│   └── google_secops/
│       ├── __init__.py
│       ├── client.py            ← GoogleSecOpsClient (UDM Search)
│       └── README.md
├── tests/                       ← Suíte de testes unificada
│   ├── __init__.py
│   ├── conftest.py
│   ├── test_core.py             ← 40 testes (shared modules)
│   ├── test_qradar.py           ← 18 testes (QRadar client)
│   ├── test_splunk.py           ← 24 testes (Splunk client)
│   └── test_google_secops.py    ← 45 testes (Google SecOps client)
└── docs/
    └── architecture.md          ← Detalhes da arquitetura modular
```

---

## 🤝 Contribuindo

Quer adicionar suporte a um novo SIEM? Veja o [CONTRIBUTING.md](CONTRIBUTING.md) com o passo a passo e o template de coletor.

---

## 📝 Licença

Este projeto está licenciado sob a [MIT License](LICENSE).

---

## 💡 Dicas

- **tmux/screen:** Para coletas longas (6+ dias), rode dentro de um `tmux` ou `screen` para não perder a sessão SSH.
- **Ctrl+C seguro:** A coleta pode ser interrompida a qualquer momento — o estado é salvo no SQLite e retomado na próxima execução.
- **Excel:** Abra o CSV no Excel com "Dados → De Texto/CSV" para manter a codificação UTF-8 correta.
- **Sizing do Sentinel:** Use as colunas `avg_gb_per_day` e `peak_gb_per_day` do CSV para calcular o custo no [Azure Pricing Calculator](https://azure.microsoft.com/pricing/calculator/).
