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
| **IBM QRadar** | ✅ Pronto | [`collectors/qradar/`](collectors/qradar/) | REST API v26.0 (AQL + Ariel) | 31 testes |
| **Splunk Enterprise** | ✅ Pronto | [`collectors/splunk/`](collectors/splunk/) | REST API (SPL + Search Jobs) | 34 testes |
| **Google SecOps (Chronicle)** | 🔜 Em desenvolvimento | [`collectors/google-secops/`](collectors/google-secops/) | Chronicle API | — |
| **Elastic Security** | 📋 Planejado | — | Elasticsearch API | — |

---

## 🏗️ Arquitetura Compartilhada

Todos os coletores seguem a **mesma arquitetura** para facilitar manutenção e contribuição:

```
┌─────────────────────────────────────────────┐
│              CLI (argparse + getpass)        │
│  ─ Prompts interativos para URL e Token     │
├─────────────────────────────────────────────┤
│           SIEM API Client                   │
│  ─ Autenticação (token / basic)             │
│  ─ Retry com backoff exponencial            │
│  ─ SSL configurável (--no-verify-ssl)       │
├─────────────────────────────────────────────┤
│         Collection Engine                   │
│  ─ Janelas contíguas de 1 hora              │
│  ─ Catch-up cap (MAX_CATCHUP_WINDOWS=3)     │
│  ─ Zero-fill para janelas sem dados         │
│  ─ Parada graciosa (Ctrl+C / SIGINT)        │
├─────────────────────────────────────────────┤
│           MetricsDB (SQLite)                │
│  ─ hourly_metrics + collection_state        │
│  ─ Idempotente (INSERT OR REPLACE)          │
│  ─ Sobrevive a reinícios                    │
├─────────────────────────────────────────────┤
│         ReportGenerator                     │
│  ─ CSV (Excel-ready, UTF-8 BOM)             │
│  ─ TXT (resumo legível no terminal)         │
│  ─ Métricas: avg/peak GB/day por source     │
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

---

## 🚀 Quick Start

### 1. Clone o repositório

```bash
git clone https://github.com/SEU-USUARIO/siem-log-collectors.git
cd siem-log-collectors
```

### 2. Escolha o coletor

```bash
# QRadar
cd collectors/qradar
pip install -r requirements.txt
python qradar_log_collector_v2.py

# Splunk
cd collectors/splunk
pip install -r requirements.txt
python splunk_log_collector_v2.py
```

### 3. Siga os prompts interativos

Cada coletor pergunta URL, token/credenciais e parâmetros via terminal (sem expor senhas no histórico do shell).

### 4. Confira os relatórios

```
reports/
├── ingestao_<SIEM>_YYYYMMDD_HHMMSS.csv   ← Excel-ready
└── ingestao_<SIEM>_YYYYMMDD_HHMMSS.txt   ← Resumo para terminal
```

---

## 🧪 Rodando os Testes

Cada coletor tem sua suíte de testes unitários (100% mocked, sem precisar de acesso ao SIEM):

```bash
# QRadar (31 testes)
cd collectors/qradar
python -m pytest test_qradar_log_collector.py -v

# Splunk (34 testes)
cd collectors/splunk
python -m pytest test_splunk_log_collector.py -v
```

> **Dica:** Todos os testes rodam offline com `unittest.mock` — não é necessário ter QRadar ou Splunk instalados.

---

## 📁 Estrutura do Repositório

```
siem-log-collectors/
├── README.md                    ← Você está aqui
├── LICENSE                      ← MIT
├── .gitignore                   ← Python + artefatos de execução
├── CONTRIBUTING.md              ← Como contribuir / adicionar novo SIEM
├── collectors/
│   ├── qradar/                  ← IBM QRadar collector
│   │   ├── qradar_log_collector_v2.py
│   │   ├── test_qradar_log_collector.py
│   │   ├── requirements.txt
│   │   └── README.md
│   ├── splunk/                  ← Splunk Enterprise collector
│   │   ├── splunk_log_collector_v2.py
│   │   ├── test_splunk_log_collector.py
│   │   ├── requirements.txt
│   │   └── README.md
│   └── google-secops/           ← Google SecOps (Chronicle) — Em desenvolvimento
│       └── README.md
└── docs/
    └── architecture.md          ← Detalhes da arquitetura compartilhada
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
