# 🤝 Contribuindo para o siem-log-collectors

Obrigado pelo interesse em contribuir! Este guia explica como adicionar suporte a um novo SIEM ou melhorar os coletores existentes.

---

## 📋 Pré-requisitos

- Python 3.8+ (recomendado 3.10+)
- `pip` para instalar dependências
- Familiaridade com REST APIs do SIEM-alvo
- Conhecimento básico de `unittest` / `pytest`

---

## 🏗️ Adicionando um novo SIEM

### 1. Crie a pasta do coletor

```bash
mkdir -p collectors/meu-siem
```

### 2. Siga a arquitetura padrão

Todos os coletores devem implementar os seguintes componentes:

| Componente | Responsabilidade |
|-----------|------------------|
| **SIEMClient (ABC)** | Herdar de `collectors/base.py` e implementar `test_connection()` e `get_event_metrics_window()` |
| **collect_inventory()** | Função para coletar inventário de log sources/indexes |
| **create_sample_config()** | Gerar `config.json` de exemplo |
| **Subcommand em main.py** | `run_<siem>(args)` + `build_parser()` com subparser |
| **Testes unitários** | Em `tests/test_<siem>.py`, 100% mocked |

### 3. Use a convenção de nomes

```
collectors/<meu-siem>/
├── __init__.py
├── client.py              # <MeuSIEM>Client(SIEMClient) + collect_inventory + create_sample_config
└── README.md              # Documentação do coletor

tests/
└── test_<meu_siem>.py      # Testes unitários (mínimo 15)
```

### 4. Implemente as constantes padrão

Constantes compartilhadas já estão em `core/utils.py`:

```python
# core/utils.py (já existentes — não redefina)
DEFAULT_COLLECTION_DAYS = 6          # Dias de coleta (evita dia parcial)
DEFAULT_INTERVAL_HOURS = 1           # Intervalo de coleta em horas
MAX_CATCHUP_WINDOWS = 3              # Cap de recuperação por ciclo
RETRY_MAX_ATTEMPTS = 3               # Tentativas com backoff
RETRY_BASE_DELAY = 2                 # Segundos iniciais de backoff
RETRYABLE_HTTP_STATUSES = (429, 500, 502, 503, 504)
```

Seu client pode ter constantes específicas (ex: `AQL_TIMEOUT_SECONDS`, `SPL_TIMEOUT_SECONDS`).

### 5. Use o schema SQLite existente

O `MetricsDB` em `core/db.py` já fornece as tabelas necessárias:

```python
# Tabelas existentes em core/db.py (NÃO redefina)
"""
collection_runs    — Registro de cada execução de coleta
event_metrics      — Métricas por data source por janela
log_sources_inventory — Inventário de sources/indexes
"""

# Formato unificado para inventário (usado por save_log_sources_inventory):
# {"logsource_id": int, "name": str, "type_name": str,
#  "type_id": int, "enabled": bool, "description": str}
```

### 6. Escreva os testes

- **100% mocked** — sem dependência do SIEM real
- Use `unittest.mock.patch` para simular respostas da API
- Cubra: autenticação, coleta normal, zero-fill, catch-up, retry, parada graciosa, relatórios
- Mínimo: 15 testes

---

## 🧪 Rodando os testes

```bash
# Da raiz do projeto
python -m unittest discover tests/ -v
```

Todos os testes devem passar **sem acesso ao SIEM** (100% offline com mocks).

---

## 📝 Checklist para PR

Antes de enviar seu Pull Request, verifique:

- [ ] Coletor segue a arquitetura padrão (MetricsDB, ReportGenerator, etc.)
- [ ] Testes unitários cobrem cenários principais (mínimo 20 testes)
- [ ] Todos os testes passam (`python -m pytest -v`)
- [ ] `requirements.txt` lista todas as dependências
- [ ] `README.md` do coletor documenta: instalação, uso, parâmetros, exemplos
- [ ] Nenhuma credencial hardcoded no código
- [ ] Credenciais são coletadas via `getpass` ou variáveis de ambiente
- [ ] Sem erros de linting (`pylint` / `flake8`)
- [ ] Root `README.md` atualizado com o novo SIEM na matriz

---

## 🔀 Fluxo de trabalho Git

1. **Fork** o repositório
2. Crie uma **branch** descritiva: `feature/elastic-collector`
3. Faça **commits** atômicos e descritivos
4. Abra um **Pull Request** com:
   - Descrição do SIEM e API usada
   - Print/log de uma execução de teste
   - Screenshot do relatório gerado (se possível)

---

## 💬 Dúvidas?

Abra uma [Issue](https://github.com/lsardim1/siem-log-collectors/issues) no repositório.
