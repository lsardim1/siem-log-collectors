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
| **CLI** | `argparse` + `getpass` para parâmetros e credenciais |
| **API Client** | Autenticação, retry com backoff, SSL configurável |
| **Collection Engine** | Janelas de 1h, catch-up cap, zero-fill, parada graciosa |
| **MetricsDB** | SQLite com tabelas `hourly_metrics` e `collection_state` |
| **ReportGenerator** | CSV (UTF-8 BOM, separador `;`) + TXT (resumo terminal) |

### 3. Use a convenção de nomes

```
collectors/meu-siem/
├── meu_siem_log_collector_v2.py      # Script principal
├── test_meu_siem_log_collector.py    # Testes unitários
├── requirements.txt                   # Dependências
└── README.md                          # Documentação do coletor
```

### 4. Implemente as constantes padrão

```python
# Configurações que todos os coletores devem ter
COLLECTION_DAYS = 6          # Dias de coleta (evita dia parcial)
WINDOW_SECONDS = 3600        # Janela de 1 hora
MAX_CATCHUP_WINDOWS = 3      # Cap de recuperação por ciclo
MAX_RETRIES = 3              # Tentativas com backoff
INITIAL_BACKOFF = 2          # Segundos iniciais de backoff
SLEEP_BETWEEN_CYCLES = 60    # Segundos entre ciclos
```

### 5. Implemente o schema do SQLite

```python
# Tabelas obrigatórias
"""
CREATE TABLE IF NOT EXISTS hourly_metrics (
    source_type TEXT,
    window_start TEXT,
    window_end TEXT,
    event_count INTEGER,
    byte_count INTEGER,
    PRIMARY KEY (source_type, window_start)
)

CREATE TABLE IF NOT EXISTS collection_state (
    key TEXT PRIMARY KEY,
    value TEXT
)
"""
```

### 6. Escreva os testes

- **100% mocked** — sem dependência do SIEM real
- Use `unittest.mock.patch` para simular respostas da API
- Cubra: autenticação, coleta normal, zero-fill, catch-up, retry, parada graciosa, relatórios
- Mínimo: 20 testes

---

## 🧪 Rodando os testes

```bash
cd collectors/meu-siem
python -m pytest test_meu_siem_log_collector.py -v
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

Abra uma [Issue](https://github.com/SEU-USUARIO/siem-log-collectors/issues) no repositório.
