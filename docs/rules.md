# Regras de detecção

Consulte o catálogo com `vitaisk rules list` e uma definição com `vitaisk rules show ssh-fail-then-success`. Adicione arquivos `.yaml` ou `.yml` em `rules.d/` dentro do diretório de configuração. Cada arquivo contém uma lista. Um ID já existente substitui a regra anterior com o mesmo ID.

## Campos

| Campo | Comportamento |
| --- | --- |
| `id` | Identificador da regra. |
| `source`, `category` | Origem e categoria normalizadas. `category` aceita uma categoria ou uma lista. |
| `contains`, `regex` | Correspondência na mensagem sem distinção de maiúsculas. Em `contains`, basta um dos termos. |
| `equals` | Correspondência exata dos valores de campos do evento. |
| `severity` | `DEBUG`, `INFO`, `WARN`, `ERROR` ou `CRITICAL`. O padrão é `WARN`. |
| `group_by` | Campos que separam os grupos usados para contagem ou correlação. |
| `threshold`, `window` | Quantidade mínima de ocorrências e janela em segundos. O padrão de quantidade é 1. |
| `distinct` | Campo de que se contam valores distintos. |
| `followed_by` | Condição para o evento posterior. Aceita os mesmos campos de correspondência. |
| `match_window` | Intervalo máximo entre as ocorrências do primeiro estágio, em segundos. |
| `suggested_actions` | Lista de ações sugeridas exibida no alerta. |

Uma regra precisa de ao menos um campo de correspondência. Quando vários são definidos, todos precisam corresponder. Regras com contagens superiores a 1 ou com `followed_by` exigem uma janela positiva.

## Exemplo

```yaml
- id: service-restart-example
  source: system
  contains: ["scheduled restart job"]
  group_by: [host]
  threshold: 3
  window: 60
  severity: WARN
```

Para testar uma regra temporal, envie uma sequência de eventos normalizados, um objeto JSON por linha, com horários e campos de agrupamento representativos:

```bash
# Avalia as regras de detecção com os eventos sintéticos lidos do arquivo JSONL.
vitaisk rules test - < eventos-sinteticos.jsonl
```

Para inspecionar uma correspondência pontual:

```bash
# Avalia as regras de detecção com uma mensagem sintética de erro do kernel.
vitaisk rules test --source kernel 'EXT4-fs error on sda'
```
