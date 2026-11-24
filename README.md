# VitaisK

```text
'##::::'##:'####:'########::::'###::::'####::'######::'##:::'##:
 ##:::: ##:. ##::... ##..::::'## ##:::. ##::'##... ##: ##::'##::
 ##:::: ##:: ##::::: ##:::::'##:. ##::: ##:: ##:::..:: ##:'##:::
 ##:::: ##:: ##::::: ##::::'##:::. ##:: ##::. ######:: #####::::
. ##:: ##::: ##::::: ##:::: #########:: ##:::..... ##: ##. ##:::
:. ## ##:::: ##::::: ##:::: ##.... ##:: ##::'##::: ##: ##:. ##::
::. ###::::'####:::: ##:::: ##:::: ##:'####:. ######:: ##::. ##:
:::...:::::....:::::..:::::..:::::..::....:::......:::..::::..::
```

Monitor local de sinais vitais do Linux. O painel acompanha o pulso dos eventos em tempo real, mostra CPU, RAM e disco e destaca alertas por gravidade.

**Status:** alfa. A cobertura varia com as fontes disponíveis no host. O catálogo está em expansão.

## Metasploitable 2

- [Rodar o VitaisK Legacy na VM pelo console do VirtualBox, sem SSH](legacy/README.md#pelo-console-do-virtualbox-sem-ssh)
- [Instalação, painel no Kali e testes do laboratório](legacy/README.md)

## Requisitos e instalação

Use Linux com **Python 3.10 ou superior**, `pip` e suporte a `venv`. Em distribuições que empacotam esses componentes separadamente, instale-os pelo gerenciador de pacotes. Para clonar o repositório, você também precisa de Git e acesso ao repositório.

```bash
# Baixa o código do VitaisK do GitHub para uma pasta local.
git clone https://github.com/Henr1sky/VitaisK-Metasploitable.git

# Entra na pasta do projeto recém-clonado.
cd VitaisK-Metasploitable

# Cria um ambiente virtual Python para isolar as dependências do projeto.
python3 -m venv .venv

# Ativa o ambiente virtual no terminal atual.
source .venv/bin/activate

# Instala o VitaisK e suas dependências no ambiente virtual ativo.
python -m pip install .

# Verifica o ambiente, as ferramentas disponíveis e os caminhos de configuração.
vitaisk doctor

# Inicia o monitoramento com a interface em português.
vitaisk --lang pt watch
```

O `pip install .` instala as dependências Python declaradas no [pyproject.toml](pyproject.toml): Click (CLI), Rich (TUI), PyYAML (configuração e regras), psutil (métricas) e python-dateutil (datas dos logs). O ambiente virtual isola essas bibliotecas do Python do sistema.

| Recurso opcional do Linux | Quando é necessário |
| --- | --- |
| `journalctl` | Para acompanhar o journal em sistemas com systemd. O usuário precisa ter acesso aos registros que deseja acompanhar. |
| `ss` do iproute2 | Para observar conexões de rede. As informações disponíveis dependem das permissões do usuário. |
| `auditd` ou log de auditoria legível | Para acompanhar eventos de auditoria. Configure `audit_log_path` se o arquivo estiver em outro local. |
| `tcpdump` | Para a captura de pacotes sob demanda ou a amostragem contínua opcional. A captura depende das permissões da interface. |

Comece executando `vitaisk doctor` como seu usuário normal. No painel, pressione **C** para ver os coletores inicializados e seu estado. Use `vitaisk --help` ou `vitaisk watch --help` para consultar as opções. `--lang` aceita `pt`, `en` e `auto` e vem antes do subcomando.

## Coletores

O catálogo abaixo lista os nove coletores implementados. A quantidade ativa depende da configuração, das ferramentas instaladas, dos arquivos presentes e das permissões do usuário.

| Coletor | O que acompanha | Chave de configuração |
| --- | --- | --- |
| Journal | Eventos de sistema, autenticação, kernel e firewall registrados no journal. | `journal_enabled` |
| Syslog | `/var/log/syslog` ou `/var/log/messages`. | `syslog_enabled` |
| Autenticação | `/var/log/auth.log` ou `/var/log/secure`. | `auth_enabled` |
| Kernel | `/var/log/kern.log` ou `/var/log/kernel.log`. | `kern_enabled` |
| Firewall | `/var/log/ufw.log` ou `/var/log/firewall.log`. | `firewall_enabled` |
| Auditoria | `/var/log/audit/audit.log` por padrão. | `audit_enabled` e `audit_log_path` |
| Métricas | CPU, RAM, disco, carga e processos via psutil. | `metrics_enabled` |
| Conexões | Mudanças na tabela de conexões do `ss`. | `connections_enabled` |
| Amostragem de pacotes | Parte dos pacotes TCP SYN sem ACK observados com `tcpdump`. Desativada por padrão. | `network_sniff_enabled` |

Os rótulos de origem dos filtros são `system`, `auth`, `kernel`, `firewall`, `audit`, `metrics` e `network`. Um coletor pode gerar mais de uma origem. Por exemplo, registros do journal podem entrar como `auth` ou `kernel`.

## Painel e modo em fluxo

```bash
# Inicia o monitor com as preferências salvas. O padrão é o painel Importantes.
vitaisk watch

# Abre a visão Tudo, que inclui eventos de qualquer gravidade permitida pelos filtros.
vitaisk watch --view all

# Abre a visão Anomalias, que exibe apenas eventos com alertas.
vitaisk watch --view anomalies

# Imprime os eventos em linhas contínuas no terminal, com a visão Tudo.
vitaisk watch --mode stream --view all
```

O painel abre em **Importantes**, que inclui eventos de nível `WARN` ou superior e eventos com alertas. **Tudo** exibe todos os eventos recebidos que correspondem aos filtros. **Anomalias** exibe os eventos com alertas. Com a saída redirecionada para um pipe ou arquivo, o VitaisK usa o modo em fluxo.

O pulso mostra o volume por segundo. Verde indica `DEBUG/INFO`, amarelo indica `WARN` e vermelho indica `ERROR/CRITICAL`. Os contadores acumulam os eventos da sessão por gravidade. Cada evento conta uma vez no maior nível entre o evento e seus alertas, mesmo se estiver oculto na lista.

| Tecla | Ação |
| --- | --- |
| ← / → ou 1 / 2 / 3 | Alternar entre Importantes, Tudo e Anomalias. |
| ↑ / ↓ ou Page Up / Page Down | Navegar pelo histórico enquanto a coleta continua. |
| Enter | Abrir o evento e as evidências dos alertas. |
| Espaço / Home | Alternar entre histórico e ao vivo com Espaço ou voltar ao vivo com Home. |
| F / `/` | Abrir os filtros ou ir direto à busca na mensagem. |
| C / I / ? | Ver coletores, trocar o idioma da sessão ou abrir a ajuda. |
| Esc / Q | Voltar de um painel ou encerrar o monitor a partir da tela principal. |

## Filtros e perfis

| Opção | Como funciona |
| --- | --- |
| `--view important\|all\|anomalies` | Escolhe a visualização inicial. `--only-anomalies` é um atalho para exibir anomalias. |
| `--level DEBUG\|INFO\|WARN\|ERROR\|CRITICAL` | Define a gravidade mínima, considerando os alertas associados. |
| `--source ORIGEM` | Limita às origens indicadas. Pode ser repetida e considera as fontes que contribuíram para a correlação. |
| `--grep REGEX` | Inclui mensagens que correspondem à expressão regular, sem distinguir maiúsculas de minúsculas. |
| `--ignore REGEX` | Oculta mensagens que correspondem ao padrão. Pode ser repetida. |
| `--ip ENDEREÇO` | Filtra pelo IP de origem ou destino registrado no evento. Aceita IPv4 e IPv6. |
| `--profile NOME` | Aplica uma combinação de filtros definida no arquivo de configuração. |

```bash
# Exibe eventos de autenticação ou firewall com gravidade WARN ou superior.
vitaisk watch --view all --source auth --source firewall --level WARN

# Mostra em fluxo as mensagens com ssh ou sudo, excluindo as que contêm session closed.
vitaisk watch --mode stream --view all --grep 'ssh|sudo' --ignore 'session closed'

# Exibe eventos associados ao IP de exemplo sem gravar a sessão.
vitaisk watch --view all --ip 192.0.2.10 --no-save
```

Use `vitaisk config path` para localizar a configuração e `vitaisk config show` para ver os valores. Para criar um perfil, adicione ao YAML:

```yaml
profiles:
  ssh:
    view: all
    sources: [auth]
    grep: ssh
```

Abra com `vitaisk watch --profile ssh`. No painel, **F** também permite editar os filtros durante a coleta. Para persistir o idioma padrão, use `vitaisk config set lang pt`.

## Alertas e correlações

O motor avalia regras pontuais, contagens em uma janela e sequências entre eventos. Por exemplo, `ssh-fail-then-success` correlaciona cinco falhas e um login posterior pelo mesmo host, IP e usuário. `inbound-scan-then-ssh-fail` correlaciona registros de bloqueio TCP em portas distintas com uma falha de SSH no mesmo host e IP. A cobertura depende de os eventos e campos necessários estarem disponíveis. Ações como `BLOCK` são sugestões exibidas no alerta.

```bash
# Lista as regras de detecção disponíveis.
vitaisk rules list

# Mostra a definição da regra de falhas de SSH seguidas de login.
vitaisk rules show ssh-fail-then-success

# Testa a detecção de uma mensagem sintética de erro do kernel.
vitaisk rules test --source kernel 'EXT4-fs error on sda'

# Exibe anomalias com o nível de sensibilidade alto.
vitaisk watch --view anomalies --sensitivity high
```

A sensibilidade ajusta o limiar de confiança. O motor também pode detectar picos estatísticos de erros usando uma referência calculada no próprio host. Consulte a [referência de regras](docs/rules.md) para exemplos de YAML e testes com eventos sintéticos.

## Dados, sessões e captura

Cada instalação começa com configuração padrão e sem histórico de outra máquina. O VitaisK gera os arquivos localmente conforme o uso.

| Arquivo | Local padrão para o usuário atual |
| --- | --- |
| Configuração | `~/.config/vitaisk/config.yaml` |
| Regras personalizadas | `~/.config/vitaisk/rules.d/` |
| Sessões | `~/.local/share/vitaisk/sessions/` |
| Referência estatística | `~/.local/share/vitaisk/baseline.json` |
| Capturas sob demanda | `~/.local/share/vitaisk/pcap/` |

Para usuários comuns, `XDG_CONFIG_HOME` e `XDG_DATA_HOME` podem alterar os diretórios-base. Ao executar como root, os caminhos padrão passam a ser `/etc/vitaisk` e `/var/lib/vitaisk`.

Uma sessão salva eventos, linhas originais e alertas antes dos filtros de tela. O formato padrão é JSONL compactado. O arquivo temporário `.part` é finalizado quando a sessão encerra normalmente ou gira para um novo arquivo. A configuração inicial retém até 20 sessões finalizadas e 500 MiB de histórico, removendo as mais antigas conforme necessário.

```bash
# Lista as sessões finalizadas que estão disponíveis no histórico local.
vitaisk sessions list

# Exibe os detalhes da sessão finalizada mais recente.
vitaisk sessions show latest

# Resume contagens por origem, gravidade e regra na sessão mais recente.
vitaisk summary --session latest

# Exporta a sessão mais recente para um arquivo JSON.
vitaisk export --session latest --format json --output sessao.json

# Exporta a sessão mais recente para um arquivo CSV.
vitaisk export --session latest --format csv --output sessao.csv
```

Use `vitaisk watch --no-save` para uma execução sem sessão, ou `vitaisk config set save_sessions false` para desativar essa gravação por padrão. A referência estatística é controlada separadamente com `vitaisk config set baseline_enabled false`.

Para gravar pacotes sob demanda, execute em uma interface à qual você tem acesso:

```bash
# Captura pacotes na interface local lo por até 10 segundos, com limite de 20 MiB.
vitaisk capture --interface lo --duration 10s --max-size 20M
```

## Eficiência e compatibilidade

A coleta é incremental. Os coletores acompanham novas entradas ou amostram o estado do sistema em intervalos. A fila, o histórico do painel e os grupos de detecção têm tamanho limitado. Se a fila lotar, ela descarta os eventos mais antigos e informa a contagem de perdas. O painel limita a frequência de atualização, e a captura contínua fica desativada por padrão.

A ferramenta roda localmente, com opção de saída em fluxo e sem dependência de um servidor, banco de dados ou ambiente gráfico. Em máquinas com pouco recurso, você pode reduzir a taxa de atualização, aumentar o intervalo das métricas e ajustar a retenção em disco. Por exemplo:

```bash
# Define duas atualizações do painel por segundo.
vitaisk config set refresh_hz 2

# Define um intervalo de cinco segundos entre amostras de métricas.
vitaisk config set metrics_interval 5

# Define o limite do histórico de sessões em 200 MiB.
vitaisk config set max_history_size_mb 200
```

Essas escolhas permitem usar a mesma ferramenta em diferentes distribuições Linux que ofereçam Python compatível. A cobertura e o custo variam com o volume de eventos e as fontes disponíveis.

## Documentação

- [Arquitetura, fontes e processamento](docs/architecture.md)
- [Referência de regras e correlações](docs/rules.md)
- [Como contribuir](CONTRIBUTING.md)
- [Licença MIT](LICENSE)
