# Guia do laboratório Metasploitable 2

O VitaisK pode exibir os eventos da VM no Kali ou no próprio console da VM. Para instalar no Kali, siga os [primeiros passos](../README.md#primeiros-passos-no-kali).

## Monitoramento pelo Kali

Mantenha o Kali e a VM na mesma rede host-only, com endereços IPv4 privados distintos e acesso direto. A VM deve ficar sem rota padrão. Verifique a chave SSH no console da VM e use a conta autorizada do laboratório. O OpenSSH pede a autenticação no terminal antes de abrir o painel.

~~~sh
.venv/bin/vitaisk lab-doctor
.venv/bin/vitaisk --lang pt watch --metasploitable --view all
~~~

O diagnóstico informa a interface usada no Kali, a versão do Python e do kernel da VM, o estado do sistema de arquivos raiz e quais logs estão legíveis. Os dois comandos aceitam as mesmas opções de conexão:

| Opção | Valor esperado |
| --- | --- |
| `--lab-host` | Endereço IPv4 da VM. |
| `--lab-bind` | Endereço IPv4 do Kali na interface da rede isolada. |
| `--lab-user` | Usuário SSH autorizado na VM. |

O coletor Python 2.5 roda na VM pela conexão SSH. O motor processa os eventos no Kali. Use `--source auth` para consultar autenticação, `--only-anomalies` para ver alertas e `--mode stream` para ler os eventos em texto. Pressione **q** para fechar o painel. Se a conexão cair, a coleta termina. Execute o comando novamente para reconectar.

### Sessões e exportação

O Kali armazena as sessões de acordo com sua configuração. Use `--no-save` para desativar a gravação da sessão atual. A referência estatística é controlada separadamente e mantida por endereço da VM. Os registros da sessão incluem o host de origem em `extra.lab_host`.

~~~sh
.venv/bin/vitaisk sessions list
.venv/bin/vitaisk summary --session latest
.venv/bin/vitaisk export --session latest --format csv --output sessao.csv
~~~

## Painel no console da VM

Com [vitaisk.py](vitaisk.py) disponível em um diretório gravável na VM, abra um terminal interativo e execute a partir desse diretório:

~~~sh
python vitaisk.py watch --mode dashboard
~~~

O painel local usa Python 2.5 e o módulo `curses`. Use **1** para sistema, **2** para autenticação, **3** para kernel, **a** para todas as fontes, **p** para pausar a exibição e **q** para sair. Para ler as entradas disponíveis e encerrar, use o modo em texto:

~~~sh
python vitaisk.py watch --source auth --once
~~~

## Cobertura da coleta

| Dados | Disponibilidade |
| --- | --- |
| Sistema, autenticação e kernel | Arquivos legíveis na VM. |
| Firewall e auditoria | Painel no Kali, quando os arquivos estão disponíveis e a conta pode lê-los. |
| CPU, memória e disco | Painel no console da VM e painel no Kali. |
| Carga, processos e conexões IPv4 | Coletados na VM e enviados ao painel no Kali. A amostragem pode perder conexões muito breves. |
| Captura PCAP sob demanda | Executada separadamente no Kali com `tcpdump` e permissões na interface. Cobre apenas o tráfego visível nessa interface. |

## Resolução de problemas

- **Falha de rota ou de autenticação SSH.** Confira os dois endereços, a interface host-only, a conta autorizada e a chave da VM em `known_hosts`. Rode `lab-doctor` novamente.
- **Métricas mudam, mas os logs não.** Confira permissões e o estado do sistema de arquivos. Se a raiz estiver montada somente para leitura, a VM pode exibir o histórico sem conseguir gravar novos eventos nos logs.
- **O painel local não abre.** Use um terminal interativo com `curses` disponível. Para ler os logs sem o painel, selecione `--mode stream`.

## Verificação

No Kali, a partir da raiz do repositório, rode os testes automatizados:

~~~sh
.venv/bin/python -m unittest discover -s tests -v
~~~

Para verificar o laboratório em execução, rode `lab-doctor`, abra o painel no Kali e confira se as métricas da VM atualizam. Se estiver usando a interface legada, abra também o painel no console da VM.
