# VitaisK no Metasploitable 2

Esta edição inicial roda com o Python 2.5.2 do Ubuntu 8.04, sem pacotes externos. Ela acompanha logs locais e identifica mensagens de sucesso e falha do SSH. O painel de terminal roda com curses. Métricas, captura de pacotes e regras da edição principal ainda não estão disponíveis.

Transfira `legacy/vitaisk.py` pelo SSH da rede isolada e rode na VM:

```sh
python vitaisk.py watch --mode dashboard
python vitaisk.py watch
python vitaisk.py watch --source auth
python vitaisk.py watch --source system --once
```

O painel mostra linhas recentes e eventos novos. Pressione q para sair do painel. O modo de texto acompanha novas linhas a partir do fim dos arquivos. Use Ctrl+C para sair. `--once` lê as linhas existentes e termina. Para testar com um arquivo próprio, combine `--file caminho` com um único `--source`.

| Fonte | Caminho |
| --- | --- |
| `system` | `/var/log/syslog` ou `/var/log/messages` |
| `auth` | `/var/log/auth.log` |
| `kernel` | `/var/log/kern.log` |

O processo usa as permissões do usuário que o executa.

## Testes na VM

Em 23 de novembro de 2026, a execução no Python 2.5.2 da VM leu 4.112 linhas do syslog, 107 de auth.log e 2.839 de kern.log. Em um arquivo temporário, o modo ao vivo classificou um login SSH simulado e uma falha simulada após a rotação do arquivo. A emissão de uma mensagem real com `logger` em um teste anterior não chegou aos arquivos esperados, então a coleta de novas mensagens do daemon de syslog ainda está pendente de verificação.

A tentativa de gravar no diretório pessoal retornou erro de sistema de arquivos somente para leitura. A VM aceita execução em memória. Para repetir o teste diretamente pelo Kali, entre no diretório que contém a pasta `legacy` e envie o script pela entrada do Python remoto:

```sh
ssh -T -b 192.168.56.102 -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=+ssh-rsa \
  msfadmin@192.168.56.101 'python - watch --source auth' < legacy/vitaisk.py
```

O painel foi verificado no Python 2.5.2 com um terminal interativo na VM. O teste confirmou o histórico inicial, a atualização após uma nova linha e o aviso de disco somente para leitura.
