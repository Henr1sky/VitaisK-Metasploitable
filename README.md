# VitaisK para Metasploitable 2

Esta edição usa o Python 2.5.2 do Ubuntu 8.04 para coletar dados na VM. No Kali, o VitaisK reutiliza o painel, as regras, os filtros, as sessões e a exportação da edição principal. Para uso inteiramente local na VM, há também um painel de terminal sem dependências adicionais.

## Começar pelo Kali

1. No VirtualBox, conecte o Metasploitable 2 apenas a uma rede interna ou Host-only compartilhada com o Kali. A VM fica sem adaptador NAT ou bridge e sem redirecionamento de porta.
2. Confira a impressão SSH no console da VM antes de aceitar a chave no Kali. Use o IP, a conta e a senha do laboratório. As opções padrão usam a VM em `192.168.56.101`, o Kali em `192.168.56.102` e a conta `msfadmin`.
3. Na raiz desta cópia do projeto, instale em um ambiente virtual no Kali com Python 3.10 ou superior:

   ```sh
   python3 -m venv .venv
   .venv/bin/python -m pip install .
   ```

4. Rode o diagnóstico e abra o painel:

   ```sh
   .venv/bin/vitaisk lab-doctor
   .venv/bin/vitaisk watch --metasploitable --view all
   ```

O OpenSSH pede a senha diretamente no terminal antes de abrir o painel. O coletor é enviado pela conexão e executado em memória na VM. As opções `--lab-host`, `--lab-bind` e `--lab-user` permitem ajustar o endereço e a conta de outro laboratório. A conexão exige IPv4 privado diretamente alcançável pela interface escolhida, chave SSH já conhecida e VM sem rota padrão ativa. Se a sessão SSH cair, o monitor encerra e avisa. Rode o comando novamente para conectar.

O painel mostra eventos e métricas **da VM**. Use `--source auth` para focar em autenticação, `--only-anomalies` para alertas e `--mode stream` para saída em texto. A tecla `q` fecha o painel. Consulte [onde os logs ficam salvos](#onde-os-logs-ficam-salvos).

O estado estatístico do laboratório é mantido por endereço da VM, separado do monitor local. Os registros das sessões identificam a origem em `extra.lab_host`.

### Monitoramento passivo de TCP

No Kali, ative o coletor de pacotes da VM quando quiser observar tentativas de conexão TCP, inclusive quando `/var/log` estiver parado:

```sh
# Mostre tentativas TCP recebidas pela VM na rede isolada.
.venv/bin/vitaisk --lang pt watch --metasploitable --lab-packets --mode dashboard --view all
```

O monitor pede a senha para `sudo` na VM e usa o `tcpdump` que já está instalado nela. Ele produz eventos com os endereços e as portas dos pacotes SYN IPv4 recebidos no endereço da VM, inclusive de outros participantes da rede isolada. Doze portas de destino distintas em até dez segundos geram o alerta `tcp-syn-many-ports`. A opção registra metadados dos SYN de entrada e agrupa alertas por IP de origem e independe da gravação em `/var/log`.

### Tentativas de acesso e correlações

Uma falha de senha, chave pública ou usuário inválido no SSH gera o alerta `lab-ssh-access-denied` em nível `WARN`. Abra **Anomalias** no painel para ver o alerta, o IP de origem e a mensagem de autenticação. Cinco falhas de senha da mesma origem em até um minuto geram `ssh-brute-force` em nível `CRITICAL`. Um SYN isolado indica uma tentativa de conexão TCP e aparece como `INFO` na visão **Todos**.


| Regra | Evidência que precisa chegar ao VitaisK |
| --- | --- |
| `ssh-fail-then-success` | Cinco falhas de SSH seguidas de login para o mesmo host, IP e usuário. |
| `inbound-scan-then-ssh-fail` | Bloqueios TCP a portas distintas no firewall, seguidos de falha de SSH da mesma origem e no mesmo host. |
| `tcp-syn-many-ports-then-ssh-fail` | Tentativas TCP em várias portas da VM, seguidas de falha de SSH para o mesmo par de endereços. Use `--lab-packets` para alimentar essa regra. |

O coletor lê os arquivos no Metasploitable 2. Bloqueios do firewall podem chegar pelo `kern.log` mesmo sem um arquivo exclusivo de firewall. A captura passiva é uma fonte separada e observa os SYN IPv4 recebidos no endereço da VM. O SSH transporta os dados e o motor no Kali aplica as regras. No painel, pressione `3` para abrir **Anomalias** e `Enter` para ver as fontes e a contagem da correlação.

O motor também avalia o catálogo de correlações do VitaisK original. Cada regra depende da chegada de suas fontes. A VM oferece autenticação, syslog, kernel, métricas e conexões. Firewall e auditd dependem de logs disponíveis e legíveis. Regras que dependem de telemetria estruturada ou classificação externa podem receber eventos de um produtor confiável no Kali por `--signal-file`. Consulte o formato no [VitaisK original](https://github.com/Henr1sky/VitaisK/blob/main/docs/telemetry.md).

```sh
# Abra o painel com o monitor TCP da VM e grave a sessão no Kali.
.venv/bin/vitaisk --lang pt watch --metasploitable --lab-packets --view all --save

# Liste as correlações e a telemetria que cada uma exige.
.venv/bin/vitaisk rules correlations

# Consulte o resumo da sessão concluída mais recente.
.venv/bin/vitaisk summary --session latest
```

Os testes reproduzem falhas de autenticação, múltiplas portas, correlação e persistência com registros sintéticos. Execute no Kali:

```sh
# Valide o catálogo e as sequências de detecção, incluindo as do laboratório.
.venv/bin/python -m unittest discover -s tests -v
```

## Painel dentro da VM

### Pelo console do VirtualBox, sem SSH

A execução local usa o Python 2.5 da VM. Se o script já estiver disponível nela, abra o console do Metasploitable 2 no VirtualBox e execute `TERM=xterm python /caminho/vitaisk.py watch --mode dashboard`.

Para levar o script à VM sem rede, use um CD virtual:

1. Em uma máquina Linux com a cópia do repositório e o `xorriso` instalado, rode na raiz do projeto:

   ```sh
   xorriso -as mkisofs -R -o /tmp/vitaisk-legacy.iso legacy/vitaisk.py
   ```

2. Disponibilize `vitaisk-legacy.iso` no computador que hospeda o VirtualBox. Na janela do Metasploitable 2, abra **Dispositivos → Unidades ópticas** e selecione a imagem. Se a VM não tiver uma unidade óptica, desligue-a e adicione uma em **Configurações → Armazenamento** antes de ligá-la novamente. [Manual do VirtualBox](https://docs.oracle.com/en/virtualization/virtualbox/7.1/user/BasicConcepts.html)
3. No console da VM, entre com seu usuário e monte o CD em `/dev/shm`, que fica em memória. Depois execute o script diretamente do CD:

   ```sh
   mkdir -p /dev/shm/vitaisk-cd
   sudo mount -n -t iso9660 -o ro /dev/cdrom /dev/shm/vitaisk-cd
   TERM=xterm python /dev/shm/vitaisk-cd/vitaisk.py watch --mode dashboard
   ```

   Se `/dev/cdrom` estiver ausente e a unidade aparecer como `/dev/sr0`, use esse dispositivo no comando `mount`. Para consultar apenas o histórico de autenticação, troque `--mode dashboard` por `--source auth --once`.

Pressione `q` para sair do painel. A montagem em memória é perdida ao reiniciar. Se a raiz estiver em somente leitura, este procedimento ainda permite abrir o painel e acompanhar as métricas. Novas linhas dos logs reais dependem de a VM voltar a gravar em `/var/log`.

### Transferência opcional por SSH

No Kali, a partir da raiz do repositório, envie o script pela rede isolada. A cópia em memória dura até a VM reiniciar:

```sh
ssh -b 192.168.56.102 -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=+ssh-rsa \
  msfadmin@192.168.56.101 'umask 077; d=$(mktemp -d /dev/shm/vitaisk.XXXXXX) && cat > "$d/vitaisk.py" && echo "$d/vitaisk.py"' < legacy/vitaisk.py
```

Na sessão SSH da VM, use o caminho que o comando imprimiu:

```sh
python /dev/shm/vitaisk.EXEMPLO/vitaisk.py watch --mode dashboard
python /dev/shm/vitaisk.EXEMPLO/vitaisk.py watch --source auth --once
```

O painel mostra linhas recentes, CPU, RAM e uso de disco. Use `1` para sistema, `2` para autenticação, `3` para kernel, `a` para todas as fontes, `p` para pausar a exibição e `q` para sair. `--once` lê o histórico e termina. Se seu terminal não for reconhecido, acrescente `TERM=xterm` antes de `python`.

## Onde os logs ficam salvos

- **No console do Metasploitable 2**, o painel lê os logs que a VM já grava em `/var/log/syslog` (ou `/var/log/messages`), `/var/log/auth.log` e `/var/log/kern.log`. O painel mantém o histórico recente em memória e não grava sessões na VM.
- **No Kali com `watch --metasploitable`**, os eventos recebidos por SSH são salvos, por padrão, em `~/.local/share/vitaisk/sessions/` no Kali. O formato e a gravação seguem o [VitaisK original](https://github.com/Henr1sky/VitaisK#dados-sess%C3%B5es-e-captura).

Se você abrir o painel nativo a partir de um terminal SSH, ele continua rodando na própria VM e mantém o histórico em memória.

## Cobertura e limites

| Recurso | Execução |
| --- | --- |
| Painel, histórico recente, filtros por fonte e métricas básicas | Na VM, com Python 2.5 |
| Syslog, autenticação, kernel, firewall e auditd | Pelos arquivos legíveis na VM. Firewall e auditd dependem de arquivos configurados e disponíveis. |
| CPU, RAM, disco, carga, contagem de processos e novas conexões IPv4 | Amostrados na VM sem privilégios adicionais e analisados no Kali |
| Regras, correlação, linha de base, sessões e exportação | Pelo motor VitaisK no Kali |
| Captura PCAP | Pelo VitaisK no Kali, na interface isolada, com tcpdump e permissões para captura |

Para capturar somente o tráfego da VM que passar pela interface do Kali, execute com as permissões locais necessárias:

```sh
sudo .venv/bin/vitaisk capture --interface eth1 --filter 'host 192.168.56.101' --duration 30s
```

A captura na interface do Kali cobre os pacotes visíveis nela. O coletor de conexões é amostrado a cada dois segundos e pode perder conexões curtas. Logs do journal e captura nativa de todos os pacotes da VM ficam fora desta edição.

## Estado deste laboratório

Se a raiz ext3 aparecer como somente leitura no painel ou no `lab-doctor`, verifique o estado do disco da VM. Uma raiz somente leitura pode interromper a gravação dos logs em `/var/log`. O monitor passivo de TCP e as métricas continuam disponíveis enquanto a VM e a rede estiverem funcionando.

Preserve uma cópia do disco virtual no host antes de mexer no sistema de arquivos. Verifique o ext3 com a VM desligada e o sistema de arquivos desmontado. Nenhuma recuperação de disco faz parte da instalação do VitaisK.

## Testes

No Kali:

```sh
.venv/bin/python -m unittest discover -s tests -v
```

Na VM de 32 bits, valide com `lab-doctor` e o painel nativo. A VM deste laboratório usa kernel 2.6.24, glibc 2.7 e Python 2.5.2.
