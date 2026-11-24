# VitaisK-Metasploitable

Monitoramento do **Metasploitable 2** em uma rede isolada. O painel legado roda no Python 2.5 da própria VM. O modo Kali recebe os eventos e as métricas da VM por SSH e os processa com o motor do VitaisK.

| Modo | Onde o painel roda | Quando usar |
| --- | --- | --- |
| **Console da VM** | No Metasploitable 2, com Python 2.5 | Para acompanhar logs e métricas básicas sem conexão SSH. |
| **Kali via SSH** | No Kali, com Python 3.10 ou superior | Para analisar eventos da VM, aplicar regras e gravar sessões no Kali. |

[Preparar o laboratório](#preparar-o-laboratório) · [Rodar na VM](#painel-na-vm-sem-ssh) · [Rodar no Kali](#painel-no-kali-via-ssh) · [Ver onde os logs ficam](#onde-os-logs-ficam-salvos)

## Preparar o laboratório

No VirtualBox, conecte o Metasploitable 2 apenas a um adaptador **Host-only**. Para monitorar pelo Kali, conecte o Kali à mesma rede Host-only. Mantenha a VM sem rota padrão, adaptador NAT, bridge ou redirecionamento de portas.

| Endereço padrão do laboratório | Valor |
| --- | --- |
| Metasploitable 2 | `192.168.56.101` |
| Kali na rede isolada | `192.168.56.102` |
| Usuário SSH da VM | `msfadmin` |

Baixe o repositório em uma máquina que tenha acesso ao GitHub. Use essa máquina para preparar a ISO ou use o próprio Kali se ele for executar o painel remoto.

```sh
# Baixe a cópia do laboratório usando uma conta com acesso ao repositório.
git clone https://github.com/Henr1sky/VitaisK-Metasploitable.git

# Entre na pasta do projeto antes de rodar os comandos deste guia.
cd VitaisK-Metasploitable
```

## Painel na VM, sem SSH

Se o script já estiver na VM, abra o console do VirtualBox e execute `python` com o caminho do arquivo e os argumentos `watch --mode dashboard`. Para transferir sem rede, use uma imagem ISO. A preparação da imagem requer `xorriso` em uma máquina Linux.

```sh
# Crie um CD virtual contendo apenas o script legado.
xorriso -as mkisofs -R -o /tmp/vitaisk-legacy.iso legacy/vitaisk.py
```

No computador que hospeda o VirtualBox, selecione a ISO em **Dispositivos → Unidades ópticas**. Depois, no console do Metasploitable 2:

```sh
# Crie o ponto de montagem em memória, inclusive se a raiz estiver somente para leitura.
mkdir -p /dev/shm/vitaisk-cd

# Monte o CD sem tentar atualizar a tabela de montagens em disco.
sudo mount -n -t iso9660 -o ro /dev/cdrom /dev/shm/vitaisk-cd

# Abra o painel com um tipo de terminal compatível com a VM.
TERM=xterm python /dev/shm/vitaisk-cd/vitaisk.py watch --mode dashboard

# Consulte o histórico de autenticação e encerre após a leitura.
python /dev/shm/vitaisk-cd/vitaisk.py watch --source auth --once
```

Se a unidade aparecer como `/dev/sr0`, use esse caminho no comando de montagem. A montagem em `/dev/shm` dura até a VM reiniciar. [Passo a passo do console e transferência opcional por SSH](legacy/README.md#painel-dentro-da-vm)

| Tecla do painel nativo | Ação |
| --- | --- |
| `1` · `2` · `3` | Exibe sistema, autenticação ou kernel. |
| `a` | Volta a exibir todas as fontes. |
| `p` | Pausa ou retoma a exibição. |
| `q` | Fecha o painel. |

## Painel no Kali, via SSH

Use Python 3.10 ou superior, suporte a `venv` e OpenSSH no Kali. Antes do primeiro login, confira no console da VM a impressão digital da chave RSA do servidor e aceite no Kali somente se coincidir. O monitor exige que a chave já esteja registrada. [Configuração e diagnóstico da conexão](legacy/README.md#começar-pelo-kali)

Para cadastrar a chave pela primeira vez, consulte a impressão digital **no console da VM**:

```sh
# Mostre a impressão digital da chave pública RSA do servidor SSH.
ssh-keygen -lf /etc/ssh/ssh_host_rsa_key.pub
```

Depois, no **Kali**, compare os valores antes de aceitar e faça login uma vez:

```sh
# Use a rede isolada e mostre a impressão no formato MD5 exibido pelo SSH antigo.
ssh -b 192.168.56.102 -o HostKeyAlgorithms=+ssh-rsa -o FingerprintHash=md5 -o StrictHostKeyChecking=ask msfadmin@192.168.56.101
```

Saia dessa sessão e rode os comandos abaixo no Kali, na pasta do repositório.

```sh
# Crie um ambiente virtual para esta cópia do projeto.
python3 -m venv .venv

# Instale o VitaisK-Metasploitable e as dependências usadas no Kali.
.venv/bin/python -m pip install .

# Verifique o caminho de rede, o acesso SSH e os logs disponíveis na VM.
.venv/bin/vitaisk lab-doctor

# Abra o painel em português com todos os eventos disponíveis.
.venv/bin/vitaisk --lang pt watch --metasploitable --mode dashboard --view all
```

Para endereços ou usuários diferentes, use `--lab-host`, `--lab-bind` e `--lab-user`, tanto no diagnóstico quanto no monitor. O monitor executa o coletor em memória na VM e usa **uma conexão SSH** para transportar as fontes disponíveis. Por isso, o painel pode mostrar um coletor ativo mesmo recebendo dados de várias fontes.

## Onde os logs ficam salvos

| Modo | Local |
| --- | --- |
| **Painel nativo** | Lê `/var/log/syslog` (ou `/var/log/messages`), `/var/log/auth.log` e `/var/log/kern.log` na VM. O histórico do painel fica em memória. |
| **Painel no Kali** | As sessões ficam normalmente em `~/.local/share/vitaisk/sessions/` no Kali, quando a gravação está habilitada. |

Abrir o painel nativo em um terminal SSH também mantém a execução e os logs na VM. Para configurações de gravação, consultas e exportação, consulte a [documentação de sessões do VitaisK original](https://github.com/Henr1sky/VitaisK#dados-sess%C3%B5es-e-captura).

## Diagnóstico rápido

| Sintoma | O que verificar |
| --- | --- |
| O painel da VM mostra `Error opening terminal: xterm-256color` | Execute o comando com `TERM=xterm`, como no exemplo acima. |
| O painel abre, mas os logs ficam parados | Rode o diagnóstico e confira se a raiz da VM está somente para leitura. Os logs existentes e as métricas continuam acessíveis. Novos eventos em `/var/log` dependem de gravação no disco. |
| O Kali não conecta | Confira a rede Host-only, os endereços, a chave SSH e a ausência de uma rota padrão na VM. |
| Firewall ou auditoria não aparecem | Essas fontes dependem de arquivos configurados e legíveis na VM. |

A compatibilidade foi verificada em uma VM i686 com Ubuntu 8.04, kernel 2.6.24 e Python 2.5.2. Para detalhes sobre fontes disponíveis, limites de captura e o estado do disco do laboratório, consulte o [guia técnico](legacy/README.md).

```sh
# Rode os testes automatizados no Kali a partir da raiz do projeto.
.venv/bin/python -m unittest discover -s tests -v
```

## Referências

- [Guia do laboratório e da edição legada](legacy/README.md)
- [VitaisK original e documentação dos recursos compartilhados](https://github.com/Henr1sky/VitaisK)
- [Licença MIT](LICENSE)
