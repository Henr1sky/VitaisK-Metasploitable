# VitaisK para Metasploitable 2

**Monitoramento de eventos e métricas de uma VM legada em laboratório isolado.**

Esta edição do [VitaisK](https://github.com/Henr1sky/VitaisK) acompanha logs e sinais vitais do Metasploitable 2. O coletor roda com o Python 2.5 da VM. O painel no Kali recebe os dados via SSH e aplica os filtros, alertas e correlações do VitaisK.

| Modo | O que oferece |
| --- | --- |
| **Painel no Kali** | Eventos da VM em tempo real, métricas, filtros, alertas, histórico de sessões e exportação. Usa Python 3.10 ou superior. |
| **Painel na VM** | Logs legíveis de sistema, autenticação e kernel, com CPU, memória e disco em um terminal interativo. Usa o script legado com Python 2.5 e `curses`. |

## Primeiros passos no Kali

Use uma rede virtual **somente host (host-only)**. Mantenha a VM sem rota padrão, sem ligação em ponte, NAT ou redirecionamento de portas. Confira a chave SSH da VM pelo console antes de registrá-la no Kali. A máquina que executa o painel precisa de Git, Python 3.10 ou superior com suporte a ambientes virtuais, OpenSSH e `ip` do iproute2.

~~~sh
git clone https://github.com/Henr1sky/VitaisK-Metasploitable.git
cd VitaisK-Metasploitable
python3 -m venv .venv
.venv/bin/python -m pip install .
~~~

Com o Kali e a VM configurados na mesma sub-rede privada, execute primeiro o diagnóstico:

~~~sh
.venv/bin/vitaisk lab-doctor
.venv/bin/vitaisk --lang pt watch --metasploitable --view all
~~~

Se o seu ambiente usar outros endereços ou outra conta, passe `--lab-host`, `--lab-bind` e `--lab-user` aos dois comandos. O [guia do laboratório](legacy/README.md) explica cada opção, os dados disponíveis, como usar o painel na VM e como diagnosticar falhas de coleta.

## O que você pode acompanhar

- **Eventos.** Consulte logs de sistema, autenticação e kernel. Firewall e auditoria dependem da disponibilidade e das permissões dos arquivos na VM.
- **Métricas.** Acompanhe CPU, memória, disco, carga e processos. O painel no Kali também recebe amostras das conexões IPv4 da VM.
- **Investigação.** Filtre a visualização, consulte os alertas e exporte sessões registradas no Kali. A cobertura varia conforme as fontes disponíveis no laboratório.

## Documentação

- [Guia do laboratório](legacy/README.md) · Diagnóstico, painel, sessões e resolução de problemas.
- [Arquitetura do motor](docs/architecture.md) · Fila de eventos, processamento e armazenamento.
- [Regras de detecção e correlações](docs/rules.md) · Campos, formatos e exemplos com dados sintéticos.
- [Como contribuir](CONTRIBUTING.md) · [Licença MIT](LICENSE)
