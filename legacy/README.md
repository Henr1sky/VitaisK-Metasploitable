# VitaisK no Metasploitable 2

Compatível com Python 2.5.2. Na VM, rode `python vitaisk.py watch` para acompanhar system, auth e kernel. Use `--once` para ler os eventos existentes.

Em teste na VM, foram lidas 4.112 linhas de syslog, 107 de auth.log e 2.839 de kern.log. O acompanhamento de um arquivo temporário classificou sucesso e falha de SSH antes e depois da rotação. A coleta de novas mensagens pelo syslog real segue pendente.
