# Como contribuir

Use Linux com Python 3.10 ou superior. Depois de clonar o repositório, configure o ambiente e execute os testes:

```bash
# Cria o ambiente virtual Python na pasta .venv.
python3 -m venv .venv
# Instala o VitaisK em modo editável com as dependências de desenvolvimento.
.venv/bin/python -m pip install -e '.[dev]'
# Executa os testes automatizados com saída detalhada.
.venv/bin/python -m unittest discover -s tests -v
# Gera os pacotes de distribuição na pasta dist.
.venv/bin/python -m build
# Valida os metadados e a descrição dos pacotes gerados.
.venv/bin/python -m twine check dist/*
```

Para mudanças em coletores ou detecção, inclua uma amostra sintética que reproduza o caso e registre quais distribuições, versões de Python e fontes foram verificadas. Use exemplos anonimizados em issues e pull requests. Os testes em `tests/` rodam sem `sudo`.

Ao abrir um pull request, descreva o comportamento alterado, como foi verificado e qualquer alteração de compatibilidade ou configuração. Consulte a [arquitetura](docs/architecture.md) e a [referência de regras](docs/rules.md).
