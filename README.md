# Relatório de comissões

Este projeto foi feito para um seminário de segurança sobre **Design Inseguro (A06 da OWASP)**. Ele mostra um erro em um sistema de comissões e uma forma de corrigir esse erro.

Existem duas versões do mesmo sistema:

- `app_vulneravel.py`: tem a falha.
- `app_corrigido.py`: tem a correção.

Os nomes, e-mails e valores usados no projeto são inventados. O exemplo é só para estudo.

## Qual era o problema?

No sistema original, a pessoa fazia login e via seu relatório de metas e comissões. Porém, o sistema usava o e-mail enviado na requisição para escolher qual relatório mostrar.

Por exemplo, entrando como Ana, era possível trocar o e-mail da URL pelo e-mail do Bruno:

```text
/api/relatorio-metas?email=bruno.lima@empresa.demo
```

Assim, a Ana conseguia ver a comissão do Bruno. O sistema deveria usar o usuário que fez login para decidir o que ele pode ver, mas confiava no e-mail enviado pelo navegador.

## Como rodar

É preciso ter Python 3.10 ou mais novo. Dentro da pasta do projeto, rode:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

No Windows, use `.venv\Scripts\activate` no lugar do comando `source`.

Depois, abra dois terminais e execute um comando em cada um:

```bash
python app_vulneravel.py
```

```bash
python app_corrigido.py
```

A versão com falha fica em <http://localhost:5001> e a corrigida em <http://localhost:5002>.

## Como ver o problema

1. Abra a versão com falha na porta 5001. O sistema entra como Ana.
2. No campo da requisição, troque o e-mail da Ana por `bruno.lima@empresa.demo` e clique em **Enviar**.
3. O relatório do Bruno vai aparecer, mesmo que você esteja como Ana.
4. Faça a mesma coisa na versão corrigida, na porta 5002. Ela vai mostrar o erro **403**, porque a Ana não tem permissão para ver esse relatório.

Também dá para escolher outros usuários na parte de cima da página. O Diego é gestor e pode ver os relatórios da equipe dele. A Fernanda é do financeiro e pode ver todos.

## O que mudou na correção?

Na versão corrigida, o servidor confere quem fez login antes de mostrar um relatório. Um vendedor só pode ver o próprio relatório. Um gestor pode ver os relatórios da sua equipe, e o financeiro pode ver todos.

Se alguém tentar acessar um relatório sem permissão, o sistema responde com erro 403 e registra a tentativa.

Os arquivos principais são `comum.py` (login e dados), `app_vulneravel.py`, `app_corrigido.py` e `static/index.html` (a página que aparece no navegador).
