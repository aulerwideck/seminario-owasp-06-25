"""
VERSÃO VULNERÁVEL — relatório de metas e comissões que usa o e-mail como chave de busca.
Réplica simplificada do caso relatado no seminário. NÃO use como referência.

Rodar:  python app_vulneravel.py      ->  http://localhost:5001
"""
from flask import jsonify, request

from comum import abrir_db, buscar_usuario, criar_app_base, erro, exige_login, montar_relatorio


def criar_app(caminho_db="dados_vulneravel.db"):
    app = criar_app_base("vulneravel", caminho_db)

    @app.get("/api/relatorio-metas")
    @exige_login                      # o usuário PRECISA estar logado...
    def relatorio_metas():
        # FALHA DE DESIGN (CWE-501 → CWE-639): o servidor pergunta ao CLIENTE "de quem é o
        # relatório?". O app manda o e-mail de quem está logado, mas qualquer um pode trocar
        # esse parâmetro. Nada compara o e-mail pedido com o dono do token.
        email = request.args.get("email", "")

        alvo = buscar_usuario(abrir_db(), email=email)
        if not alvo:
            # FALHA: resposta diferente para e-mail inexistente permite descobrir quem existe.
            return erro(404, "usuário não encontrado")

        # FALHA: nenhum registro de quem viu o relatório de quem.
        return jsonify(montar_relatorio(abrir_db(), alvo))

    return app


if __name__ == "__main__":
    criar_app().run(port=5001)
