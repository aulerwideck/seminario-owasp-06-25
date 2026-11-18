"""
VERSÃO CORRIGIDA — o mesmo relatório, redesenhado a partir da modelagem de ameaças (STRIDE).
Cada controle está marcado com "CONTROLE" e a letra STRIDE que ele mitiga.

Rodar:  python app_corrigido.py       ->  http://localhost:5002
"""
import datetime as dt
import logging

from flask import g, jsonify, request

from comum import abrir_db, agora, buscar_usuario, criar_app_base, erro, exige_login, montar_relatorio

log = logging.getLogger("comissoes")
SEM_PERMISSAO = "sem permissão para ver este relatório"
NEGACOES_PARA_ALERTA = 3


def pode_ver(solicitante, alvo):
    """CONTROLE (I, E): a regra de negócio escrita no servidor.
    - todo mundo vê o próprio relatório;
    - gestor vê o da própria equipe;
    - financeiro vê todos.
    O papel e a equipe vêm do BANCO, nunca da requisição nem do token."""
    if alvo["id"] == solicitante["id"]:
        return True
    if solicitante["papel"] == "financeiro":
        return True
    if solicitante["papel"] == "gestor" and alvo["equipe"] == solicitante["equipe"]:
        return True
    return False


def auditar(db, evento, alvo_email=None):
    db.execute("INSERT INTO auditoria(usuario_id, evento, alvo_email, criado_em) VALUES (?,?,?,?)",
               (g.usuario_id, evento, alvo_email, agora().isoformat(timespec="seconds")))


def criar_app(caminho_db="dados_corrigido.db"):
    app = criar_app_base("corrigido", caminho_db)

    @app.get("/api/relatorio-metas")
    @exige_login
    def relatorio_metas():
        db = abrir_db()
        # CONTROLE (S): quem pede é quem está no token assinado — não um parâmetro.
        eu = buscar_usuario(db, uid=g.usuario_id)

        email = request.args.get("email")
        if email is None or email == eu["email"]:
            # Sem parâmetro, o relatório é o do próprio usuário: o SERVIDOR decide.
            return jsonify(montar_relatorio(db, eu))

        alvo = buscar_usuario(db, email=email)
        if not alvo or not pode_ver(eu, alvo):
            # CONTROLE (I): mesma resposta para "não existe" e "não pode ver":
            # não dá para descobrir quais e-mails existem.
            auditar(db, "acesso_negado", email)
            # CONTROLE (R, D): registra e alerta quem insiste.
            desde = (agora() - dt.timedelta(minutes=10)).isoformat(timespec="seconds")
            negacoes = db.execute("SELECT COUNT(*) FROM auditoria WHERE usuario_id=? AND "
                                  "evento='acesso_negado' AND criado_em >= ?",
                                  (eu["id"], desde)).fetchone()[0]
            if negacoes >= NEGACOES_PARA_ALERTA:
                log.warning("ALERTA: %s teve %d acessos negados em 10 min", eu["email"], negacoes)
            return erro(403, SEM_PERMISSAO)

        # CONTROLE (R): acesso legítimo a relatório de outra pessoa também fica registrado.
        auditar(db, "relatorio_de_outro", alvo["email"])
        return jsonify(montar_relatorio(db, alvo))

    @app.get("/api/equipe")
    @exige_login
    def equipe():
        """O caminho certo para o gestor: a lista vem do servidor, já filtrada pelo papel."""
        db = abrir_db()
        eu = buscar_usuario(db, uid=g.usuario_id)
        if eu["papel"] == "financeiro":
            linhas = db.execute("SELECT * FROM usuarios WHERE papel != 'financeiro' ORDER BY nome").fetchall()
        elif eu["papel"] == "gestor":
            linhas = db.execute("SELECT * FROM usuarios WHERE equipe=? ORDER BY nome", (eu["equipe"],)).fetchall()
        else:
            linhas = [eu]
        return jsonify([montar_relatorio(db, u) for u in linhas])

    @app.get("/api/auditoria")
    @exige_login
    def ver_auditoria():
        db = abrir_db()
        if buscar_usuario(db, uid=g.usuario_id)["papel"] != "financeiro":
            return erro(403, "sem permissão")
        linhas = db.execute("SELECT a.evento, u.email AS quem, a.alvo_email, a.criado_em FROM auditoria a "
                            "JOIN usuarios u ON u.id = a.usuario_id ORDER BY a.id DESC LIMIT 50").fetchall()
        return jsonify([dict(l) for l in linhas])

    return app


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    criar_app().run(port=5002)
