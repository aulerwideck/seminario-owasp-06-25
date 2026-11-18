"""
Código compartilhado pelas duas versões do app de comissões.

Repare: autenticação e criptografia estão CORRETAS aqui, nas duas versões:
  - senhas guardadas com hash lento e com sal (scrypt, via werkzeug);
  - sessão com JWT HS256, algoritmo fixado na verificação, expiração obrigatória.

O login funciona. A falha está no DESENHO do relatório: quem decide de quem é o relatório
é o cliente (vulnerável) ou o servidor (corrigido).
"""
import datetime as dt
import os
import secrets
import sqlite3
from functools import wraps

import jwt
from flask import Flask, current_app, g, jsonify, request, send_from_directory
from werkzeug.security import check_password_hash, generate_password_hash

PASTA_ESTATICA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
MES = "2026-10"

ESQUEMA = """
CREATE TABLE usuarios(
    id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, nome TEXT NOT NULL,
    senha_hash TEXT NOT NULL,
    papel TEXT NOT NULL CHECK (papel IN ('vendedor', 'gestor', 'financeiro')),
    equipe TEXT);
CREATE TABLE metas(
    usuario_id INTEGER NOT NULL REFERENCES usuarios(id), mes TEXT NOT NULL,
    meta_centavos INTEGER NOT NULL, vendido_centavos INTEGER NOT NULL,
    comissao_centavos INTEGER NOT NULL, PRIMARY KEY (usuario_id, mes));
CREATE TABLE auditoria(
    id INTEGER PRIMARY KEY, usuario_id INTEGER, evento TEXT NOT NULL,
    alvo_email TEXT, criado_em TEXT NOT NULL);
"""

# email, nome, senha, papel, equipe, meta, vendido, comissão (centavos) — dados fictícios
USUARIOS = [
    ("ana.souza@empresa.demo", "Ana Souza", "ana123", "vendedor", "Sul", 50_000_00, 42_000_00, 1_260_00),
    ("bruno.lima@empresa.demo", "Bruno Lima", "bruno123", "vendedor", "Sul", 50_000_00, 61_000_00, 3_050_00),
    ("carla.dias@empresa.demo", "Carla Dias", "carla123", "vendedor", "Sul", 40_000_00, 40_800_00, 2_040_00),
    ("eduardo.reis@empresa.demo", "Eduardo Reis", "eduardo123", "vendedor", "Norte", 60_000_00, 75_000_00, 3_750_00),
    ("diego.alves@empresa.demo", "Diego Alves", "diego123", "gestor", "Sul", 140_000_00, 143_800_00, 4_314_00),
    ("fernanda.costa@empresa.demo", "Fernanda Costa", "fernanda123", "financeiro", None, 0, 0, 0),
]


def reais(centavos):
    return round(centavos / 100, 2)


def agora():
    return dt.datetime.now(dt.timezone.utc)


def erro(status, mensagem):
    return jsonify({"erro": mensagem}), status


# ----------------------------------------------------------------------------- banco

def _conectar(caminho):
    con = sqlite3.connect(caminho, timeout=10, isolation_level=None, check_same_thread=False)
    con.row_factory = sqlite3.Row
    return con


def abrir_db():
    if "db" not in g:
        g.db = _conectar(current_app.config["CAMINHO_DB"])
    return g.db


def fechar_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


_HASHES = {}


def _hash(senha):
    if senha not in _HASHES:
        _HASHES[senha] = generate_password_hash(senha)
    return _HASHES[senha]


def inicializar_db(caminho):
    con = _conectar(caminho)
    con.execute("PRAGMA journal_mode=WAL")
    for t in ("auditoria", "metas", "usuarios"):
        con.execute(f"DROP TABLE IF EXISTS {t}")
    con.executescript(ESQUEMA)
    for email, nome, senha, papel, equipe, meta, vendido, comissao in USUARIOS:
        uid = con.execute("INSERT INTO usuarios(email, nome, senha_hash, papel, equipe) VALUES (?,?,?,?,?)",
                          (email, nome, _hash(senha), papel, equipe)).lastrowid
        if papel != "financeiro":
            con.execute("INSERT INTO metas VALUES (?,?,?,?,?)", (uid, MES, meta, vendido, comissao))
    con.close()


def buscar_usuario(db, *, uid=None, email=None):
    if uid is not None:
        return db.execute("SELECT * FROM usuarios WHERE id=?", (uid,)).fetchone()
    return db.execute("SELECT * FROM usuarios WHERE email=?", (email,)).fetchone()


def montar_relatorio(db, u):
    m = db.execute("SELECT * FROM metas WHERE usuario_id=? AND mes=?", (u["id"], MES)).fetchone()
    corpo = {"nome": u["nome"], "email": u["email"], "equipe": u["equipe"], "mes": MES}
    if m:
        corpo.update({
            "meta": reais(m["meta_centavos"]), "vendido": reais(m["vendido_centavos"]),
            "atingimento_pct": round(100 * m["vendido_centavos"] / m["meta_centavos"], 1),
            "comissao": reais(m["comissao_centavos"])})
    return corpo


# ----------------------------------------------------------------------------- autenticação

def emitir_token(usuario_id):
    claims = {"sub": str(usuario_id), "iat": agora(), "exp": agora() + dt.timedelta(minutes=30)}
    return jwt.encode(claims, current_app.config["SEGREDO_JWT"], algorithm="HS256")


def exige_login(funcao):
    @wraps(funcao)
    def envoltorio(*args, **kwargs):
        cabecalho = request.headers.get("Authorization", "")
        if not cabecalho.startswith("Bearer "):
            return erro(401, "token ausente")
        try:
            claims = jwt.decode(cabecalho[7:], current_app.config["SEGREDO_JWT"],
                                algorithms=["HS256"], options={"require": ["exp", "iat", "sub"]})
        except jwt.PyJWTError:
            return erro(401, "token inválido ou expirado")
        g.usuario_id = int(claims["sub"])
        return funcao(*args, **kwargs)
    return envoltorio


# ----------------------------------------------------------------------------- aplicação

def criar_app_base(versao, caminho_db):
    app = Flask(__name__, static_folder=None)
    app.config.update(VERSAO=versao, CAMINHO_DB=caminho_db,
                      SEGREDO_JWT=os.environ.get("SEGREDO_JWT") or secrets.token_hex(32))
    inicializar_db(caminho_db)
    app.teardown_appcontext(fechar_db)

    @app.get("/")
    def pagina():
        return send_from_directory(PASTA_ESTATICA, "index.html")

    @app.get("/api/info")
    def info():
        return jsonify({"versao": app.config["VERSAO"]})

    @app.post("/api/reset")
    def reset():
        # Só para a apresentação. Não exponha algo assim em produção.
        inicializar_db(app.config["CAMINHO_DB"])
        return jsonify({"ok": True})

    @app.post("/api/login")
    def login():
        dados = request.get_json(silent=True) or {}
        u = buscar_usuario(abrir_db(), email=dados.get("email", ""))
        if not u or not check_password_hash(u["senha_hash"], dados.get("senha", "")):
            return erro(401, "credenciais inválidas")
        return jsonify({"token": emitir_token(u["id"])})

    @app.get("/api/me")
    @exige_login
    def eu():
        u = buscar_usuario(abrir_db(), uid=g.usuario_id)
        return jsonify({"nome": u["nome"], "email": u["email"], "papel": u["papel"], "equipe": u["equipe"]})

    return app
