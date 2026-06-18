"""
app.py — Application Flask principale
Projet Fintech GTA — Cryptomonnaie + IA + Blockchain
"""

import os, uuid, json, datetime, re, logging, secrets, hashlib, smtplib
from functools import wraps
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, request, jsonify, render_template
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity, verify_jwt_in_request
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from dotenv import load_dotenv
import joblib, pandas as pd, numpy as np
from web3 import Web3
from database import db, User, Transaction, FraudAlert, AuditLog, PasswordResetToken, BlockchainAuditBlock

load_dotenv()

# Journalisation 
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("security.log", encoding="utf-8"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


#  CONNEXION BLOCKCHAIN 
w3         = Web3(Web3.HTTPProvider(os.getenv("RPC_URL", "http://127.0.0.1:7545")))
ADMIN_ADDR = os.getenv("ADMIN_ADDRESS", "0x0")
ADMIN_KEY  = os.getenv("ADMIN_PRIVATE_KEY", "0x0")


#  CONFIGURATION EMAIL (SMTP Gmail)  
MAIL_SERVER   = os.getenv("MAIL_SERVER",   "smtp.gmail.com")
MAIL_PORT     = int(os.getenv("MAIL_PORT", "587"))
MAIL_USERNAME = os.getenv("MAIL_USERNAME", "")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD", "")
RESET_TOKEN_EXPIRY_MIN = 30

#  SUPER ADMIN 
SUPERADMIN_EMAIL = "nganouarthur9@gmail.com"
SUPERADMIN_PASS  = "GTA@237"


#  CONFIGURATION FLASK 
app = Flask(__name__)
app.config["JWT_SECRET_KEY"]           = os.getenv("JWT_SECRET", os.urandom(32).hex())
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = datetime.timedelta(hours=8)
app.config["SQLALCHEMY_DATABASE_URI"]  = "sqlite:///fintech.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)
JWTManager(app)
CORS(app, resources={r"/*": {"origins": ["http://127.0.0.1:5000", "http://localhost:5000"]}})
limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["200/day", "50/hour"])

transactions_db = []


# MIGRATION : ajoute les colonnes manquantes sans perdre les données ──
def _migrate_db():
    from sqlalchemy import text, inspect as sa_inspect
    inspector = sa_inspect(db.engine)

    user_cols = [c["name"] for c in inspector.get_columns("users")]
    migrations = [
        ("is_active",     "BOOLEAN DEFAULT 1"),
        ("failed_logins", "INTEGER DEFAULT 0"),
        ("locked_until",  "DATETIME"),
        ("role",          "VARCHAR(20) DEFAULT 'user'"),
    ]
    with db.engine.connect() as conn:
        for col, definition in migrations:
            if col not in user_cols:
                conn.execute(text(f"ALTER TABLE users ADD COLUMN {col} {definition}"))
                logger.info("Migration : colonne '%s' ajoutée à users", col)

        # email_sent sur fraud_alerts
        if "fraud_alerts" in sa_inspect(db.engine).get_table_names():
            fa_cols = [c["name"] for c in inspector.get_columns("fraud_alerts")]
            if "email_sent" not in fa_cols:
                conn.execute(text("ALTER TABLE fraud_alerts ADD COLUMN email_sent BOOLEAN DEFAULT 0"))
                logger.info("Migration : colonne 'email_sent' ajoutée à fraud_alerts")

        conn.commit()


# BLOCKCHAIN AUDIT CHAIN 
def _add_audit_block(event_type: str, data: dict) -> BlockchainAuditBlock:
    """
    Ajoute un bloc immuable à la chaîne d'audit.
    Chaque hash intègre le hash du bloc précédent — modification
    d'un bloc invalide tous les blocs suivants (principe blockchain).
    """
    last      = BlockchainAuditBlock.query.order_by(BlockchainAuditBlock.block_index.desc()).first()
    prev_hash = last.block_hash if last else "0" * 64
    index     = (last.block_index + 1) if last else 0

    data_str   = json.dumps(data, sort_keys=True, ensure_ascii=False)
    content    = f"{index}|{event_type}|{data_str}|{prev_hash}"
    block_hash = hashlib.sha256(content.encode()).hexdigest()

    block = BlockchainAuditBlock(
        block_index   = index,
        event_type    = event_type,
        data          = data_str,
        previous_hash = prev_hash,
        block_hash    = block_hash,
    )
    db.session.add(block)
    db.session.commit()
    return block


#  CRÉATION DU SUPER ADMIN 
def _create_superadmin():
    if not User.query.filter_by(email=SUPERADMIN_EMAIL).first():
        admin = User(
            email          = SUPERADMIN_EMAIL,
            wallet_address = "0x0000000000000000000000000000000000000000",
            role           = "superadmin",
            is_active      = True,
            failed_logins  = 0,
        )
        admin.set_password(SUPERADMIN_PASS)
        db.session.add(admin)
        db.session.commit()
        logger.info("Super admin créé : %s", SUPERADMIN_EMAIL)

    if BlockchainAuditBlock.query.count() == 0:
        _add_audit_block("GENESIS", {
            "message": "Bloc genèse — Chaîne d'audit GTA-IT Fintech",
            "admin"  : SUPERADMIN_EMAIL,
            "version": "1.0",
        })
        logger.info("Bloc genèse de la chaîne d'audit créé")


# Créer les tables + migrer + initialiser super admin 
with app.app_context():
    db.create_all()
    _migrate_db()
    _create_superadmin()
    logger.info("Base de données SQLite prête")


#  CHARGEMENT CONTRATS BLOCKCHAIN 
def load_abi(name):
    with open(f"abi/{name}.json") as f:
        return json.load(f)

token_contract     = w3.eth.contract(address=Web3.to_checksum_address(os.getenv("TOKEN_ADDRESS",     "0x0")), abi=load_abi("FintechToken"))
registry_contract  = w3.eth.contract(address=Web3.to_checksum_address(os.getenv("REGISTRY_ADDRESS",  "0x0")), abi=load_abi("FraudRegistry"))
optimizer_contract = w3.eth.contract(address=Web3.to_checksum_address(os.getenv("OPTIMIZER_ADDRESS", "0x0")), abi=load_abi("TransactionOptimizer"))


#  CHARGEMENT MODÈLE IA 
fraud_model = joblib.load("models/fraud_detector.pkl")
scaler      = joblib.load("models/scaler.pkl")

with open("models/feature_columns.json") as f:
    FEATURE_COLS = json.load(f)

logger.info("Modèle IA chargé")
logger.info("Connexion blockchain : %s", w3.is_connected())


# ══════════════════════════════════════════════════════════════
# EN-TÊTES DE SÉCURITÉ HTTP
# ══════════════════════════════════════════════════════════════
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"]        = "DENY"
    response.headers["X-XSS-Protection"]       = "1; mode=block"
    response.headers["Referrer-Policy"]        = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"]     = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self';"
    )
    return response


# ══════════════════════════════════════════════════════════════
# HELPERS — VALIDATION DES ENTRÉES
# ══════════════════════════════════════════════════════════════
_EMAIL_RE  = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')
_WALLET_RE = re.compile(r'^0x[a-fA-F0-9]{40}$')

def is_valid_email(email: str) -> bool:
    return bool(_EMAIL_RE.match(email))

def is_valid_wallet(wallet: str) -> bool:
    return bool(_WALLET_RE.match(wallet))

def is_strong_password(password: str) -> bool:
    return len(password) >= 8 and bool(re.search(r'[0-9]', password)) and bool(re.search(r'[a-zA-Z]', password))


# ══════════════════════════════════════════════════════════════
# HELPER — JOURNAL D'AUDIT
# ══════════════════════════════════════════════════════════════
def audit(event_type: str, email: str = None, success: bool = True, details: str = None):
    try:
        entry = AuditLog(
            event_type = event_type,
            email      = email,
            ip_address = request.remote_addr,
            user_agent = request.headers.get("User-Agent", "")[:200],
            details    = details,
            success    = success,
        )
        db.session.add(entry)
        db.session.commit()
    except Exception as exc:
        logger.error("Erreur audit log : %s", exc)
    log_fn = logger.info if success else logger.warning
    log_fn("AUDIT | %s | email=%s | ip=%s | %s", event_type, email, request.remote_addr, details or "")


# ══════════════════════════════════════════════════════════════
# HELPER — SUPER ADMIN REQUIS
# ══════════════════════════════════════════════════════════════
def superadmin_required(fn):
    """Décorateur : vérifie que le JWT appartient au super administrateur."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        identity = get_jwt_identity()
        user = User.query.filter_by(email=identity).first()
        if not user or user.role != "superadmin":
            return jsonify({"error": "Accès réservé au super administrateur"}), 403
        return fn(*args, **kwargs)
    return wrapper


# ══════════════════════════════════════════════════════════════
# HELPER — ENVOI D'EMAIL (SMTP)
# ══════════════════════════════════════════════════════════════
def send_email(to_email: str, subject: str, html_body: str) -> bool:
    if not MAIL_USERNAME or not MAIL_PASSWORD:
        logger.warning("MAIL_USERNAME/MAIL_PASSWORD non configurés — email non envoyé à %s", to_email)
        return False

    msg            = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = MAIL_USERNAME
    msg["To"]      = to_email
    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(MAIL_SERVER, MAIL_PORT, timeout=15) as server:
            server.starttls()
            server.login(MAIL_USERNAME, MAIL_PASSWORD)
            server.sendmail(MAIL_USERNAME, to_email, msg.as_string())
        return True
    except Exception as exc:
        logger.error("Échec envoi email à %s : %s", to_email, exc)
        return False


def generate_reset_token() -> tuple[str, str]:
    raw_token  = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    return raw_token, token_hash


def build_reset_email_html(reset_link: str) -> str:
    return f"""
    <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto;">
      <div style="background: linear-gradient(90deg, #CC0000, #E53E3E); padding: 4px;"></div>
      <div style="padding: 2rem; background:#F5F7FA;">
        <h2 style="color:#1A202C;">Réinitialisation de mot de passe</h2>
        <p style="color:#2D3748; font-size:0.95rem; line-height:1.6;">
          Vous avez demandé à réinitialiser votre mot de passe sur <b>GTA-IT Fintech</b>.
          Cliquez sur le bouton ci-dessous pour choisir un nouveau mot de passe.
          Ce lien est valable <b>{RESET_TOKEN_EXPIRY_MIN} minutes</b>.
        </p>
        <p style="text-align:center; margin: 2rem 0;">
          <a href="{reset_link}"
             style="background:#CC0000; color:#fff; text-decoration:none; padding:0.8rem 1.5rem;
                    border-radius:8px; font-weight:bold; display:inline-block;">
            Réinitialiser mon mot de passe
          </a>
        </p>
        <p style="color:#718096; font-size:0.8rem;">
          Si vous n'êtes pas à l'origine de cette demande, ignorez simplement cet email.
        </p>
      </div>
    </div>
    """


def build_fraud_alert_email(tx_data: dict, fraud_result: dict, block_hash: str = "") -> str:
    level   = fraud_result.get("risk_level", "HIGH")
    score   = fraud_result.get("risk_score", 0)
    color   = "#7C3AED" if level == "HIGH" else "#CC0000"
    return f"""
    <div style="font-family:Arial,sans-serif;max-width:580px;margin:0 auto;">
      <div style="background:linear-gradient(90deg,{color},#CC0000);padding:5px;"></div>
      <div style="background:#1A202C;padding:2rem;color:#F5F7FA;">
        <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:1.5rem;">
          <span style="font-size:2rem;">🚨</span>
          <div>
            <h2 style="margin:0;color:#F56565;">Alerte de Fraude Détectée</h2>
            <span style="font-family:monospace;font-size:0.75rem;background:{color};
                         color:#fff;padding:0.2rem 0.7rem;border-radius:20px;">
              {level} RISK — Score {score}/100
            </span>
          </div>
        </div>
        <table style="width:100%;border-collapse:collapse;font-family:monospace;font-size:0.82rem;">
          <tr style="border-bottom:1px solid #2D3748;">
            <td style="padding:0.6rem;color:#718096;width:40%;">Référence TX</td>
            <td style="padding:0.6rem;color:#E2E8F0;">{tx_data.get("tx_ref","N/A")}</td>
          </tr>
          <tr style="border-bottom:1px solid #2D3748;">
            <td style="padding:0.6rem;color:#718096;">Expéditeur (wallet)</td>
            <td style="padding:0.6rem;color:#E2E8F0;">{tx_data.get("sender","N/A")}</td>
          </tr>
          <tr style="border-bottom:1px solid #2D3748;">
            <td style="padding:0.6rem;color:#718096;">Destinataire (wallet)</td>
            <td style="padding:0.6rem;color:#E2E8F0;">{tx_data.get("receiver","N/A")}</td>
          </tr>
          <tr style="border-bottom:1px solid #2D3748;">
            <td style="padding:0.6rem;color:#718096;">Montant</td>
            <td style="padding:0.6rem;color:#F6AD55;font-weight:bold;">{tx_data.get("amount",0)} FTK</td>
          </tr>
          <tr style="border-bottom:1px solid #2D3748;">
            <td style="padding:0.6rem;color:#718096;">Score de Risque IA</td>
            <td style="padding:0.6rem;color:#F56565;font-weight:bold;">{score} / 100</td>
          </tr>
          <tr style="border-bottom:1px solid #2D3748;">
            <td style="padding:0.6rem;color:#718096;">Niveau de Menace</td>
            <td style="padding:0.6rem;color:#F56565;font-weight:bold;">{level}</td>
          </tr>
          <tr style="border-bottom:1px solid #2D3748;">
            <td style="padding:0.6rem;color:#718096;">Statut</td>
            <td style="padding:0.6rem;color:#FC8181;">🛑 TRANSACTION BLOQUÉE</td>
          </tr>
          <tr>
            <td style="padding:0.6rem;color:#718096;">Hash bloc blockchain</td>
            <td style="padding:0.6rem;color:#68D391;font-family:monospace;font-size:0.72rem;">
              {block_hash[:32] + "..." if block_hash else "En cours d'enregistrement"}
            </td>
          </tr>
        </table>
        <div style="margin-top:1.5rem;padding:1rem;background:#2D3748;border-radius:8px;
                    border-left:4px solid {color};">
          <p style="margin:0;color:#CBD5E0;font-size:0.8rem;">
            Cette alerte a été générée automatiquement par le modèle IA <b>RandomForest_v1</b>
            de GTA-IT Fintech. L'événement a été enregistré de façon immuable dans la
            chaîne d'audit blockchain.
          </p>
        </div>
        <p style="margin-top:1rem;color:#4A5568;font-size:0.72rem;">
          GTA-IT Fintech · Système de détection de fraude IA + Blockchain
        </p>
      </div>
    </div>
    """


# ══════════════════════════════════════════════════════════════
# HELPER — TRANSACTION BLOCKCHAIN
# ══════════════════════════════════════════════════════════════
def send_blockchain_tx(contract_function):
    try:
        nonce   = w3.eth.get_transaction_count(ADMIN_ADDR)
        tx      = contract_function.build_transaction({
            "from": ADMIN_ADDR, "nonce": nonce, "gas": 300_000, "gasPrice": w3.eth.gas_price,
        })
        signed  = w3.eth.account.sign_transaction(tx, private_key=ADMIN_KEY)
        tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
        return {"tx_hash": tx_hash.hex(), "status": "success" if receipt.status == 1 else "failed"}
    except Exception as e:
        return {"tx_hash": None, "status": "error", "error": str(e)}


# ══════════════════════════════════════════════════════════════
# HELPER — PRÉDICTION IA
# ══════════════════════════════════════════════════════════════
def predict_fraud(features_dict: dict) -> dict:
    row = {col: 0.0 for col in FEATURE_COLS}
    if "Amount" in features_dict: row["Amount"] = features_dict["Amount"]
    if "Time"   in features_dict: row["Time"]   = features_dict["Time"]

    df = pd.DataFrame([row])
    df[["Amount", "Time"]] = scaler.transform(df[["Amount", "Time"]])
    proba      = fraud_model.predict_proba(df)[0]
    fraud_prob = float(proba[1])
    risk_score = int(fraud_prob * 100)

    if fraud_prob < 0.30:   risk_level, blocked = "LOW",      False
    elif fraud_prob < 0.60: risk_level, blocked = "MEDIUM",   False
    elif fraud_prob < 0.85: risk_level, blocked = "HIGH",     True
    else:                   risk_level, blocked = "CRITICAL", True

    return {"fraud_probability": round(fraud_prob, 4), "risk_score": risk_score,
            "risk_level": risk_level, "blocked": blocked}


# ══════════════════════════════════════════════════════════════
# PAGES HTML
# ══════════════════════════════════════════════════════════════
@app.route("/")
def index():
    return render_template("login.html")

@app.route("/register")
def register_page():
    return render_template("register.html")

@app.route("/forgot-password")
def forgot_password_page():
    return render_template("forgot_password.html")

@app.route("/reset-password")
def reset_password_page():
    return render_template("reset_password.html")

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

@app.route("/transactions")
def transactions_page():
    return render_template("transactions.html")

@app.route("/fraudes")
def fraudes_page():
    return render_template("fraudes.html")

@app.route("/token")
def token_page():
    return render_template("token.html")

@app.route("/optimisation")
def optimisation_page():
    return render_template("optimisation.html")

@app.route("/superadmin")
def superadmin_page():
    return render_template("superadmin.html")


# ══════════════════════════════════════════════════════════════
# AUTH
# ══════════════════════════════════════════════════════════════
MAX_FAILED_LOGINS = 5
LOCKOUT_MINUTES   = 15

@app.route("/auth/register", methods=["POST"])
@limiter.limit("5/minute")
def register():
    data     = request.get_json(silent=True) or {}
    email    = data.get("email",          "").strip().lower()
    password = data.get("password",       "")
    wallet   = data.get("wallet_address", "").strip()

    if not email or not password or not wallet:
        return jsonify({"error": "email, password et wallet_address obligatoires"}), 400
    if not is_valid_email(email):
        return jsonify({"error": "Format d'email invalide"}), 400
    if not is_strong_password(password):
        return jsonify({"error": "Mot de passe trop faible (min 8 caractères, 1 lettre et 1 chiffre)"}), 400
    if not is_valid_wallet(wallet):
        return jsonify({"error": "Adresse wallet invalide (format : 0x suivi de 40 caractères hex)"}), 400

    if User.query.filter_by(email=email).first():
        audit("REGISTER_DUPLICATE", email, success=False, details="Email déjà utilisé")
        return jsonify({"error": "Un compte avec ces informations existe déjà"}), 409

    user = User(email=email, wallet_address=wallet)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    audit("REGISTER", email, success=True, details=f"wallet={wallet[:10]}…")

    mint_tx = None
    try:
        receipt = send_blockchain_tx(
            token_contract.functions.mint(Web3.to_checksum_address(wallet), int(1000 * 10**18))
        )
        mint_tx = receipt.get("tx_hash")
    except Exception as e:
        logger.error("Mint error pour %s : %s", email, e)

    try:
        _add_audit_block("USER_REGISTERED", {"email": email, "wallet": wallet[:10]})
    except Exception as e:
        logger.error("Audit block error : %s", e)

    token = create_access_token(identity=email)
    return jsonify({
        "message": "Compte créé ! 1000 FTK offerts.",
        "wallet": wallet, "mint_tx": mint_tx, "access_token": token,
    }), 201


@app.route("/auth/login", methods=["POST"])
@limiter.limit("10/minute")
def login():
    data     = request.get_json(silent=True) or {}
    email    = data.get("email",    "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"error": "email et password obligatoires"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        audit("LOGIN_FAILED", email, success=False, details="Compte inexistant")
        return jsonify({"error": "Email ou mot de passe incorrect"}), 401

    if user.is_locked():
        remaining = int((user.locked_until - datetime.datetime.utcnow()).total_seconds() / 60)
        audit("LOGIN_LOCKED", email, success=False)
        return jsonify({"error": f"Compte verrouillé. Réessayez dans {remaining} minute(s)."}), 403

    if not user.check_password(password):
        user.failed_logins = (user.failed_logins or 0) + 1
        if user.failed_logins >= MAX_FAILED_LOGINS:
            user.locked_until  = datetime.datetime.utcnow() + datetime.timedelta(minutes=LOCKOUT_MINUTES)
            user.failed_logins = 0
            db.session.commit()
            audit("LOGIN_LOCKOUT", email, success=False)
            return jsonify({"error": f"Trop de tentatives. Compte verrouillé {LOCKOUT_MINUTES} minutes."}), 403
        db.session.commit()
        audit("LOGIN_FAILED", email, success=False, details=f"Tentative {user.failed_logins}/{MAX_FAILED_LOGINS}")
        return jsonify({"error": "Email ou mot de passe incorrect"}), 401

    user.failed_logins = 0
    user.locked_until  = None
    db.session.commit()
    audit("LOGIN", email, success=True)

    try:
        _add_audit_block("LOGIN", {"email": email, "role": user.role})
    except Exception as e:
        logger.error("Audit block error : %s", e)

    token = create_access_token(identity=email)
    return jsonify({
        "access_token": token,
        "wallet"      : user.wallet_address,
        "email"       : email,
        "role"        : user.role,
    })


@app.route("/auth/login-metamask", methods=["POST"])
@limiter.limit("10/minute")
def login_metamask():
    data   = request.get_json(silent=True) or {}
    wallet = data.get("wallet_address", "").strip()

    if not wallet or not is_valid_wallet(wallet):
        return jsonify({"error": "wallet_address invalide"}), 400

    email = f"{wallet.lower()}@metamask.local"
    user  = User.query.filter_by(email=email).first()
    if not user:
        user = User(email=email, wallet_address=wallet)
        db.session.add(user)
        db.session.commit()
        audit("REGISTER_METAMASK", email, success=True)

    audit("LOGIN_METAMASK", email, success=True)
    token = create_access_token(identity=email)
    return jsonify({"access_token": token, "wallet": wallet, "role": user.role})


@app.route("/auth/forgot-password", methods=["POST"])
@limiter.limit("3/minute")
def forgot_password():
    data  = request.get_json(silent=True) or {}
    email = data.get("email", "").strip().lower()

    generic = jsonify({"message": "Si un compte existe avec cet email, un lien de réinitialisation a été envoyé."})

    if not email or not is_valid_email(email):
        return generic, 200

    user = User.query.filter_by(email=email).first()
    if not user:
        audit("FORGOT_PASSWORD_UNKNOWN", email, success=False)
        return generic, 200

    raw_token, token_hash = generate_reset_token()
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=RESET_TOKEN_EXPIRY_MIN)

    db.session.add(PasswordResetToken(user_id=user.id, token_hash=token_hash, expires_at=expires_at))
    db.session.commit()

    reset_link = f"{request.host_url.rstrip('/')}/reset-password?token={raw_token}"
    sent = send_email(email, "Réinitialisation de mot de passe. GTA-IT Fintech", build_reset_email_html(reset_link))

    if sent:
        audit("FORGOT_PASSWORD_SENT", email, success=True)
    else:
        audit("FORGOT_PASSWORD_EMAIL_FAILED", email, success=False, details=f"lien={reset_link}")
        logger.warning("Lien de réinitialisation (email non envoyé) : %s", reset_link)

    return generic, 200


@app.route("/auth/reset-password", methods=["POST"])
@limiter.limit("5/minute")
def reset_password():
    data         = request.get_json(silent=True) or {}
    token        = data.get("token", "")
    new_password = data.get("password", "")

    if not token or not new_password:
        return jsonify({"error": "token et password obligatoires"}), 400
    if not is_strong_password(new_password):
        return jsonify({"error": "Mot de passe trop faible (min 8 caractères, 1 lettre et 1 chiffre)"}), 400

    token_hash  = hashlib.sha256(token.encode()).hexdigest()
    reset_entry = PasswordResetToken.query.filter_by(token_hash=token_hash).first()

    if not reset_entry or not reset_entry.is_valid():
        audit("RESET_PASSWORD_INVALID", success=False, details="Token invalide, utilisé ou expiré")
        return jsonify({"error": "Lien invalide ou expiré. Merci de refaire une demande."}), 400

    user = User.query.get(reset_entry.user_id)
    user.set_password(new_password)
    user.failed_logins = 0
    user.locked_until  = None
    reset_entry.used   = True
    db.session.commit()

    audit("RESET_PASSWORD_SUCCESS", user.email, success=True)
    return jsonify({"message": "Mot de passe réinitialisé avec succès. Vous pouvez vous connecter."})


# ══════════════════════════════════════════════════════════════
# WALLET
# ══════════════════════════════════════════════════════════════
@app.route("/wallet/balance/<address>", methods=["GET"])
@jwt_required()
def get_balance(address):
    if not is_valid_wallet(address):
        return jsonify({"error": "Adresse invalide"}), 400
    try:
        raw     = token_contract.functions.balanceOf(Web3.to_checksum_address(address)).call()
        balance = raw / 10**18
        return jsonify({"address": address, "balance": balance, "symbol": "FTK"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ══════════════════════════════════════════════════════════════
# TRANSACTIONS
# ══════════════════════════════════════════════════════════════
@app.route("/transactions/send", methods=["POST"])
@jwt_required()
@limiter.limit("30/minute")
def send_transaction():
    data     = request.get_json(silent=True) or {}
    identity = get_jwt_identity()
    user     = User.query.filter_by(email=identity).first()
    sender   = user.wallet_address if user else "0x0"

    receiver = data.get("receiver", "").strip()
    amount   = float(data.get("amount", 0))
    hour     = int(data.get("hour_of_day", datetime.datetime.now().hour))

    if not receiver or amount <= 0:
        return jsonify({"error": "receiver et amount obligatoires"}), 400
    if not is_valid_wallet(receiver):
        return jsonify({"error": "Adresse receiver invalide"}), 400

    tx_ref       = str(uuid.uuid4())
    fraud_result = predict_fraud({"Amount": amount, "Time": hour * 3600})

    tx_record = {
        "id": tx_ref, "sender": sender, "receiver": receiver, "amount": amount,
        "risk_score": fraud_result["risk_score"], "risk_level": fraud_result["risk_level"],
        "blocked": fraud_result["blocked"],
        "timestamp": datetime.datetime.now().strftime("%d/%m %H:%M"),
    }
    transactions_db.append(tx_record)

    # Persistance en base de données
    db_tx = Transaction(
        tx_ref     = tx_ref,
        sender     = sender,
        receiver   = receiver,
        amount     = amount,
        risk_score = fraud_result["risk_score"],
        risk_level = fraud_result["risk_level"],
        blocked    = fraud_result["blocked"],
        user_id    = user.id if user else None,
    )
    db.session.add(db_tx)
    db.session.commit()

    if fraud_result["blocked"]:
        # Enregistrement blockchain
        try:
            send_blockchain_tx(registry_contract.functions.reportFraud(
                Web3.to_checksum_address(sender), Web3.to_checksum_address(receiver),
                int(amount * 10**18), fraud_result["risk_score"], fraud_result["risk_level"],
                "RandomForest_v1", True, tx_ref[:32]
            ))
        except Exception as e:
            logger.error("Registry error : %s", e)

        # Alerte fraude en DB
        alert = FraudAlert(
            suspect    = sender,
            amount     = amount,
            risk_score = fraud_result["risk_score"],
            risk_level = fraud_result["risk_level"],
            tx_ref     = tx_ref,
            email_sent = False,
        )
        db.session.add(alert)
        db.session.commit()

        # Bloc d'audit immuable
        audit_block = None
        try:
            audit_block = _add_audit_block("FRAUD_DETECTED", {
                "tx_ref"    : tx_ref,
                "sender"    : sender,
                "receiver"  : receiver,
                "amount"    : amount,
                "risk_score": fraud_result["risk_score"],
                "risk_level": fraud_result["risk_level"],
            })
        except Exception as e:
            logger.error("Audit block error : %s", e)

        # Email de notification au super admin
        try:
            if fraud_result["risk_level"] in ("HIGH", "CRITICAL"):
                block_hash = audit_block.block_hash if audit_block else ""
                sent = send_email(
                    SUPERADMIN_EMAIL,
                    f"🚨 Alerte Fraude {fraud_result['risk_level']} — GTA-IT Fintech",
                    build_fraud_alert_email(
                        {"tx_ref": tx_ref, "sender": sender, "receiver": receiver, "amount": amount},
                        fraud_result,
                        block_hash,
                    )
                )
                if sent:
                    alert.email_sent = True
                    db.session.commit()
                    logger.info("Email alerte fraude envoyé au super admin pour tx=%s", tx_ref)
        except Exception as e:
            logger.error("Fraud email error : %s", e)

        audit("TX_BLOCKED", identity, success=False,
              details=f"amount={amount} receiver={receiver[:10]} score={fraud_result['risk_score']}")
        return jsonify({"status": "BLOCKED", "risk_score": fraud_result["risk_score"],
                        "risk_level": fraud_result["risk_level"], "tx_ref": tx_ref}), 403

    gas_estimated = max(21000, min(int(50000 - hour * 1000), 200000))
    route_score   = max(0, 100 - (hour * 2))
    optimizer_tx  = None
    try:
        receipt = send_blockchain_tx(optimizer_contract.functions.recordOptimizedTransaction(
            Web3.to_checksum_address(receiver), int(amount * 10**18), gas_estimated, route_score,
            f"IA: score={fraud_result['risk_score']}, gas={gas_estimated}"
        ))
        optimizer_tx = receipt.get("tx_hash")
    except Exception as e:
        logger.error("Optimizer error : %s", e)

    tx_record["optimizer_tx"] = optimizer_tx
    db_tx.tx_hash = optimizer_tx
    db.session.commit()

    try:
        _add_audit_block("TRANSACTION_SENT", {
            "tx_ref"    : tx_ref,
            "sender"    : sender,
            "receiver"  : receiver,
            "amount"    : amount,
            "risk_score": fraud_result["risk_score"],
            "risk_level": fraud_result["risk_level"],
        })
    except Exception as e:
        logger.error("Audit block error : %s", e)

    return jsonify({
        "status": "SUCCESS", "tx_ref": tx_ref, "sender": sender, "receiver": receiver,
        "amount": amount, "risk_score": fraud_result["risk_score"], "risk_level": fraud_result["risk_level"],
        "estimated_gas": gas_estimated, "route_score": route_score, "optimizer_tx": optimizer_tx,
    })


@app.route("/transactions/recent", methods=["GET"])
@jwt_required()
def recent_transactions():
    return jsonify({"transactions": list(reversed(transactions_db))[:20], "total": len(transactions_db)})


@app.route("/transactions/all", methods=["GET"])
@jwt_required()
def all_transactions():
    identity = get_jwt_identity()
    user     = User.query.filter_by(email=identity).first()
    wallet   = user.wallet_address.lower() if user else ""
    my_txs   = [t for t in transactions_db
                if t["sender"].lower() == wallet or t["receiver"].lower() == wallet]
    return jsonify({"transactions": list(reversed(my_txs)), "total": len(my_txs)})


# ══════════════════════════════════════════════════════════════
# FRAUDE
# ══════════════════════════════════════════════════════════════
@app.route("/fraud/reports", methods=["GET"])
@jwt_required()
def fraud_reports():
    try:
        stats   = registry_contract.functions.getStats().call()
        total, blocked, ratio = stats[0], stats[1], f"{stats[2]}%"
    except Exception:
        total   = len(transactions_db)
        blocked = sum(1 for t in transactions_db if t.get("blocked"))
        ratio   = f"{int(blocked/total*100) if total else 0}%"
    return jsonify({"total_reports": total, "total_blocked": blocked, "block_ratio": ratio})


@app.route("/fraud/list", methods=["GET"])
@jwt_required()
def fraud_list():
    frauds = [t for t in transactions_db if t.get("blocked")]
    return jsonify({"frauds": list(reversed(frauds)), "total": len(frauds)})


@app.route("/fraud/check/<address>", methods=["GET"])
@jwt_required()
def check_address(address):
    if not is_valid_wallet(address):
        return jsonify({"error": "Adresse invalide"}), 400
    try:
        is_high_risk, count = registry_contract.functions.isHighRiskAddress(
            Web3.to_checksum_address(address)).call()
        is_blacklisted = token_contract.functions.blacklisted(
            Web3.to_checksum_address(address)).call()
        return jsonify({"address": address, "is_high_risk": is_high_risk,
                        "fraud_count": count, "is_blacklisted": is_blacklisted})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ══════════════════════════════════════════════════════════════
# OPTIMISATION
# ══════════════════════════════════════════════════════════════
@app.route("/optimization/gas-estimate", methods=["GET"])
@jwt_required()
def gas_estimate():
    try:
        params = optimizer_contract.functions.getOptimizationParams().call()
        return jsonify({"recommended_gas_price": params[0] or 20,
                        "network_load": f"{params[1]}%", "last_updated": params[2]})
    except Exception:
        hour = datetime.datetime.now().hour
        return jsonify({"recommended_gas_price": int(max(10, 50 - hour * 1.5)),
                        "network_load": "45%", "last_updated": 0})


# ══════════════════════════════════════════════════════════════
# STATUS
# ══════════════════════════════════════════════════════════════
@app.route("/status", methods=["GET"])
def status():
    return jsonify({
        "blockchain_connected": w3.is_connected(),
        "chain_id"            : w3.eth.chain_id if w3.is_connected() else None,
        "ia_model_loaded"     : fraud_model is not None,
        "total_transactions"  : len(transactions_db),
    })


# ══════════════════════════════════════════════════════════════
# SUPER ADMIN — API
# ══════════════════════════════════════════════════════════════

@app.route("/superadmin/api/stats", methods=["GET"])
@superadmin_required
def superadmin_stats():
    total_users   = User.query.count()
    total_tx      = Transaction.query.count()
    total_blocked = Transaction.query.filter_by(blocked=True).count()
    total_alerts  = FraudAlert.query.count()
    total_blocks  = BlockchainAuditBlock.query.count()

    # Vérification intégrité de la chaîne
    blocks      = BlockchainAuditBlock.query.order_by(BlockchainAuditBlock.block_index.asc()).all()
    chain_valid = True
    for i, blk in enumerate(blocks):
        expected = hashlib.sha256(
            f"{blk.block_index}|{blk.event_type}|{blk.data}|{blk.previous_hash}".encode()
        ).hexdigest()
        hash_ok = blk.block_hash == expected
        if i == 0:
            prev_ok = blk.previous_hash == "0" * 64
        else:
            prev_ok = blk.previous_hash == blocks[i-1].block_hash
        if not (hash_ok and prev_ok):
            chain_valid = False
            break

    return jsonify({
        "total_users"   : total_users,
        "total_tx"      : total_tx,
        "total_blocked" : total_blocked,
        "total_alerts"  : total_alerts,
        "total_blocks"  : total_blocks,
        "chain_valid"   : chain_valid,
        "block_ratio"   : f"{int(total_blocked / total_tx * 100) if total_tx else 0}%",
    })


@app.route("/superadmin/api/transactions", methods=["GET"])
@superadmin_required
def superadmin_transactions():
    limit = min(int(request.args.get("limit", 50)), 200)
    txs   = Transaction.query.order_by(Transaction.created_at.desc()).limit(limit).all()
    return jsonify({
        "transactions": [t.to_dict() for t in txs],
        "total"       : Transaction.query.count(),
    })


@app.route("/superadmin/api/alerts", methods=["GET"])
@superadmin_required
def superadmin_alerts():
    limit  = min(int(request.args.get("limit", 50)), 200)
    alerts = FraudAlert.query.order_by(FraudAlert.created_at.desc()).limit(limit).all()
    return jsonify({
        "alerts": [a.to_dict() for a in alerts],
        "total" : FraudAlert.query.count(),
    })


@app.route("/superadmin/api/users", methods=["GET"])
@superadmin_required
def superadmin_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return jsonify({"users": [u.to_dict() for u in users], "total": len(users)})


@app.route("/superadmin/api/chain", methods=["GET"])
@superadmin_required
def superadmin_chain():
    limit  = min(int(request.args.get("limit", 20)), 100)
    blocks = BlockchainAuditBlock.query.order_by(BlockchainAuditBlock.block_index.desc()).limit(limit).all()
    return jsonify({
        "blocks": [b.to_dict() for b in blocks],
        "total" : BlockchainAuditBlock.query.count(),
    })


@app.route("/superadmin/api/chain/verify", methods=["GET"])
@superadmin_required
def verify_chain():
    blocks  = BlockchainAuditBlock.query.order_by(BlockchainAuditBlock.block_index.asc()).all()
    results = []
    chain_valid = True

    for i, blk in enumerate(blocks):
        expected = hashlib.sha256(
            f"{blk.block_index}|{blk.event_type}|{blk.data}|{blk.previous_hash}".encode()
        ).hexdigest()
        hash_ok = blk.block_hash == expected
        if i == 0:
            prev_ok = blk.previous_hash == "0" * 64
        else:
            prev_ok = blk.previous_hash == blocks[i-1].block_hash
        valid = hash_ok and prev_ok
        if not valid:
            chain_valid = False
        results.append({
            "block_index": blk.block_index,
            "event_type" : blk.event_type,
            "hash_ok"    : hash_ok,
            "prev_ok"    : prev_ok,
            "valid"      : valid,
        })

    return jsonify({
        "chain_valid" : chain_valid,
        "total_blocks": len(blocks),
        "blocks"      : results,
    })


# ══════════════════════════════════════════════════════════════
# DÉMARRAGE
# ══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    debug_mode = os.getenv("FLASK_ENV", "production") == "development"
    print("=" * 55)
    print(" Fintech GTA — Dashboard Flask")
    print(f"   Blockchain : {'Connecté' if w3.is_connected() else '[X] Déconnecté — Activez Ganache'}")
    print(f"   IA Model   : Chargé")
    print(f"   Super Admin: {SUPERADMIN_EMAIL}")
    print(f"   Mode debug : {'ON' if debug_mode else 'OFF'}")
    print(f"   URL        : http://127.0.0.1:5000")
    print(f"   Admin URL  : http://127.0.0.1:5000/superadmin")
    print("=" * 55)
    app.run(debug=debug_mode, host="0.0.0.0", port=5000)
