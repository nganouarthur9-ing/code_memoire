"""
app.py — Application Flask principale
Projet Fintech GTA — Cryptomonnaie + IA + Blockchain
"""

import os, uuid, json, datetime
from flask import Flask, request, jsonify, render_template
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from dotenv import load_dotenv
import joblib, pandas as pd, numpy as np
from web3 import Web3

load_dotenv()

# ══════════════════════════════════════════════════════════════
# CONFIGURATION FLASK
# ══════════════════════════════════════════════════════════════
app = Flask(__name__)
app.config["JWT_SECRET_KEY"]        = os.getenv("JWT_SECRET", "fintech-gta-2025")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = datetime.timedelta(hours=24)

CORS(app)
jwt     = JWTManager(app)
limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["200/minute"])

# CONNEXION BLOCKCHAIN (Ganache)
RPC_URL    = os.getenv("RPC_URL", "HTTP://127.0.0.1:7545")
w3         = Web3(Web3.HTTPProvider(RPC_URL))
ADMIN_ADDR = os.getenv("ADMIN_ADDRESS")
ADMIN_KEY  = os.getenv("ADMIN_PRIVATE_KEY")

# Charger les ABI
def load_abi(name):
    with open(f"abi/{name}.json") as f:
        return json.load(f)

token_contract     = w3.eth.contract(address=Web3.to_checksum_address(os.getenv("TOKEN_ADDRESS",     "0x0")), abi=load_abi("FintechToken"))
registry_contract  = w3.eth.contract(address=Web3.to_checksum_address(os.getenv("REGISTRY_ADDRESS",  "0x0")), abi=load_abi("FraudRegistry"))
optimizer_contract = w3.eth.contract(address=Web3.to_checksum_address(os.getenv("OPTIMIZER_ADDRESS", "0x0")), abi=load_abi("TransactionOptimizer"))

# CHARGEMENT MODÈLE IA
fraud_model = joblib.load("models/fraud_detector.pkl")
scaler      = joblib.load("models/scaler.pkl")

with open("models/feature_columns.json") as f:
    FEATURE_COLS = json.load(f)

print(" Modèle IA chargé")
print(" Connexion blockchain:", w3.is_connected())

# ══════════════════════════════════════════════════════════════
# BASE DONNÉES SIMPLE (dictionnaire en mémoire pour la démo)
# En production → remplacer par SQLite/PostgreSQL
# ══════════════════════════════════════════════════════════════
users_db       = {}   # { email: { password, wallet } }
transactions_db = []  # liste des transactions

# ══════════════════════════════════════════════════════════════
# HELPER — Envoyer une transaction blockchain
# ══════════════════════════════════════════════════════════════
def send_blockchain_tx(contract_function):
    """Signer et envoyer une transaction on-chain"""
    try:
        nonce = w3.eth.get_transaction_count(ADMIN_ADDR)
        tx    = contract_function.build_transaction({
            "from"     : ADMIN_ADDR,
            "nonce"    : nonce,
            "gas"      : 300_000,
            "gasPrice" : w3.eth.gas_price,
        })
        signed  = w3.eth.account.sign_transaction(tx, private_key=ADMIN_KEY)
        tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
        return { "tx_hash": tx_hash.hex(), "status": "success" if receipt.status == 1 else "failed" }
    except Exception as e:
        return { "tx_hash": None, "status": "error", "error": str(e) }

# ══════════════════════════════════════════════════════════════
# HELPER — Prédiction IA
# ══════════════════════════════════════════════════════════════
def predict_fraud(features_dict: dict) -> dict:
    """
    Analyser une transaction avec le modèle IA
    features_dict doit contenir les mêmes colonnes que le dataset
    """
    # Créer un DataFrame avec les valeurs par défaut (0) pour les features manquantes
    row = {col: 0.0 for col in FEATURE_COLS}
    # Remplir les valeurs connues
    if "Amount" in features_dict:
        row["Amount"] = features_dict["Amount"]
    if "Time" in features_dict:
        row["Time"]   = features_dict["Time"]

    df = pd.DataFrame([row])
    # Normaliser Amount et Time
    df[["Amount", "Time"]] = scaler.transform(df[["Amount", "Time"]])

    proba      = fraud_model.predict_proba(df)[0]
    fraud_prob = float(proba[1])
    risk_score = int(fraud_prob * 100)

    if fraud_prob < 0.30:
        risk_level, blocked = "LOW",      False
    elif fraud_prob < 0.60:
        risk_level, blocked = "MEDIUM",   False
    elif fraud_prob < 0.85:
        risk_level, blocked = "HIGH",     True
    else:
        risk_level, blocked = "CRITICAL", True

    return {
        "fraud_probability": round(fraud_prob, 4),
        "risk_score"       : risk_score,
        "risk_level"       : risk_level,
        "blocked"          : blocked,
    }

# ══════════════════════════════════════════════════════════════
# PAGES HTML
# ══════════════════════════════════════════════════════════════
@app.route("/")
def index():
    return render_template("login.html")

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

# ══════════════════════════════════════════════════════════════
# AUTH
# ══════════════════════════════════════════════════════════════
@app.route("/auth/register", methods=["POST"])
@limiter.limit("10/minute")
def register():
    data    = request.get_json()
    email   = data.get("email",          "").strip().lower()
    password= data.get("password",       "")
    wallet  = data.get("wallet_address", "")

    if not email or not password or not wallet:
        return jsonify({"error": "email, password et wallet_address obligatoires"}), 400
    if email in users_db:
        return jsonify({"error": "Email déjà utilisé"}), 409

    users_db[email] = { "password": password, "wallet": wallet }

    # Mint 1000 FTK de bienvenue
    try:
        amount_wei = int(1000 * 10**18)
        receipt = send_blockchain_tx(
            token_contract.functions.mint(Web3.to_checksum_address(wallet), amount_wei)
        )
        mint_tx = receipt.get("tx_hash")
    except Exception as e:
        mint_tx = None

    token = create_access_token(identity=email)
    return jsonify({
        "message"    : "Compte créé ! 1000 FTK offerts.",
        "wallet"     : wallet,
        "mint_tx"    : mint_tx,
        "access_token": token
    }), 201


@app.route("/auth/login", methods=["POST"])
@limiter.limit("20/minute")
def login():
    data     = request.get_json()
    email    = data.get("email",    "").strip().lower()
    password = data.get("password", "")

    user = users_db.get(email)
    if not user or user["password"] != password:
        return jsonify({"error": "Email ou mot de passe incorrect"}), 401

    token = create_access_token(identity=email)
    return jsonify({
        "access_token": token,
        "wallet"      : user["wallet"],
        "email"       : email
    })


@app.route("/auth/login-metamask", methods=["POST"])
def login_metamask():
    """Login direct avec adresse MetaMask"""
    data   = request.get_json()
    wallet = data.get("wallet_address", "")
    if not wallet:
        return jsonify({"error": "wallet_address obligatoire"}), 400

    # Auto-créer le compte si nouveau wallet
    email = f"{wallet.lower()}@metamask"
    if email not in users_db:
        users_db[email] = { "password": None, "wallet": wallet }

    token = create_access_token(identity=email)
    return jsonify({ "access_token": token, "wallet": wallet })

# ══════════════════════════════════════════════════════════════
# WALLET
# ══════════════════════════════════════════════════════════════
@app.route("/wallet/balance/<address>", methods=["GET"])
@jwt_required()
def get_balance(address):
    try:
        raw     = token_contract.functions.balanceOf(
            Web3.to_checksum_address(address)
        ).call()
        balance = raw / 10**18
        return jsonify({ "address": address, "balance": balance, "symbol": "FTK" })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ══════════════════════════════════════════════════════════════
# TRANSACTIONS
# ══════════════════════════════════════════════════════════════
@app.route("/transactions/send", methods=["POST"])
@jwt_required()
@limiter.limit("30/minute")
def send_transaction():
    data     = request.get_json()
    identity = get_jwt_identity()
    sender   = users_db.get(identity, {}).get("wallet", "0x0")
    receiver = data.get("receiver", "")
    amount   = float(data.get("amount", 0))
    hour     = int(data.get("hour_of_day", datetime.datetime.now().hour))

    if not receiver or amount <= 0:
        return jsonify({"error": "receiver et amount obligatoires"}), 400

    tx_ref = str(uuid.uuid4())

    # ── Analyse IA ────────────────────────────────────────────
    fraud_result = predict_fraud({
        "Amount": amount,
        "Time"  : hour * 3600
    })

    # Enregistrer en mémoire
    tx_record = {
        "id"        : tx_ref,
        "sender"    : sender,
        "receiver"  : receiver,
        "amount"    : amount,
        "risk_score": fraud_result["risk_score"],
        "risk_level": fraud_result["risk_level"],
        "blocked"   : fraud_result["blocked"],
        "timestamp" : datetime.datetime.now().strftime("%d/%m %H:%M"),
    }
    transactions_db.append(tx_record)

    # ── Si bloqué → enregistrer dans FraudRegistry ────────────
    if fraud_result["blocked"]:
        try:
            send_blockchain_tx(
                registry_contract.functions.reportFraud(
                    Web3.to_checksum_address(sender),
                    Web3.to_checksum_address(receiver),
                    int(amount * 10**18),
                    fraud_result["risk_score"],
                    fraud_result["risk_level"],
                    "RandomForest_v1",
                    True,
                    tx_ref[:32]
                )
            )
        except Exception as e:
            print(f"Registry error: {e}")

        return jsonify({
            "status"    : "BLOCKED",
            "risk_score": fraud_result["risk_score"],
            "risk_level": fraud_result["risk_level"],
            "tx_ref"    : tx_ref,
        }), 403

    # ── Enregistrer dans TransactionOptimizer ─────────────────
    gas_estimated = max(21000, min(int(50000 - hour * 1000), 200000))
    route_score   = max(0, 100 - (hour * 2))

    optimizer_tx = None
    try:
        receipt = send_blockchain_tx(
            optimizer_contract.functions.recordOptimizedTransaction(
                Web3.to_checksum_address(receiver),
                int(amount * 10**18),
                gas_estimated,
                route_score,
                f"IA: score={fraud_result['risk_score']}, gas={gas_estimated}"
            )
        )
        optimizer_tx = receipt.get("tx_hash")
    except Exception as e:
        print(f"Optimizer error: {e}")

    tx_record["optimizer_tx"] = optimizer_tx

    return jsonify({
        "status"           : "SUCCESS",
        "tx_ref"           : tx_ref,
        "sender"           : sender,
        "receiver"         : receiver,
        "amount"           : amount,
        "risk_score"       : fraud_result["risk_score"],
        "risk_level"       : fraud_result["risk_level"],
        "estimated_gas"    : gas_estimated,
        "route_score"      : route_score,
        "optimizer_tx"     : optimizer_tx,
    })


@app.route("/transactions/recent", methods=["GET"])
@jwt_required()
def recent_transactions():
    recent = list(reversed(transactions_db))[:20]
    return jsonify({ "transactions": recent, "total": len(transactions_db) })


@app.route("/transactions/all", methods=["GET"])
@jwt_required()
def all_transactions():
    identity = get_jwt_identity()
    wallet   = users_db.get(identity, {}).get("wallet", "").lower()
    my_txs   = [t for t in transactions_db
                if t["sender"].lower() == wallet or t["receiver"].lower() == wallet]
    return jsonify({ "transactions": list(reversed(my_txs)), "total": len(my_txs) })

# ══════════════════════════════════════════════════════════════
# FRAUDE
# ══════════════════════════════════════════════════════════════
@app.route("/fraud/reports", methods=["GET"])
@jwt_required()
def fraud_reports():
    try:
        stats   = registry_contract.functions.getStats().call()
        total   = stats[0]
        blocked = stats[1]
        ratio   = f"{stats[2]}%"
    except Exception:
        # Fallback sur les données en mémoire
        total   = len(transactions_db)
        blocked = sum(1 for t in transactions_db if t.get("blocked"))
        ratio   = f"{int(blocked/total*100) if total else 0}%"

    return jsonify({
        "total_reports": total,
        "total_blocked": blocked,
        "block_ratio"  : ratio,
    })


@app.route("/fraud/list", methods=["GET"])
@jwt_required()
def fraud_list():
    frauds = [t for t in transactions_db if t.get("blocked")]
    return jsonify({ "frauds": list(reversed(frauds)), "total": len(frauds) })


@app.route("/fraud/check/<address>", methods=["GET"])
@jwt_required()
def check_address(address):
    try:
        is_high_risk, count = registry_contract.functions\
            .isHighRiskAddress(Web3.to_checksum_address(address)).call()
        is_blacklisted = token_contract.functions\
            .blacklisted(Web3.to_checksum_address(address)).call()
        return jsonify({
            "address"       : address,
            "is_high_risk"  : is_high_risk,
            "fraud_count"   : count,
            "is_blacklisted": is_blacklisted,
        })
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
        return jsonify({
            "recommended_gas_price": params[0] or 20,
            "network_load"         : f"{params[1]}%",
            "last_updated"         : params[2],
        })
    except Exception:
        hour = datetime.datetime.now().hour
        gas  = max(10, 50 - hour * 1.5)
        return jsonify({
            "recommended_gas_price": int(gas),
            "network_load"         : "45%",
            "last_updated"         : 0,
        })

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
# DÉMARRAGE
# ══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("=" * 50)
    print(" Fintech GTA — Dashboard Flask")
    print(f"   Blockchain : {' Connecté' if w3.is_connected() else '❌ Déconnecté; Activez Ganache'}")
    print(f"   IA Model   : Chargé")
    print(f"   URL        : http://127.0.0.1:5000")
    print("=" * 50)
    app.run(debug=True, host="0.0.0.0", port=5000)
