"""
database.py — Gestion de la base de données SQLite
Projet Fintech GTA
"""

import json
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

db = SQLAlchemy()

def _now():
    return datetime.utcnow()


# TABLE 1 — Utilisateur
class User(db.Model):
    __tablename__ = "users"

    id             = db.Column(db.Integer, primary_key=True)
    email          = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash  = db.Column(db.String(255), nullable=True)
    wallet_address = db.Column(db.String(60),  nullable=False)
    role           = db.Column(db.String(20),  default="user")   # user | superadmin
    is_active      = db.Column(db.Boolean,  default=True)
    failed_logins  = db.Column(db.Integer,  default=0)
    locked_until   = db.Column(db.DateTime, nullable=True)
    created_at     = db.Column(db.DateTime, default=_now)

    transactions = db.relationship("Transaction", backref="user", lazy=True)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password, method="pbkdf2:sha256:600000")

    def check_password(self, password: str) -> bool:
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

    def is_locked(self) -> bool:
        if self.locked_until and _now() < self.locked_until:
            return True
        return False

    def to_dict(self):
        return {
            "id"            : self.id,
            "email"         : self.email,
            "wallet_address": self.wallet_address,
            "role"          : self.role,
            "is_active"     : self.is_active,
            "created_at"    : self.created_at.strftime("%d/%m/%Y %H:%M"),
        }


# TABLE 2 — Transactions
class Transaction(db.Model):
    __tablename__ = "transactions"

    id          = db.Column(db.Integer, primary_key=True)
    tx_ref      = db.Column(db.String(40), unique=True, nullable=False)
    sender      = db.Column(db.String(60), nullable=False)
    receiver    = db.Column(db.String(60), nullable=False)
    amount      = db.Column(db.Float,      nullable=False)
    risk_score  = db.Column(db.Integer,    default=0)
    risk_level  = db.Column(db.String(20), default="LOW")
    blocked     = db.Column(db.Boolean,    default=False)
    tx_hash     = db.Column(db.String(80), nullable=True)
    created_at  = db.Column(db.DateTime,   default=_now)
    user_id     = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    def to_dict(self):
        return {
            "id"        : self.id,
            "tx_ref"    : self.tx_ref,
            "sender"    : self.sender,
            "receiver"  : self.receiver,
            "amount"    : self.amount,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "blocked"   : self.blocked,
            "tx_hash"   : self.tx_hash,
            "timestamp" : self.created_at.strftime("%d/%m %H:%M"),
        }


# TABLE 3 — Alertes de Fraude
class FraudAlert(db.Model):
    __tablename__ = "fraud_alerts"

    id          = db.Column(db.Integer, primary_key=True)
    suspect     = db.Column(db.String(60), nullable=False)
    amount      = db.Column(db.Float,      nullable=False)
    risk_score  = db.Column(db.Integer,    nullable=False)
    risk_level  = db.Column(db.String(20), nullable=False)
    model_used  = db.Column(db.String(40), default="RandomForest")
    tx_ref      = db.Column(db.String(40), nullable=True)
    email_sent  = db.Column(db.Boolean,    default=False)
    created_at  = db.Column(db.DateTime,   default=_now)

    def to_dict(self):
        return {
            "id"        : self.id,
            "suspect"   : self.suspect,
            "amount"    : self.amount,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "model_used": self.model_used,
            "tx_ref"    : self.tx_ref,
            "email_sent": self.email_sent,
            "timestamp" : self.created_at.strftime("%d/%m %H:%M"),
        }


# TABLE 4 — Tokens de réinitialisation de mot de passe
class PasswordResetToken(db.Model):
    __tablename__ = "password_reset_tokens"

    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    token_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    expires_at = db.Column(db.DateTime, nullable=False)
    used       = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=_now)

    def is_valid(self) -> bool:
        return (not self.used) and _now() < self.expires_at


# TABLE 5 — Journal d'audit de sécurité
class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id         = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(50),  nullable=False)
    email      = db.Column(db.String(120), nullable=True)
    ip_address = db.Column(db.String(45),  nullable=True)
    user_agent = db.Column(db.String(200), nullable=True)
    details    = db.Column(db.Text,        nullable=True)
    success    = db.Column(db.Boolean,     default=True)
    created_at = db.Column(db.DateTime,    default=_now)

    def to_dict(self):
        return {
            "id"        : self.id,
            "event_type": self.event_type,
            "email"     : self.email,
            "ip_address": self.ip_address,
            "details"   : self.details,
            "success"   : self.success,
            "timestamp" : self.created_at.strftime("%d/%m/%Y %H:%M:%S"),
        }


# TABLE 6 — Chaîne d'audit Blockchain (hash chain immuable)
class BlockchainAuditBlock(db.Model):
    """
    Chaque bloc contient le hash du bloc précédent, formant une chaîne
    cryptographique immuable. Toute modification d'un bloc invalide
    tous les blocs suivants (principe blockchain).
    """
    __tablename__ = "blockchain_audit_blocks"

    id            = db.Column(db.Integer, primary_key=True)
    block_index   = db.Column(db.Integer, unique=True, nullable=False, index=True)
    event_type    = db.Column(db.String(50), nullable=False)
    data          = db.Column(db.Text,       nullable=False)   # JSON string
    previous_hash = db.Column(db.String(64), nullable=False)
    block_hash    = db.Column(db.String(64), nullable=False, unique=True)
    created_at    = db.Column(db.DateTime,   default=_now)

    def to_dict(self):
        try:
            parsed = json.loads(self.data)
        except Exception:
            parsed = {}
        return {
            "block_index"  : self.block_index,
            "event_type"   : self.event_type,
            "data"         : parsed,
            "previous_hash": self.previous_hash,
            "block_hash"   : self.block_hash,
            "timestamp"    : self.created_at.strftime("%d/%m/%Y %H:%M:%S"),
        }
