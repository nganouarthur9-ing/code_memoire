"""
blockchain_service.py
Service Python qui connecte Flask + IA aux smart contracts Solidity
via Web3.py
"""

import os, json, time, joblib
import numpy as np
from web3 import Web3
from web3.middleware import geth_poa_middleware

# ══════════════════════════════════════════════════════════════
# 1. CONNEXION À LA BLOCKCHAIN
# ══════════════════════════════════════════════════════════════

class BlockchainService:
    """
    Service central qui gère toute la communication
    entre Python et les smart contracts Solidity
    """

    def __init__(self):
        # ── Connexion au réseau ──────────────────────────────
        # Pour les tests Remix : utilisez le réseau Injected (MetaMask)
        # Options :
        #   - Remix VM        : pas besoin de connexion externe
        #   - Ganache local   : HTTP://127.0.0.1:7545
        #   - Sepolia testnet : via Infura/Alchemy
        #   - Mainnet         : NE PAS utiliser pour les tests

        RPC_URL = os.getenv("RPC_URL", "HTTP://127.0.0.1:7545")  # Ganache par défaut
        self.w3 = Web3(Web3.HTTPProvider(RPC_URL))

        # Nécessaire pour Polygon / BSC (réseaux PoA)
        self.w3.middleware_onion.inject(geth_poa_middleware, layer=0)

        if not self.w3.is_connected():
            raise ConnectionError(f"Impossible de se connecter à {RPC_URL}")

        print(f" Connecté à la blockchain | Chain ID: {self.w3.eth.chain_id}")

        # ── Compte administrateur (votre wallet MetaMask) 
        # IMPORTANT : Ne jamais mettre la clé privée en clair en production !
        # Utilisez une variable d'environnement
        self.admin_address    = os.getenv("ADMIN_ADDRESS")
        self.admin_private_key = os.getenv("ADMIN_PRIVATE_KEY")

        # ── Adresses des contrats déployés depuis Remix 
        # Après avoir déployé dans Remix, copiez l'adresse ici
        self.token_address     = os.getenv("TOKEN_ADDRESS",     "0x...")
        self.registry_address  = os.getenv("REGISTRY_ADDRESS",  "0x...")
        self.optimizer_address = os.getenv("OPTIMIZER_ADDRESS", "0x...")

        # ── Charger les ABI (copier depuis Remix → Compilation → ABI) 
        self.registry_abi  = self._load_abi("abi/FraudRegistry.json")
        self.optimizer_abi = self._load_abi("abi/TransactionOptimizer.json")

        # ── Créer les objets contrat
        self.token = self.w3.eth.contract(
            address=Web3.to_checksum_address(self.token_address),
            abi=self.token_abi
        )
        self.registry = self.w3.eth.contract(
            address=Web3.to_checksum_address(self.registry_address),
            abi=self.registry_abi
        )
        self.optimizer = self.w3.eth.contract(
            address=Web3.to_checksum_address(self.optimizer_address),
            abi=self.optimizer_abi
        )

        # ── Charger le modèle IA ──────────────────────────
        self.fraud_model = joblib.load("models/fraud_detector.pkl")
        self.scaler      = joblib.load("models/scaler.pkl")
        print(" Modèle IA chargé")

    def _load_abi(self, path: str) -> list:
        """Charger un ABI depuis un fichier JSON"""
        with open(path, "r") as f:
            return json.load(f)

    # ══════════════════════════════════════════════════════════
    # 2. HELPER : SIGNER ET ENVOYER UNE TRANSACTION
    # ══════════════════════════════════════════════════════════

    def _send_transaction(self, contract_function):
        """
        Signer localement et envoyer une transaction on-chain.
        Utilisé pour TOUTES les fonctions qui modifient l'état.
        """
        nonce = self.w3.eth.get_transaction_count(self.admin_address)
        gas_price = self.w3.eth.gas_price

        # Construire la transaction
        tx = contract_function.build_transaction({
            "from"     : self.admin_address,
            "nonce"    : nonce,
            "gas"      : 300_000,
            "gasPrice" : gas_price,
        })

        # Signer avec la clé privée (localement, sécurisé)
        signed_tx = self.w3.eth.account.sign_transaction(
            tx, private_key=self.admin_private_key
        )

        # Envoyer et attendre la confirmation
        tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

        return {
            "tx_hash" : tx_hash.hex(),
            "status"  : "success" if receipt.status == 1 else "failed",
            "gas_used": receipt.gasUsed,
            "block"   : receipt.blockNumber,
        }

    # ══════════════════════════════════════════════════════════
    # 3. INTERACTIONS AVEC FintechToken.sol
    # ══════════════════════════════════════════════════════════

    def get_balance(self, address: str) -> float:
        """Lire le solde FTK d'une adresse (lecture gratuite)"""
        raw = self.token.functions.balanceOf(
            Web3.to_checksum_address(address)
        ).call()
        return raw / 10**18  # Convertir wei → FTK

    def mint_tokens(self, to_address: str, amount: float) -> dict:
        """
        Créer des tokens FTK pour une adresse.
        Utilisé lors de l'inscription d'un utilisateur.
        """
        amount_wei = int(amount * 10**18)
        fn = self.token.functions.mint(
            Web3.to_checksum_address(to_address),
            amount_wei
        )
        return self._send_transaction(fn)

    def blacklist_address(self, address: str, reason: str) -> dict:
        """
        Blacklister une adresse frauduleuse.
        Appelé automatiquement quand le score IA > 0.85
        """
        fn = self.token.functions.setBlacklist(
            Web3.to_checksum_address(address),
            True,
            reason
        )
        return self._send_transaction(fn)

    def pause_contract(self) -> dict:
        """Pause d'urgence du contrat (ex: hack détecté)"""
        fn = self.token.functions.setPaused(True)
        return self._send_transaction(fn)

    # ══════════════════════════════════════════════════════════
    # 4. IA + BLOCKCHAIN : ANALYSE FRAUDE ET ENREGISTREMENT
    # ══════════════════════════════════════════════════════════

    def analyze_and_report(
        self,
        sender_address: str,
        receiver_address: str,
        amount: float,
        features: list,        # features ML de la transaction
        tx_ref: str            # référence unique de la transaction
    ) -> dict:
        """
        Pipeline complet :
        1. Analyser avec le modèle IA
        2. Si fraude → enregistrer dans FraudRegistry.sol
        3. Si score critique → blacklister dans FintechToken.sol
        """

        # ── Étape 1 : Prédiction IA ──────────────────────
        features_scaled = self.scaler.transform([features])
        proba           = self.fraud_model.predict_proba(features_scaled)[0]
        fraud_prob      = float(proba[1])          # probabilité de fraude
        risk_score      = int(fraud_prob * 100)    # 0-100

        # Catégorisation du risque
        if fraud_prob < 0.30:
            risk_level = "LOW"
            blocked    = False
        elif fraud_prob < 0.60:
            risk_level = "MEDIUM"
            blocked    = False
        elif fraud_prob < 0.85:
            risk_level = "HIGH"
            blocked    = True
        else:
            risk_level = "CRITICAL"
            blocked    = True

        result = {
            "fraud_probability": fraud_prob,
            "risk_score"       : risk_score,
            "risk_level"       : risk_level,
            "blocked"          : blocked,
        }

        # ── Étape 2 : Enregistrer on-chain si risque ≥ MEDIUM ─
        if risk_score >= 30:
            amount_wei = int(amount * 10**18)

            fn = self.registry.functions.reportFraud(
                Web3.to_checksum_address(sender_address),
                Web3.to_checksum_address(receiver_address),
                amount_wei,
                risk_score,
                risk_level,
                "RandomForest_v1",
                blocked,
                tx_ref
            )
            receipt = self._send_transaction(fn)
            result["registry_tx"] = receipt

        # ── Étape 3 : Blacklister si CRITICAL ────────────
        if risk_level == "CRITICAL":
            bl_receipt = self.blacklist_address(
                sender_address,
                f"CRITICAL fraud score: {risk_score}/100 | TX: {tx_ref}"
            )
            result["blacklist_tx"] = bl_receipt
            print(f"🚨 ADRESSE BLACKLISTÉE : {sender_address}")

        return result

    # ══════════════════════════════════════════════════════════
    # 5. OPTIMISATION DES TRANSACTIONS
    # ══════════════════════════════════════════════════════════

    def optimize_and_record(
        self,
        sender_address: str,
        receiver_address: str,
        amount: float,
        hour_of_day: int
    ) -> dict:
        """
        1. Calculer le gas optimal avec l'IA
        2. Enregistrer la transaction optimisée on-chain
        """

        # ── Calcul IA du gas optimal ──────────────────────
        gas_model = joblib.load("models/gas_optimizer.pkl")
        estimated_gas = int(gas_model.predict([[hour_of_day, 50]])[0])
        estimated_gas = max(21000, min(estimated_gas, 300000))

        # Score du chemin de routage (simulé)
        network_load = self.optimizer.functions.getOptimizationParams().call()[1]
        route_score  = max(0, 100 - int(network_load))

        note = (
            f"Gas optimal: {estimated_gas} gwei | "
            f"Charge réseau: {network_load}% | "
            f"Score route: {route_score}/100"
        )

        # ── Enregistrer on-chain ──────────────────────────
        amount_wei = int(amount * 10**18)
        fn = self.optimizer.functions.recordOptimizedTransaction(
            Web3.to_checksum_address(receiver_address),
            amount_wei,
            estimated_gas,
            route_score,
            note
        )
        receipt = self._send_transaction(fn)

        return {
            "estimated_gas": estimated_gas,
            "route_score"  : route_score,
            "network_load" : network_load,
            "note"         : note,
            "tx_receipt"   : receipt,
        }

    # ══════════════════════════════════════════════════════════
    # 6. ÉCOUTE DES ÉVÉNEMENTS BLOCKCHAIN (temps réel)
    # ══════════════════════════════════════════════════════════

    def listen_fraud_events(self, callback):
        """
        Écouter les événements FraudReported en temps réel.
        Utiliser dans un thread séparé.
        """
        event_filter = self.registry.events.FraudReported.create_filter(
            fromBlock="latest"
        )
        print("👂 Écoute des événements de fraude...")
        while True:
            for event in event_filter.get_new_entries():
                callback({
                    "report_id" : event["args"]["reportId"],
                    "suspect"   : event["args"]["suspect"],
                    "risk_score": event["args"]["riskScore"],
                    "risk_level": event["args"]["riskLevel"],
                    "blocked"   : event["args"]["blocked"],
                    "block"     : event["blockNumber"],
                })
            time.sleep(2)  # vérifier toutes les 2 secondes
