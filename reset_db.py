"""
reset_db.py Vide complètement la base de données Fintech GTA
Supprime tous les utilisateurs, transactions, alertes de fraude,
tokens de réinitialisation et journaux d'audit.

Utilisation :
  python reset_db.py            -> demande confirmation avant de vider
  python reset_db.py --force    -> vide sans demander confirmation
"""

import sys
from app import app, db


def reset_database():
    with app.app_context():
        db.drop_all()
        db.create_all()
    print(" Base de données entièrement vidée et recréée (tables vides).")


if __name__ == "__main__":
    if "--force" not in sys.argv:
        reponse = input(" Cette action supprime TOUS les utilisateurs, transactions et logs. Continuer ? (oui/non) : ")
        if reponse.strip().lower() not in ("oui", "o", "yes", "y"):
            print("Annulé.")
            sys.exit(0)
    reset_database()
