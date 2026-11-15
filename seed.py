"""Jeu de données de démonstration (fictif) : Alice, Bob et un contrat partagé.

Usage : python init_db.py puis python seed.py
"""
import io

from app import create_app

ALICE = ("alice@example.com", "Alice-Demo-2026!")
BOB = ("bob@example.com", "Bob-Demo-2026!")


def main():
    client = create_app().test_client()
    for email, password in (ALICE, BOB):
        client.post("/register", data={"email": email, "password": password})

    client.post("/login", data={"email": ALICE[0], "password": ALICE[1]})
    pdf = b"%PDF-1.4\n% Contrat de demonstration (donnees fictives)\n%%EOF\n"
    client.post("/upload", data={"file": (io.BytesIO(pdf), "contrat_demo.pdf")},
                content_type="multipart/form-data")
    client.post("/share/1", data={"recipient_email": BOB[0]})

    print("Comptes de démonstration créés :")
    print("  ", ALICE[0], "/", ALICE[1])
    print("  ", BOB[0], "/", BOB[1])
    print("Alice a déposé contrat_demo.pdf et l'a partagé avec Bob.")


if __name__ == "__main__":
    main()
