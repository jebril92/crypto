import sys
import os
sys.path.insert(0, os.path.abspath("dependencies"))
import time
import logging
import requests
import json
from ecelgamal import ECEG_encrypt
from ecdsa import ECDSA_sign, ECDSA_generate_keys
from dsa import DSA_generate_keys, DSA_sign
from elgamal import EGA_encrypt

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[logging.StreamHandler()]
)

HOST = "127.0.0.1"
PORT = 8080

server_public_key = None
user_id = None

def get_protocol(retries=5, delay=2):
    url = f"http://{HOST}:{PORT}/api/protocol"

    for attempt in range(retries):
        try:
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            data = response.json()
            logging.info(f"🔍 Protocole récupéré : {'Elliptic Curve' if data['isEC'] else 'Classique'}")
            return bool(data['isEC'])
        except requests.RequestException as e:
            logging.warning(f"⚠️ Échec récupération protocole ({attempt+1}/{retries}) : {e}")
            time.sleep(delay)

    logging.error("❌ Impossible de récupérer le protocole après plusieurs tentatives.")
    sys.exit(1)

def send_public_key_sign():
    global user_id, server_public_key
    url = f"http://{HOST}:{PORT}/api/send-key"
    payload = {"key": public_key_sign}

    try:
        response = requests.post(url, json=payload, timeout=5)
        response.raise_for_status()
        data = response.json()

        user_id = data["id"]
        server_public_key = data["pubkey"]

        logging.info(f"✅ Clé publique envoyée avec succès. ID utilisateur : {user_id}")
    except requests.RequestException as e:
        logging.error(f"❌ Impossible d'envoyer la clé publique : {e}")
        sys.exit(1)

def encrypt_vote(vote_list):
    encrypted = []
    if isEC:
        encrypted = [ECEG_encrypt(server_public_key, v) for v in vote_list]
    else:
        encrypted = [EGA_encrypt(server_public_key, v) for v in vote_list]

    logging.info("🔒 Vote chiffré avec succès.")
    return encrypted

def sign_vote(encrypted_votes):
    message_str = "".join(str(ev) for ev in encrypted_votes).replace('(', '[').replace(')', ']')

    if isEC:
        r, s = ECDSA_sign(private_key_sign, message_str)
    else:
        r, s = DSA_sign(private_key_sign, message_str)

    logging.info("✍️  Vote signé avec succès.")
    return (r, s)

def send_vote(vote_list):
    url = f"http://{HOST}:{PORT}/api/vote"

    encrypted_votes = encrypt_vote(vote_list)
    signature = sign_vote(encrypted_votes)

    payload = {
        "id": user_id,
        "voteList": encrypted_votes,
        "signature": signature
    }

    try:
        response = requests.post(url, json=payload, timeout=5)
        response.raise_for_status()
        logging.info("📩 Vote envoyé avec succès.")
    except requests.RequestException as e:
        logging.error(f"❌ Impossible d'envoyer le vote : {e}")
        sys.exit(1)

def get_user_vote():
    while True:
        try:
            choice = int(input("🗳️  Pour quel candidat votez-vous ? (1-5) : "))
            if 1 <= choice <= 5:
                logging.info(f"✅ Vote pris en compte pour le candidat {choice}.")
                return choice
            else:
                logging.warning("⚠️ Choix invalide, veuillez entrer un nombre entre 1 et 5.")
        except ValueError:
            logging.warning("⚠️ Entrée invalide, veuillez entrer un nombre.")

def main():
    send_public_key_sign()

    if not user_id or not server_public_key:
        logging.error("❌ Impossible de récupérer l'ID ou la clé publique du serveur. Arrêt.")
        return

    choice = get_user_vote()

    my_vote = [0, 0, 0, 0, 0]
    my_vote[choice - 1] = 1

    send_vote(my_vote)

    logging.info("🎉 Vote complété avec succès. Merci de votre participation !")

isEC = get_protocol()

if isEC:
    private_key_sign, public_key_sign = ECDSA_generate_keys()
else:
    private_key_sign, public_key_sign = DSA_generate_keys()

main()
