import requests
import json
from ecelgamal import ECEG_encrypt, ECEG_generate_keys
from ecdsa import ECDSA_sign, ECDSA_generate_keys

HOST = "127.0.0.1"
PORT = 8080

server_public_key = None
user_id = None

private_key_sign, public_key_sign = ECDSA_generate_keys()

def send_public_key_sign():
    global user_id, server_public_key
    url = f"http://{HOST}:{PORT}/api/send-key"
    payload = {
        "key": public_key_sign
    }
    try:
        response = requests.post(url, json=payload)
        response.raise_for_status()

        data = response.json()
        user_id = data["id"]
        server_public_key = data["pubkey"]
        print("Clé publique envoyée, ID reçu =", user_id)
        print("Clé publique du serveur pour le chiffrement =", server_public_key)
    except requests.RequestException as e:
        print("[ERREUR] Impossible d'envoyer la clé publique :", e)


def encrypt_vote(vote_list):
    encrypted = []
    for v in vote_list:
        # v = 0 ou 1
        c = ECEG_encrypt(server_public_key, v)
        encrypted.append(c)
    return encrypted

def sign_vote(encrypted_votes):
    message_str = "".join(str(ev) for ev in encrypted_votes)
    r, s = ECDSA_sign(private_key_sign, message_str.replace('(', '[').replace(')', ']'))
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
        response = requests.post(url, json=payload)
        response.raise_for_status()

        data = response.json()
        print("Réponse du serveur (vote) :", data)
    except requests.RequestException as e:
        print("[ERREUR] Impossible d'envoyer le vote :", e)


def main():
    send_public_key_sign()
    if not user_id or not server_public_key:
        print("Impossible de récupérer l'ID ou la clé publique du serveur, arrêt.")
        return
    my_vote = [1, 0, 0, 0, 0]
    send_vote(my_vote)
if __name__ == "__main__":
    main()
