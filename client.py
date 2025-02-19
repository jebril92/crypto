import requests
import json
from ecelgamal import ECEG_encrypt
from ecdsa import ECDSA_sign, ECDSA_generate_keys
from dsa import DSA_generate_keys, DSA_sign
from elgamal import EGA_encrypt

HOST = "127.0.0.1"
PORT = 8080

server_public_key = None
user_id = None

def get_protocol():
    url = f"http://{HOST}:{PORT}/api/protocol"
    response = requests.get(url)
    data = response.json()
    return bool(data['isEC'])


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
    except requests.RequestException as e:
        print("[ERREUR] Impossible d'envoyer la clé publique :", e)

def encrypt_vote(vote_list):
    encrypted = []
    if isEC:
        for v in vote_list:
            c = ECEG_encrypt(server_public_key, v)
            encrypted.append(c)
    else:
        for v in vote_list:
            c = EGA_encrypt(server_public_key, v)
            encrypted.append(c)
    return encrypted

def sign_vote(encrypted_votes):
    message_str = "".join(str(ev) for ev in encrypted_votes)
    message_str = message_str.replace('(', '[').replace(')', ']')
    if isEC:
        r, s = ECDSA_sign(private_key_sign, message_str)
        return (r, s)
    else:
        r, s = DSA_sign(private_key_sign, message_str)
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
    except requests.RequestException as e:
        print("[ERREUR] Impossible d'envoyer le vote :", e)

def main():
    send_public_key_sign()
    if not user_id or not server_public_key:
        print("Impossible de récupérer l'ID ou la clé publique du serveur, arrêt.")
        return
    while True:
        try:
            choice = int(input("Pour quel candidat votez-vous ? (1-5) : "))
            if 1 <= choice <= 5:
                print("Vote bien pris en compte.")
                break
            else:
                print("Choix invalide, réessayez.")
        except ValueError:
            print("Choix invalide, réessayez.")
    my_vote = [0, 0, 0, 0, 0]
    my_vote[choice - 1] = 1

    send_vote(my_vote)

isEC = get_protocol()
if isEC:
    private_key_sign, public_key_sign = ECDSA_generate_keys()
else:
    private_key_sign, public_key_sign = DSA_generate_keys()
main()
