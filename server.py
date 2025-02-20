import sys
import os
import threading
sys.path.insert(0, os.path.abspath("dependencies"))
import json
import logging
from http.server import BaseHTTPRequestHandler, HTTPServer
from ecdsa import ECDSA_verify
from ecelgamal import ECEG_generate_keys, ECEG_decrypt, add_pairs_of_points, bruteECLog
from dsa import DSA_verify
from elgamal import EG_generate_keys, EG_decrypt, add, bruteforcer


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[logging.StreamHandler()]
)

keyStore = {}
count_user = 1
vote_received = 0
candidat_list = [None] * 5
isEliptic = True

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def _set_response(self, status=200, content_type="application/json"):
        self.send_response(status)
        self.send_header('Content-type', content_type)
        self.end_headers()

    def log_request(self, code='-', size='-'):
        logging.info(f"📩 Requête reçue : {self.command} {self.path} | Code HTTP : {code}")

    def vote_result_service(self):
        global private_key, candidat_list
        logging.info("\n" + "="*60)
        logging.info("🗳 Calcul des résultats de l'élection...")
        result = [0] * len(candidat_list)

        if isEliptic:
            for i in range(len(candidat_list)):
                result[i] = bruteECLog(*ECEG_decrypt(private_key, candidat_list[i])) if candidat_list[i] else 0
        else:
            for i in range(len(candidat_list)):
                result[i] = bruteforcer(EG_decrypt(private_key, candidat_list[i], "additive")) if candidat_list[i] else 0

        max_index = result.index(max(result))
        logging.info(f"🏆 Le candidat {max_index + 1} a gagné l'élection avec {result[max_index]} votes !")
        logging.info("="*60 + "\n")

        logging.info("📴 Arrêt du serveur après 10 votes")

    def send_key_service(self):
        global count_user, keyStore, public_key
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        try:
            data = json.loads(body.decode('utf-8'))
            keyStore[count_user] = data['key']

            self._set_response(200)
            response = {
                "message": "🔑 Clé correctement enregistrée",
                "id": count_user,
                "pubkey": public_key
            }
            self.wfile.write(json.dumps(response).encode('utf-8'))

            logging.info(f"\n{'='*60}\n✅ Clé publique reçue pour l'utilisateur {count_user}\n{'='*60}")

            count_user += 1

        except json.JSONDecodeError:
            logging.error("❌ Erreur : JSON invalide dans /api/send-key")
            self._set_response(400)
            self.wfile.write(b'{"error": "Invalid JSON"}')

    def vote_service(self):
        global keyStore, vote_received, candidat_list
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        try:
            data = json.loads(body.decode('utf-8'))
            voteList = data['voteList']
            r, s = data['signature']
            user_id = data['id']

            if user_id not in keyStore:
                logging.error(f"🚨 ID utilisateur invalide : {user_id}")
                self._set_response(400)
                self.wfile.write(b'{"error": "Invalid ID (key not found)"}')
                return

            pubkey_client = keyStore[user_id]

            is_valid_signature = (
                ECDSA_verify(pubkey_client, ''.join(str(v) for v in voteList), (r, s))
                if isEliptic else
                DSA_verify(pubkey_client, ''.join(str(v) for v in voteList), (r, s))
            )

            if not is_valid_signature:
                logging.warning(f"⚠️ Vote rejeté pour l'utilisateur {user_id} : signature invalide")
                self._set_response(400)
                self.wfile.write(b'{"error": "Invalid signature"}')
                return

            for i in range(len(candidat_list)):
                if candidat_list[i] is None:
                    candidat_list[i] = voteList[i]
                else:
                    candidat_list[i] = add_pairs_of_points(candidat_list[i], voteList[i]) if isEliptic else add(candidat_list[i], voteList[i])

            vote_received += 1

            logging.info(f"\n{'='*60}\n🗳 Vote enregistré de l'utilisateur {user_id} ({vote_received}/10)\n{'='*60}")

            if vote_received == 10:
                self.vote_result_service()

            self._set_response(200)
            response = {"message": "✅ Vote enregistré avec succès !"}
            self.wfile.write(json.dumps(response).encode('utf-8'))

            if vote_received == 10:
                threading.Thread(target=self.server.shutdown).start()

        except json.JSONDecodeError:
            logging.error("❌ JSON invalide dans /api/vote")
            self._set_response(400)
            self.wfile.write(b'{"error": "Invalid JSON"}')

    def do_GET(self):
        self.log_request()
        if self.path == "/api/hello":
            self._set_response()
            self.wfile.write(json.dumps({"message": "Hello, World!"}).encode('utf-8'))
            logging.info("👋 Requête /api/hello exécutée avec succès")
        elif self.path == "/api/protocol":
            self._set_response()
            self.wfile.write(json.dumps({"isEC": isEliptic}).encode('utf-8'))
            logging.info(f"🔍 Protocole demandé : {'Elliptic Curve' if isEliptic else 'Classique'}")
        else:
            logging.warning(f"❌ Requête inconnue : {self.path}")
            self._set_response(404)
            self.wfile.write(b'{"error": "Not Found"}')

    def do_POST(self):
        self.log_request()
        if self.path == "/api/send-key":
            self.send_key_service()
        elif self.path == "/api/vote":
            self.vote_service()
        else:
            logging.warning(f"❌ Requête POST inconnue : {self.path}")
            self._set_response(404)
            self.wfile.write(b'{"error": "Not Found"}')

def run(server_class=HTTPServer, handler_class=SimpleHTTPRequestHandler, port=8080):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    logging.info(f"🚀 Démarrage du serveur sur le port {port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logging.info("🛑 Arrêt manuel du serveur")
    finally:
        httpd.server_close()
        logging.info("✅ Serveur arrêté proprement.")

while True:
    userInput = input('Utiliser DSA et ElGamal sur courbes elliptiques ? (Y/N) : ').strip().upper()
    if userInput in ('Y', 'N'):
        break
    print('❌ Entrée invalide ! Répondez Y ou N')

if userInput == 'N':
    private_key, public_key = EG_generate_keys()
    isEliptic = False
else:
    private_key, public_key = ECEG_generate_keys()

run()
