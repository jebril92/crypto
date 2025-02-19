import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from ecdsa import ECDSA_verify
from ecelgamal import ECEG_generate_keys, ECEG_decrypt, add_pairs_of_points

# Variables globales
keyStore = {}        # dictionnaire : id_utilisateur -> clé publique ECDSA du client
count_user = 1       # compteur pour attribuer un ID unique à chaque nouvel utilisateur
vote_received = 0    # compte le nombre de votes reçus
candidat_list = [None, None, None, None, None]  # sommes homomorphes pour 5 candidats

# Génération de la paire de clés EC-ElGamal (pour le serveur)
private_key, public_key = ECEG_generate_keys()

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def _set_response(self, status=200, content_type="application/json"):
        self.send_response(status)
        self.send_header('Content-type', content_type)
        self.end_headers()

    def vote_result_service(self):
        global private_key, candidat_list
        # Déchiffre la somme des votes pour chaque candidat
        result = [0] * len(candidat_list)
        for i in range(len(candidat_list)):
            result[i] = ECEG_decrypt(private_key, candidat_list[i])

        # Trouve l’indice du candidat gagnant
        max_index = 0
        for i in range(1, len(result)):
            if result[i] > result[max_index]:
                max_index = i

        print("Le candidat " + str(max_index) + " a gagné l'élection !")

    def send_key_service(self):
        """
        Enregistre la clé publique ECDSA du client et retourne l'ID attribué + la clé publique EC-ElGamal du serveur.
        """
        global count_user, keyStore, public_key
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        try:
            data = json.loads(body.decode('utf-8'))

            # On associe la clé publique ECDSA reçue à l'ID count_user au lieu de self.client_address
            keyStore[count_user] = data['key']

            # Prépare la réponse
            self._set_response(200)
            response = {
                "message": "Key correctly loaded, here is your ID and my public key",
                "id": count_user,
                "pubkey": public_key
            }
            self.wfile.write(json.dumps(response).encode('utf-8'))

            # On incrémente après avoir répondu
            count_user += 1

        except json.JSONDecodeError:
            self._set_response(400)
            self.wfile.write(b'{"error": "Invalid JSON"}')

    def vote_service(self):
        """
        Récupère le vote chiffré + la signature, vérifie la signature ECDSA, et ajoute homomorphiquement au total.
        """
        global keyStore, vote_received, candidat_list
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        try:
            data = json.loads(body.decode('utf-8'))
            voteList = data['voteList']  # liste de 5 points (chiffrements)
            r, s = data['signature']

            # On récupère la clé publique associée à l'ID envoyé
            user_id = data['id']
            pubkey_client = keyStore[user_id]

            # Vérifie la signature ECDSA
            if ECDSA_verify(
                pubkey_client,
                ''.join(str(v) for v in voteList),  # le message à signer
                (r, s)
            ):
                # Addition homomorphe de chaque composante de vote
                for i in range(len(candidat_list)):
                    if candidat_list[i] is None:
                        candidat_list[i] = voteList[i]
                    else:
                        candidat_list[i] = add_pairs_of_points(
                            candidat_list[i],
                            voteList[i]
                        )
            
            vote_received += 1

            # Suppose qu'on arrête après 10 votes
            if vote_received == 10:
                self.vote_result_service()
                self.server.shutdown()

            self._set_response(200)
            response = {"message": "Vote Successfully taken into account!"}
            self.wfile.write(json.dumps(response).encode('utf-8'))

        except json.JSONDecodeError:
            self._set_response(400)
            self.wfile.write(b'{"error": "Invalid JSON"}')
        except KeyError:
            self._set_response(400)
            self.wfile.write(b'{"error": "Invalid ID (key not found)"}')

    def do_GET(self):
        if self.path == "/api/hello":
            self._set_response()
            response = {"message": "Hello, World!"}
            self.wfile.write(json.dumps(response).encode('utf-8'))
        else:
            self._set_response(404)
            self.wfile.write(b'{"error": "Not Found"}')

    def do_POST(self):
        if self.path == "/api/send-key":
            self.send_key_service()
        elif self.path == "/api/vote":
            self.vote_service()
        else:
            self._set_response(404)
            self.wfile.write(b'{"error": "Not Found"}')

def run(server_class=HTTPServer, handler_class=SimpleHTTPRequestHandler, port=8080):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f"Starting HTTP server on port {port}")
    httpd.serve_forever()

if __name__ == "__main__":
    run()
