import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from ecdsa import ECDSA_verify
from ecelgamal import ECEG_generate_keys, ECEG_decrypt, add_pairs_of_points, bruteECLog
from dsa import DSA_verify
from elgamal import EG_generate_keys, EG_decrypt, add, bruteforcer
import json

keyStore = {}
count_user = 1
vote_received = 0 
candidat_list = [None, None, None, None, None]
isEliptic = True

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def _set_response(self, status=200, content_type="application/json"):
        self.send_response(status)
        self.send_header('Content-type', content_type)
        self.end_headers()

    def vote_result_service(self):
        global private_key, candidat_list
        result = [0] * len(candidat_list)
        if isEliptic:
            for i in range(len(candidat_list)):
                result[i] = bruteECLog(*ECEG_decrypt(private_key, candidat_list[i]))
        else:
            for i in range(len(candidat_list)):
                result[i] = bruteforcer(EG_decrypt(private_key, candidat_list[i], "additive"))

        max_index = 0
        for i in range(1, len(result)):
            if result[i] > result[max_index]:
                max_index = i
        print("Le candidat " + str(max_index + 1) + " a gagné l'élection !")

    def send_key_service(self):
        global count_user, keyStore, public_key
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        try:
            data = json.loads(body.decode('utf-8'))
            keyStore[count_user] = data['key']

            self._set_response(200)
            response = {
                "message": "Key correctly loaded, here is your ID and my public key",
                "id": count_user,
                "pubkey": public_key
            }
            self.wfile.write(json.dumps(response).encode('utf-8'))
            count_user += 1

        except json.JSONDecodeError:
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
            pubkey_client = keyStore[user_id]

            if isEliptic:
                if ECDSA_verify(pubkey_client, ''.join(str(v) for v in voteList), (r, s)):
                    for i in range(len(candidat_list)):
                        if candidat_list[i] is None:
                            candidat_list[i] = voteList[i]
                        else:
                            candidat_list[i] = add_pairs_of_points(candidat_list[i], voteList[i])
            else:
                if DSA_verify(pubkey_client, ''.join(str(v) for v in voteList), (r, s)):
                    for i in range(len(candidat_list)):
                        if candidat_list[i] is None:
                            candidat_list[i] = voteList[i]
                        else:
                            candidat_list[i] = add(candidat_list[i], voteList[i])
            
            vote_received += 1

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
        global isEliptic
        if self.path == "/api/hello":
            self._set_response()
            response = {"message": "Hello, World!"}
            self.wfile.write(json.dumps(response).encode('utf-8'))
        elif self.path == "/api/protocol":
            self._set_response()
            response = {"isEC": isEliptic}
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


userInput = ""
while (not (userInput == 'Y' or userInput == 'N')):
    userInput = input('Do you want to use eliptic DSA and ElGamal or no ? (Y/N)\n')
    if (not (userInput == 'Y' or userInput == 'N')):
        print('Sorry only Y or N input are supported. Please only answer by Y or N')
    elif userInput == 'N':
        private_key, public_key = EG_generate_keys()
        isEliptic = False
    else:
        private_key, public_key = ECEG_generate_keys()

run()