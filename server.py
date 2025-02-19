from http.server import BaseHTTPRequestHandler, HTTPServer
from ecdsa import ECDSA_verify
from ecelgamal import ECEG_generate_keys, ECEG_decrypt, add_pairs_of_points
import json

keyStore = {}
count_user = 1
vote_received = 0
candidat_list = [None, None, None, None, None]

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def vote_result_service(self):
        global private_key
        result = [0] * 5
        for i in range(len(candidat_list)):
            result[i] = ECEG_decrypt(private_key, candidat_list[i])

        max = 0
        for i in range(1, len(result)):
            if result[i] > result[max]:
                max = i
        print("The candidat " + max + " has won the election !")

    def send_key_service(self):
        global count_user
        global keyStore
        global public_key
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        try:
            data = json.loads(body.decode('utf-8'))
            keyStore[self.client_address] = data['key']
            self._set_response(200)
            response = {"message": "Key correctly loaded, here is your ID and my public key", "id": count_user, "pubkey": public_key}
            count_user += 1
            self.wfile.write(json.dumps(response).encode('utf-8'))
        except json.JSONDecodeError:
            self._set_response(400)
            self.wfile.write(b'{"error": "Invalid JSON"}')

    def vote_service(self):
        global keyStore
        global vote_received
        global candidat_list
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        try:
            data = json.loads(body.decode('utf-8'))
            voteList = data['voteList']
            r, s = data['signature']
            if ECDSA_verify(keyStore[data['id']], ''.join(voteList), (r, s)):
                for i in range(len(candidat_list)):
                    if candidat_list[i] is None:
                        candidat_list[i] = voteList[i]
                    else:
                        candidat_list[i] = add_pairs_of_points(candidat_list[i], voteList[i])
            vote_received+=1
            if vote_received == 10:
                self.vote_result_service(self)
                self.server.shutdown()

            self._set_response(200)
            response = {"message": "Vote Successfully taken into account !"}
            count_user += 1
            self.wfile.write(json.dumps(response).encode('utf-8'))
        except json.JSONDecodeError:
            self._set_response(400)
            self.wfile.write(b'{"error": "Invalid JSON"}')

    def _set_response(self, status=200, content_type="application/json"):
        self.send_response(status)
        self.send_header('Content-type', content_type)
        self.end_headers()

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
            self.send_key_service(self)
        elif self.path == "/api/vote":
            self.vote_service(self)
        else:
            self._set_response(404)
            self.wfile.write(b'{"error": "Not Found"}')


def run(server_class=HTTPServer, handler_class=SimpleHTTPRequestHandler, port=8080):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f"Starting HTTP server on port {port}")
    httpd.serve_forever()

isEliptic = True
private_key, public_key = ECEG_generate_keys()
"""
userInput = ""
while (not (userInput == 'Y' or userInput == 'N')):
    userInput = input('Do you want to use eliptic DSA and ElGamal or no ? (Y/N)\n')
    if (not (userInput == 'Y' or userInput == 'N')):
        print('Sorry only Y or N input are supported. Please only answer by Y or N')
    elif userInput == 'N':
        isEliptic = False
"""

run()
