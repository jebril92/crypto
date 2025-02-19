from rfc7748 import x25519, add, computeVcoordinate, mult
from Crypto.Hash import SHA256
from random import randint
from algebra import mod_inv

p = 2**255 - 19
ORDER = (2**252 + 27742317777372353535851937790883648493)

BaseU = 9
BaseV = computeVcoordinate(BaseU)


def H(message):
    if isinstance(message, str):
        message = message.encode()
    h = SHA256.new(message)
    return int(h.hexdigest(), 16)


def ECDSA_generate_nonce(private_key, message):
    if isinstance(message, str):
        message = message.encode()
    h = H(str(private_key).encode() + message)
    return (h % ORDER) or 1


def ECDSA_generate_keys():
    private_key = randint(1, ORDER - 1)
    public_key = mult(private_key, BaseU, BaseV, p)
    return private_key, public_key


def ECDSA_sign(private_key, message):
    k = ECDSA_generate_nonce(private_key, message)
    R = mult(k, BaseU, BaseV, p)
    r = R[0] % ORDER

    if r == 0:
        return ECDSA_sign(private_key, message)

    s = (mod_inv(k, ORDER) * (H(message) + r * private_key)) % ORDER

    if s == 0:
        return ECDSA_sign(private_key, message)

    return r, s


def ECDSA_verify(public_key, message, signature):
    r, s = signature

    if not (1 <= r < ORDER and 1 <= s < ORDER):
        return False

    h_m = H(message)
    s_inv = mod_inv(s, ORDER)

    u1 = (h_m * s_inv) % ORDER
    u2 = (r * s_inv) % ORDER

    P1 = mult(u1, BaseU, BaseV, p)
    P2 = mult(u2, public_key[0], public_key[1], p)
    P = add(P1[0], P1[1], P2[0], P2[1], p)

    return P[0] % ORDER == r
