from algebra import mod_inv, int_to_bytes
from rfc7748 import x25519, add, sub, computeVcoordinate, mult
from random import randint

p = 2**255 - 19

ORDER = (2**252 + 27742317777372353535851937790883648493)

BaseU = 9
BaseV = computeVcoordinate(BaseU)

def debug_values():
    print(f"DEBUG - BaseU: {BaseU}", flush=True)
    print(f"DEBUG - BaseV expected: {BaseV}", flush=True)
    print(f"DEBUG - computeVcoordinate(9) = {computeVcoordinate(9)}", flush=True)

def bruteECLog(C1, C2):
    s1, s2 = 1, 0
    for i in range(p):
        if s1 == C1 and s2 == C2:
            return i
        s1, s2 = add(s1, s2, BaseU, BaseV, p)
    return -1

def add_points(point1, point2):
    r1, c1 = point1
    r2, c2 = point2
    return add(r1, c1, r2, c2, p)


def add_pairs_of_points(coords1, coords2):
    return (
        add_points(coords1[0], coords2[0]),
        add_points(coords1[1], coords2[1]),
    )

def EGencode(message):
    if message == 0:
        return (1, 0)
    if message == 1:
        return (BaseU, BaseV)


def ECEG_generate_keys():
    private_key = randint(1, ORDER - 1)
    public_key = mult(private_key, BaseU, BaseV, p)
    return private_key, public_key       


def ECEG_encrypt(public_key, message):
    encoded_message = EGencode(message)
    k = randint(1, ORDER - 1)

    C1 = mult(k, BaseU, BaseV, p)
    C2 = add(encoded_message[0], encoded_message[1], *mult(k, public_key[0], public_key[1], p), p)

    return C1, C2


def ECEG_decrypt(private_key, ciphertext):
    C1, C2 = ciphertext
    S = mult(private_key, C1[0], C1[1], p)
    S_inv = sub(1, 0, S[0], S[1], p)
    M = add(C2[0], C2[1], S_inv[0], S_inv[1], p)

    return M