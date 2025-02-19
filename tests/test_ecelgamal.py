import pytest
from ecelgamal import ECEG_generate_keys, ECEG_encrypt, ECEG_decrypt, debug_values, p, EGencode
from rfc7748 import add, mult, sub

def test_debug_values():
    debug_values()

def test_key_generation():
    private_key, public_key = ECEG_generate_keys()
    assert isinstance(private_key, int)
    assert isinstance(public_key, tuple) and len(public_key) == 2
    assert private_key > 0
    assert all(isinstance(coord, int) for coord in public_key)


def test_encryption_decryption():
    private_key, public_key = ECEG_generate_keys()
    message = 1

    ciphertext = ECEG_encrypt(public_key, message)
    decrypted_message = ECEG_decrypt(private_key, ciphertext)

    assert message == decrypted_message, "Decryption failed"


def test_invalid_decryption():
    private_key, public_key = ECEG_generate_keys()
    autre_private_key, _ = ECEG_generate_keys()
    message = 1

    ciphertext = ECEG_encrypt(public_key, message)
    decrypted_message = ECEG_decrypt(autre_private_key, ciphertext)

    assert message != decrypted_message, "Wrong key decrypted message"

def test_additive():
    private_key, public_key = ECEG_generate_keys()
    autre_private_key, _ = ECEG_generate_keys()

    (r1, c1) = ECEG_encrypt(public_key, 1)
    (r2, c2) = ECEG_encrypt(public_key, 0)
    (r3, c3) = ECEG_encrypt(public_key, 1)
    (r4, c4) = ECEG_encrypt(public_key, 1)
    (r5, c5) = ECEG_encrypt(public_key, 0)

    result = ECEG_decrypt(autre_private_key, (r1 + r2 + r3+ r4 + r5, c1 + c2+ c3+ c4 + c5))
    assert result != 3
