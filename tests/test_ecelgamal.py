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
