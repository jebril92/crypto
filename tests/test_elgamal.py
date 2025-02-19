import pytest
from algebra import int_to_bytes
from elgamal import EG_generate_keys, EGM_encrypt, EGA_encrypt, EG_decrypt


def test_key_generation():
    private_key, public_key = EG_generate_keys()
    assert isinstance(private_key, int)
    assert isinstance(public_key, int)
    assert private_key > 0
    assert public_key > 0


def test_egm_encryption_decryption():
    private_key, public_key = EG_generate_keys()
    message = 123456

    ciphertext = EGM_encrypt(public_key, message)
    decrypted_message = EG_decrypt(private_key, ciphertext, mode="multiplicative")

    assert message == decrypted_message, "Decryption failed"


def test_ega_encryption_decryption():
    private_key, public_key = EG_generate_keys()
    message = 7890

    ciphertext = EGA_encrypt(public_key, message)
    decrypted_message = EG_decrypt(private_key, ciphertext, mode="additive")

    assert message == decrypted_message, "Decryption failed"


def test_invalid_multiplicative_decryption():
    private_key, public_key = EG_generate_keys()
    autre_private_key, _ = EG_generate_keys()
    message = 654321

    ciphertext = EGM_encrypt(public_key, message)
    decrypted_message = EG_decrypt(autre_private_key, ciphertext, mode="multiplicative")

    assert message != decrypted_message, "Wrong key decrypted message"


def test_invalid_additive_decryption():
    private_key, public_key = EG_generate_keys()
    autre_private_key, _ = EG_generate_keys()
    message = 2024

    ciphertext = EGA_encrypt(public_key, message)
    decrypted_message = EG_decrypt(autre_private_key, ciphertext, mode="additive")

    assert message != decrypted_message, "Wrong key decrypted message"

def test_homorphic_mult():
    private_key, public_key = EG_generate_keys()
    autre_private_key, _ = EG_generate_keys()

    m1 = 0x2661b673f687c5c3142f806d500d2ce57b1182c9b25bfe4fa09529424b
    m2 = 0x1c1c871caabca15828cf08ee3aa3199000b94ed15e743c3

    (r1, c1) = EGA_encrypt(public_key, m1)
    (r2, c2) = EGA_encrypt(public_key, m2)

    res = EG_decrypt(autre_private_key, (r1 * r2, c1 * c2), mode="multiplicative")
    print(int_to_bytes(res))
    assert res == m1 * m2

def test_homorphic_add():
    private_key, public_key = EG_generate_keys()
    autre_private_key, _ = EG_generate_keys()

    (r1, c1) = EGA_encrypt(public_key, 1)
    (r2, c2) = EGA_encrypt(public_key, 0)
    (r3, c3) = EGA_encrypt(public_key, 1)
    (r4, c4) = EGA_encrypt(public_key, 1)
    (r5, c5) = EGA_encrypt(public_key, 0)

    res = EG_decrypt(autre_private_key, (r1 + r2 + r3+ r4 + r5, c1 + c2+ c3+ c4 + c5), mode="additive")
    assert res == 3