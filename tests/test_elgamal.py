import pytest
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
