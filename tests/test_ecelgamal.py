import random
from ecelgamal import ECEG_generate_keys, ECEG_encrypt, ECEG_decrypt, EGencode, EGencode, bruteECLog, add_pairs_of_points

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

    assert message == bruteECLog(*decrypted_message), "Decryption failed"

def test_additive():
    priv, pub = ECEG_generate_keys()

    accumulator = None
    expected = 0

    for i in range(10):
        val = random.randint(0, 1)
        expected += val
        encrypted = ECEG_encrypt(pub, val)
        decrypted = ECEG_decrypt(priv, encrypted)
        assert decrypted == EGencode(val)
        if accumulator is None:
            accumulator = encrypted
        else:
            accumulator = add_pairs_of_points(accumulator, encrypted)

    decrypted = ECEG_decrypt(priv, accumulator)
    total = bruteECLog(*decrypted)
    assert total == expected