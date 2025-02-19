from ecdsa import ECDSA_generate_keys, ECDSA_sign, ECDSA_verify

def test_key_generation():
    private_key, public_key = ECDSA_generate_keys()
    assert isinstance(private_key, int)
    assert isinstance(public_key, tuple) and len(public_key) == 2

def test_signature():
    private_key, public_key = ECDSA_generate_keys()
    message = b"Test signature"
    r, s = ECDSA_sign(private_key, message)

    assert isinstance(r, int)
    assert isinstance(s, int)
    assert r > 0
    assert s > 0

def test_verification():
    private_key, public_key = ECDSA_generate_keys()
    message = b"Test verification"
    r, s = ECDSA_sign(private_key, message)

    assert ECDSA_verify(public_key, message, (r, s))

def test_invalid_signature():
    private_key, public_key = ECDSA_generate_keys()
    message = b"Test invalid signature"
    r, s = ECDSA_sign(private_key, message)

    message_modifie = b"Message modifie"
    assert not ECDSA_verify(public_key, message_modifie, (r, s))

def test_invalid_public_key():
    private_key, public_key = ECDSA_generate_keys()
    autre_private_key, autre_public_key = ECDSA_generate_keys()
    message = b"Test invalid public key"
    r, s = ECDSA_sign(private_key, message)

    assert not ECDSA_verify(autre_public_key, message, (r, s))

def test_different_messages():
    private_key, public_key = ECDSA_generate_keys()
    message1 = b"Message 1"
    message2 = b"Message 2"

    r1, s1 = ECDSA_sign(private_key, message1)
    r2, s2 = ECDSA_sign(private_key, message2)

    assert (r1, s1) != (r2, s2)
