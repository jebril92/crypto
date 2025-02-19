from dsa import DSA_generate_keys, DSA_sign, DSA_verify

def test_key_generation():
    private_key, public_key = DSA_generate_keys()
    assert isinstance(private_key, int)
    assert isinstance(public_key, int)
    assert private_key > 0
    assert public_key > 0


def test_signature():
    private_key, public_key = DSA_generate_keys()
    message = "Test signature"
    r, s = DSA_sign(private_key, message)

    assert isinstance(r, int)
    assert isinstance(s, int)
    assert r > 0
    assert s > 0


def test_verification():
    private_key, public_key = DSA_generate_keys()
    message = "Test verification"
    r, s = DSA_sign(private_key, message)

    assert DSA_verify(public_key, message, (r, s))


def test_invalid_signature():
    private_key, public_key = DSA_generate_keys()
    message = "Test invalid signature"
    r, s = DSA_sign(private_key, message)

    message_modifie = "Message modifie"
    assert not DSA_verify(public_key, message_modifie, (r, s))


def test_invalid_public_key():
    private_key, public_key = DSA_generate_keys()
    autre_private_key, autre_public_key = DSA_generate_keys()
    message = "Test invalid public key"
    r, s = DSA_sign(private_key, message)

    assert not DSA_verify(autre_public_key, message, (r, s))


def test_different_messages():
    private_key, public_key = DSA_generate_keys()
    message1 = "Message 1"
    message2 = "Message 2"

    r1, s1 = DSA_sign(private_key, message1)
    r2, s2 = DSA_sign(private_key, message2)

    assert (r1, s1) != (r2, s2)
