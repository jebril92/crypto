from algebra import int_to_bytes
from elgamal import EG_generate_keys, EGM_encrypt, EGA_encrypt, EG_decrypt, add, bruteforcer

p = 0x87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597

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

    m1 = 0x2661b673f687c5c3142f806d500d2ce57b1182c9b25bfe4fa09529424b
    m2 = 0x1c1c871caabca15828cf08ee3aa3199000b94ed15e743c3

    (r1, c1) = EGM_encrypt(public_key, m1)
    (r2, c2) = EGM_encrypt(public_key, m2)

    res = EG_decrypt(private_key, ((r1 * r2) % p, (c1 * c2) % p), mode="multiplicative")
    excepted = m1 * m2
    assert res == excepted


def test_homorphic_add():
    private_key, public_key = EG_generate_keys()
    print(f"Private key: {private_key}, Public key: {public_key}")

    val1 = EGA_encrypt(public_key, 1)
    val2 = EGA_encrypt(public_key, 0)
    val3 = EGA_encrypt(public_key, 1)
    val4 = EGA_encrypt(public_key, 1)
    val5 = EGA_encrypt(public_key, 0)

    print(f"Ciphertext 1: {val1}")
    print(f"Ciphertext 2: {val2}")
    print(f"Ciphertext 3: {val3}")
    print(f"Ciphertext 4: {val4}")
    print(f"Ciphertext 5: {val5}")

    addition = add(val1, val2)
    addition = add(addition, val3)
    addition = add(addition, val4)
    addition = add(addition, val5)

    print(f"Addition result: {addition}")

    res = EG_decrypt(private_key, addition, mode="additive")
    print(f"Decryption result: {res}")

    brute_result = bruteforcer(res)
    print(f"Brute-forced result: {brute_result}")

    assert brute_result == 3
