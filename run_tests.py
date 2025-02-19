import tests.test_dsa
import tests.test_ecdsa
import tests.test_ecelgamal
import tests.test_elgamal

print("Test DSA:")

tests.test_dsa.test_key_generation()
tests.test_dsa.test_signature()
tests.test_dsa.test_verification()
tests.test_dsa.test_invalid_signature()
tests.test_dsa.test_invalid_public_key()
tests.test_dsa.test_different_messages()

print("Test ECDSA:")

tests.test_ecdsa.test_key_generation()
tests.test_ecdsa.test_signature()
tests.test_ecdsa.test_verification()
tests.test_ecdsa.test_invalid_signature()
tests.test_ecdsa.test_invalid_public_key()
tests.test_ecdsa.test_different_messages()

print("Test El Gamal:")

tests.test_elgamal.test_key_generation()
tests.test_elgamal.test_egm_encryption_decryption()
tests.test_elgamal.test_invalid_multiplicative_decryption()
tests.test_elgamal.test_invalid_additive_decryption()
tests.test_elgamal.test_homorphic_mult()
tests.test_elgamal.test_homorphic_add()

print("Test EC EL Gamal:")

tests.test_ecelgamal.test_key_generation()
tests.test_ecelgamal.test_encryption_decryption()
tests.test_ecelgamal.test_additive()

print("!!!!!!!!!!!!!!!!!!!!!!SUCESS!!!!!!!!!!!!!!!!!!!!!!!")
print("If you are seing this then all test are succefull !")