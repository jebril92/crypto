import pytest
from dsa import DSA_generate_keys, DSA_sign, DSA_verify
from dsa import PARAM_G, PARAM_P

@pytest.fixture
def test_data():
    return {
        "message": "An important message !",
        "k_fixed": 0x7e7f77278fe5232f30056200582ab6e7cae23992bca75929573b779c62ef4759,
        "x_private": 0x49582493d17932dabd014bb712fc55af453ebfb2767537007b0ccff6e857e6a3,
        "expected_r": 0x5ddf26ae653f5583e44259985262c84b483b74be46dec74b07906c5896e26e5a,
        "expected_s": 0x194101d2c55ac599e4a61603bc6667dcc23bd2e9bdbef353ec3cb839dcce6ec1,
        "public_key": pow(PARAM_G, 0x49582493d17932dabd014bb712fc55af453ebfb2767537007b0ccff6e857e6a3, PARAM_P)
    }

def test_dsa_signature(test_data):
    r, s = DSA_sign(test_data["x_private"], test_data["message"], test_data["k_fixed"])
    assert r == test_data["expected_r"], "r ne correspond pas à la valeur attendue"
    assert s == test_data["expected_s"], "s ne correspond pas à la valeur attendue"

def test_dsa_verification(test_data):
    r, s = DSA_sign(test_data["x_private"], test_data["message"], test_data["k_fixed"])
    assert DSA_verify(test_data["public_key"], test_data["message"], (r, s)), "La signature devrait être valide"
