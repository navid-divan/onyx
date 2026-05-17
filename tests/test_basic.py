import os
import sys

CURRENT_DIRECTORY = os.path.dirname(os.path.abspath(__file__))
PARENT_DIRECTORY = os.path.dirname(CURRENT_DIRECTORY)
if PARENT_DIRECTORY not in sys.path:
    sys.path.insert(0, PARENT_DIRECTORY)

from oper.polynomial import Polynomial
from oper.lagrange import lagrange_interpolate
from onyx.bgv import BGVScheme
from parameters import quick_parameters
from primitives.samplers import sample_uniform_polynomial
from vss.pi_la import HashBasedVSS


def test_polynomial_addition_and_multiplication() -> None:
    degree = 8
    modulus = 257
    polynomial_a = Polynomial([1, 2, 3, 4, 0, 0, 0, 0], degree, modulus)
    polynomial_b = Polynomial([5, 6, 0, 0, 0, 0, 0, 0], degree, modulus)
    addition_result = polynomial_a + polynomial_b
    assert addition_result.to_list()[0] == 6
    assert addition_result.to_list()[1] == 8
    multiplication_result = polynomial_a * polynomial_b
    assert isinstance(multiplication_result, Polynomial)


def test_bgv_encrypt_decrypt() -> None:
    parameters = quick_parameters()
    scheme = BGVScheme(parameters.dfhe.ring, parameters.dfhe.error_std, parameters.dfhe.error_bound)
    public_key, secret_key = scheme.generate_keys()
    for message in [0, 1, 5, 42, 100, 200, 256]:
        ciphertext = scheme.encrypt(public_key, message)
        decrypted = scheme.decrypt(secret_key, ciphertext)
        assert decrypted == message % parameters.dfhe.ring.plaintext_modulus, f"got {decrypted}, expected {message}"


def test_vss_round_trip() -> None:
    modulus = (1 << 256) - 189
    protocol = HashBasedVSS(modulus, parties=5, threshold=2)
    secret = 123456789
    dealer_output = protocol.share(secret)
    for index, share in enumerate(dealer_output.shares):
        assert protocol.verify_share(index + 1, share, dealer_output.public_proof)
    reconstructed = protocol.reconstruct(dealer_output.shares[:3])
    assert reconstructed == secret


def test_lagrange_interpolate() -> None:
    modulus = 1009
    points = [1, 2, 3]
    values = [2, 5, 10]
    constant = lagrange_interpolate(points, values, modulus)
    assert isinstance(constant, int)


if __name__ == "__main__":
    test_polynomial_addition_and_multiplication()
    test_bgv_encrypt_decrypt()
    test_vss_round_trip()
    test_lagrange_interpolate()
    print("All basic tests passed.")
