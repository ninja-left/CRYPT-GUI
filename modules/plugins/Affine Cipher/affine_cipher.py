"""
"Affine Cipher" from https://github.com/TheAlgorithms/Python/Ciphers/affine_cipher.py
"gcd_by_iterative" from https://github.com/TheAlgorithms/Python/maths/greatest_common_divisor.py
"""

import random
import sys
from ruamel.yaml import YAML
from modules.parent import Cipher

y = YAML(typ="safe")
with open("modules/plugins/Affine Cipher/info.yaml") as f:
    info = y.load(f)
del y


class BadKeyError(Exception):
    def __init__(self, message: str = "Key is not valid"):
        self.message = message
        super().__init__(self.message)


class AffineCipher(Cipher):
    global info
    _alias_ = info["name"]
    _version_ = info["version"]

    def get_info(self) -> dict:
        global info
        return info

    def gcd_by_iterative(self, x: int, y: int) -> int:
        while y:  # --> when y=0 then loop will terminate and return x as final GCD.
            x, y = y, x % y
        return abs(x)

    def find_mod_inverse(self, a: int, m: int) -> int:
        if self.gcd_by_iterative(a, m) != 1:
            msg = f"mod inverse of {a!r} and {m!r} does not exist"
            raise ValueError(msg)
        u1, u2, u3 = 1, 0, a
        v1, v2, v3 = 0, 1, m
        while v3 != 0:
            q = u3 // v3
            v1, v2, v3, u1, u2, u3 = (
                (u1 - q * v1),
                (u2 - q * v2),
                (u3 - q * v3),
                v1,
                v2,
                v3,
            )
        return u1 % m

    def check_keys(self, key_a: int, key_b: int, mode: str, alphabet: str) -> None:
        if mode == "encrypt":
            if key_a == 1:
                raise BadKeyError(
                    "The affine cipher becomes weak when key A is set to 1. Choose different key"
                )
            if key_b == 0:
                raise BadKeyError(
                    "The affine cipher becomes weak when key B is set to 0. Choose different key"
                )
        if key_a < 0 or key_b < 0 or key_b > len(alphabet) - 1:
            raise BadKeyError(
                f"Key A must be greater than 0 and key B must be between 0 and {len(alphabet) - 1}."
            )
        if self.gcd_by_iterative(key_a, len(alphabet)) != 1:
            raise BadKeyError(
                f"Key A {key_a} and the symbol set size {len(alphabet)} are not relatively prime. Choose a different key."
            )

    def encode(self, plain: str, **kwargs) -> str:
        """
        **kwargs:
            key: int, alphabet: str
        >>> encode(4545, 'The affine cipher is a type of monoalphabetic substitution cipher.')
        'VL}p MM{I}p~{HL}Gp{vp pFsH}pxMpyxIx JHL O}F{~pvuOvF{FuF{xIp~{HL}Gi'
        >>> encode(6478, 'This is an example output of affine cipher.')
        'GeJY2JY2d"2W1d=KXW2f#>K#>2f<2d<<J"W2.JKeWt4'
        """
        key = kwargs["key"]
        alphabet = kwargs["alphabet"]
        key_a, key_b = divmod(key, len(alphabet))
        self.check_keys(key_a, key_b, "encrypt", alphabet)
        cipher_text = ""
        for symbol in plain:
            if symbol in alphabet:
                sym_index = alphabet.find(symbol)
                cipher_text += alphabet[(sym_index * key_a + key_b) % len(alphabet)]
            else:
                cipher_text += symbol
        return cipher_text

    def decode(self, plain: str, **kwargs) -> str:
        """
        **kwargs:
            key: int, alphabet: str
        >>> decode('VL}p MM{I}p~{HL}Gp{vp pFsH}pxMpyxIx JHL O}F{~pvuOvF{FuF{xIp~{HL}Gi', key=4545)
        'The affine cipher is a type of monoalphabetic substitution cipher.'
        >>> decode('GeJY2JY2d"2W1d=KXW2f#>K#>2f<2d<<J"W2.JKeWt4', key=6478)
        'This is an example output of affine cipher.'
        """
        key_a, key_b = divmod(key, len(alphabet))
        self.check_keys(key_a, key_b, "decrypt", alphabet)
        plain_text = ""
        mod_inverse_of_key_a = self.find_mod_inverse(key_a, len(alphabet))
        for symbol in plain:
            if symbol in alphabet:
                sym_index = alphabet.find(symbol)
                plain_text += alphabet[
                    (sym_index - key_b) * mod_inverse_of_key_a % len(alphabet)
                ]
            else:
                plain_text += symbol
        return plain_text
