"""
author: Christian Bender
date: 21.12.2017
class: XORCipher

This class implements the XOR-cipher algorithm and provides
some useful methods for encrypting and decrypting strings and
files.

Overview about methods

- encode : str
- decode : str
- encode_file : boolean
- decode_file : boolean
"""

from ruamel.yaml import YAML
from modules.parent import Cipher

y = YAML(typ="safe")
with open("modules/plugins/XOR cipher/info.yaml") as f:
    info = y.load(f)
del y


class BadKeyError(Exception):
    def __init__(self, message: str = "Key is not valid"):
        self.message = message
        super().__init__(self.message)


class XORCipher(Cipher):
    global info
    _alias_ = info["name"]
    _version_ = info["version"]

    def get_info(self) -> dict:
        global info
        return info

    def encode(self, plain: str, **kwargs) -> str:
        """
        input: 'plain' of type string and 'key' of type int
        output: encrypted string 'content'
        """
        try:
            key = int(kwargs["key"])
            # make sure key is an appropriate size
            key %= 256
        except ValueError:
            raise BadKeyError("Key is not valid: Must be a number between 1-255")

        ans = ""

        for ch in plain:
            ans += chr(ord(ch) ^ key)

        return ans

    def brute_force(self, plain, **kwargs) -> dict:
        results = dict()
        for i in range(1, 256):
            results[f"Key {i}"] = self.encode(plain, key=i)
        return results

    # UNUSED
    # def encode_file(self, file: str, out: str, key: int = 0) -> bool:
    #     """
    #     input: filename (str), output (str) and a key (int)
    #     output: returns true if encrypt process was
    #     successful otherwise false
    #     """

    #     # precondition
    #     assert isinstance(file, str)
    #     assert isinstance(key, int)

    #     # make sure key is an appropriate size
    #     key %= 256

    #     try:
    #         with open(file) as fin, open(out, "w+") as fout:
    #             # actual encrypt-process
    #             for line in fin:
    #                 fout.write(self.encode(line, key))

    #     except OSError:
    #         return False

    #     return True

    # UNUSED
    # def decode_file(self, file: str, out: str, key: int) -> bool:
    #     """
    #     input: filename (str), output (str) and a key (int)
    #     output: returns true if decrypt process was
    #     successful otherwise false
    #     """

    #     # precondition
    #     assert isinstance(file, str)
    #     assert isinstance(key, int)

    #     # make sure key is an appropriate size
    #     key %= 256

    #     try:
    #         with open(file) as fin, open(out, "w+") as fout:
    #             # actual encrypt-process
    #             for line in fin:
    #                 fout.write(self.decode(line, key))

    #     except OSError:
    #         return False

    #     return True
