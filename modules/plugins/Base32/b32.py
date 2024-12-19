from ruamel.yaml import YAML
from modules.parent import Cipher

y = YAML(typ="safe")
with open("modules/plugins/Base32/info.yaml") as f:
    info = y.load(f)
del y


class BadKeyError(Exception):
    def __init__(self, message: str = "Key is not valid"):
        self.message = message
        super().__init__(self.message)


class Base32(Cipher):
    global info
    _alias_ = info["name"]
    _version_ = info["version"]

    def get_info(self) -> dict:
        global info
        return info

    def encode(self, plain: str, **kwargs) -> str:
        """
        Encodes data to Base32
        >>> encode("123456")
        'GEZDGNBVGY======'
        """
        alphabet = kwargs["alphabet"]
        print(plain)
        plain = "".join(bin(ord(d))[2:].zfill(8) for d in plain)
        plain = plain.ljust(5 * ((len(plain) // 5) + 1), "0")
        b32_chunks = map("".join, zip(*[iter(plain)] * 5))
        b32_result = "".join(alphabet[int(chunk, 2)] for chunk in b32_chunks)
        return b32_result.ljust(8 * ((len(b32_result) // 8) + 1), "=")

    def decode(self, plain: str, **kwargs) -> str:
        """
        Decodes Base32 input
        >>> decode('GEZDGNBVGY======')
        '123456'
        """
        alphabet = kwargs["alphabet"]
        print(plain)
        chunks = "".join(
            bin(alphabet.index(_d))[2:].zfill(5) for _d in plain.strip("=")
        )
        plain = list(map("".join, zip(*[iter(chunks)] * 8)))
        return "".join([chr(int(_d, 2)) for _d in plain])
