from ruamel.yaml import YAML
from modules.parent import Cipher

y = YAML(typ="safe")
with open("modules/plugins/Base85/info.yaml") as f:
    info = y.load(f)
del y


class BadKeyError(Exception):
    def __init__(self, message: str = "Key is not valid"):
        self.message = message
        super().__init__(self.message)


class Base85(Cipher):
    global info
    _alias_ = info["name"]
    _version_ = info["version"]

    def get_info(self) -> dict:
        global info
        return info

    def _base10_to_85(self, d: int) -> str:
        return "".join(chr(d % 85 + 33)) + self._base10_to_85(d // 85) if d > 0 else ""

    def _base85_to_10(self, digits: list) -> int:
        return sum(char * 85**i for i, char in enumerate(reversed(digits)))

    def encode(self, plain: str, **kwargs) -> str:
        """
        >>> encode("")
        ''
        >>> encode("12345")
        '0etOA2#'
        >>> encode("base 85")
        '@UX=h+?24'
        """
        data = plain.encode("utf-8")
        binary_data = "".join(bin(ord(d))[2:].zfill(8) for d in data.decode("utf-8"))
        null_values = (32 * ((len(binary_data) // 32) + 1) - len(binary_data)) // 8
        binary_data = binary_data.ljust(32 * ((len(binary_data) // 32) + 1), "0")
        b85_chunks = [int(_s, 2) for _s in map("".join, zip(*[iter(binary_data)] * 32))]
        result = "".join(self._base10_to_85(chunk)[::-1] for chunk in b85_chunks)
        return bytes(
            result[:-null_values] if null_values % 4 != 0 else result, "utf-8"
        ).decode("utf-8")

    def decode(self, encoded: str, **kwargs) -> str:
        """
        >>> decode("")
        ''
        >>> decode("0etOA2#")
        '12345'
        >>> decode("@UX=h+?24")
        'base 85'
        """
        data = encoded.encode("utf-8")
        null_values = 5 * ((len(data) // 5) + 1) - len(data)
        binary_data = data.decode("utf-8") + "u" * null_values
        b85_chunks = map("".join, zip(*[iter(binary_data)] * 5))
        b85_segments = [[ord(_s) - 33 for _s in chunk] for chunk in b85_chunks]
        results = [
            bin(self._base85_to_10(chunk))[2::].zfill(32) for chunk in b85_segments
        ]
        char_chunks = [
            [chr(int(_s, 2)) for _s in map("".join, zip(*[iter(r)] * 8))]
            for r in results
        ]
        result = "".join("".join(char) for char in char_chunks)
        offset = int(null_values % 5 == 0)
        return bytes(result[: offset - null_values], "utf-8").decode("utf-8")
