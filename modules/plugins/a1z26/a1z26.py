"""
Convert a string of characters to a sequence of numbers
corresponding to the character's position in the alphabet.

https://www.dcode.fr/letter-number-cipher
http://bestcodes.weebly.com/a1z26.html

Source from https://github.com/TheAlgorithms/Python/Ciphers/a1z26.py
"""

from modules.parent import Cipher
from ruamel.yaml import YAML

y = YAML(typ="safe")
with open("modules/plugins/a1z26/info.yaml") as f:
    info = y.load(f)
del y

class A1Z26(Cipher):
    global info
    _alias_ = info["name"]
    _version_ = info["version"]

    def get_info(self) -> dict:
        """This function returns data from plugin's info.yaml file"""
        global info
        return info

    def encode(self, plain: str) -> str:
        """
        >>> encode("myname")
        '13,25,14,1,13,5'
        """
        return ",".join([str(ord(elem) - 96) for elem in plain])

    def decode(self, encoded: list[int] | str) -> str:
        """
        >>> decode([13, 25, 14, 1, 13, 5])
        'myname'
        >>> decode("13,25,14,1,13,5")
        'myname'
        """
        if type(encoded) == str:
            encoded = [int(n) for n in encoded.split(",")]
        return "".join(chr(elem + 96) for elem in encoded)
