from modules.parent import Cipher
from ruamel.yaml import YAML
from hashlib import sha512

y = YAML(typ="safe")
with open("modules/plugins/SHA512/info.yaml") as f:
    info = y.load(f)
del y


class SHA512(Cipher):
    global info
    _alias_ = info["name"]
    _version_ = info["version"]

    def get_info(self) -> dict:
        """This function returns data from plugin's info.yaml file"""
        global info
        return info

    def encode(self, plain: str, **kwargs) -> str:
        return sha512(plain.encode()).hexdigest()

    def decode(self, encoded: str, **kwargs) -> str:
        matches = encoded == self.encode(kwargs["plaintext"])
        return "Matches" if matches else "Does not match"
