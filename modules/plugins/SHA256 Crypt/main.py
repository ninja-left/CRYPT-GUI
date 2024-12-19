from modules.parent import Cipher
from ruamel.yaml import YAML
from passlib.hash import sha256_crypt

y = YAML(typ="safe")
with open("modules/plugins/SHA256 Crypt/info.yaml") as f:
    info = y.load(f)
del y


class SHA256_CRYPT(Cipher):
    global info
    _alias_ = info["name"]
    _version_ = info["version"]

    def get_info(self) -> dict:
        """This function returns data from plugin's info.yaml file"""
        global info
        return info

    def encode(self, plain: str, **kwargs) -> str:
        return sha256_crypt.using(rounds=kwargs["rounds"]).hash(plain)

    def decode(self, encoded: str, **kwargs) -> str:
        matches = sha256_crypt.verify(kwargs["plaintext"], encoded)
        return "Matches" if matches else "Does not match"
