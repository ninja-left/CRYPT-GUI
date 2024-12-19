from modules.parent import Cipher
from ruamel.yaml import YAML
from passlib.hash import argon2

y = YAML(typ="safe")
with open("modules/plugins/Argon2/info.yaml") as f:
    info = y.load(f)
del y


class Argon2(Cipher):
    global info
    _alias_ = info["name"]
    _version_ = info["version"]

    def get_info(self) -> dict:
        """This function returns data from plugin's info.yaml file"""
        global info
        return info

    def encode(self, plain: str, **kwargs) -> str:
        # FIXME: fix the using part based on https://passlib.readthedocs.io/en/stable/lib/passlib.hash.argon2.html#format-algorithm
        return argon2.using(rounds=int(kwargs["rounds"])).hash(plain)

    def decode(self, encoded: str, **kwargs) -> str:
        matches = argon2.verify(kwargs["plaintext"], encoded)
        return "Matches" if matches else "Does not match"
