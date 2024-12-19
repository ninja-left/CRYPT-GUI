from modules.parent import Cipher
from ruamel.yaml import YAML
from passlib.hash import bcrypt

y = YAML(typ="safe")
with open("modules/plugins/BCrypt/info.yaml") as f:
    info = y.load(f)
del y


class BCrypt(Cipher):
    global info
    _alias_ = info["name"]
    _version_ = info["version"]

    def get_info(self) -> dict:
        """This function returns data from plugin's info.yaml file"""
        global info
        return info

    def encode(self, plain: str, **kwargs) -> str:
        return bcrypt.using(rounds=int(kwargs["rounds"])).hash(plain)

    def decode(self, encoded: str, **kwargs) -> str:
        matches = bcrypt.verify(kwargs["plaintext"], encoded)
        return "Matches" if matches else "Does not match"
