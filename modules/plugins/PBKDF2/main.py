from modules.parent import Cipher
from ruamel.yaml import YAML
from passlib.hash import pbkdf2_sha256, pbkdf2_sha512, pbkdf2_sha1

y = YAML(typ="safe")
with open("modules/plugins/SHA256 Crypt/info.yaml") as f:
    info = y.load(f)
del y


class BadDigestError(Exception):
    def __init__(self, message: str = "Digest is not valid", digest: str = "sha"):
        self.message = message
        self.digest = digest
        super().__init__(f"{self.message}: <<{self.digest}>>")


class SHA256_CRYPT(Cipher):
    global info
    _alias_ = info["name"]
    _version_ = info["version"]

    def get_info(self) -> dict:
        """This function returns data from plugin's info.yaml file"""
        global info
        return info

    def encode(self, plain: str, **kwargs) -> str:
        if (d := kwargs["arguments"]["digest"]) == "sha256":
            return pbkdf2_sha256.using(rounds=kwargs["rounds"]).hash(plain)
        elif d == "sha512":
            return pbkdf2_sha512.using(rounds=kwargs["rounds"]).hash(plain)
        elif d == "sha1":
            return pbkdf2_sha1.using(rounds=kwargs["rounds"]).hash(plain)
        else:
            raise BadDigestError(digest=d)

    def decode(self, encoded: str, **kwargs) -> str:
        if (d := kwargs["arguments"]["digest"]) == "sha256":
            matches = pbkdf2_sha256.verify(kwargs["plaintext"], encoded)
        elif d == "sha512":
            matches = pbkdf2_sha512.verify(kwargs["plaintext"], encoded)
        elif d == "sha1":
            matches = pbkdf2_sha1.verify(kwargs["plaintext"], encoded)
        else:
            raise BadDigestError(digest=d)

        return "Matches" if matches else "Does not match"
