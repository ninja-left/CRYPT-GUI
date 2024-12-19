from modules.parent import Cipher
from ruamel.yaml import YAML

y = YAML(typ="safe")
with open("modules/plugins/VigenereCipher/info.yaml") as f:
    info = y.load(f)
del y


class VigenereCipher(Cipher):
    global info
    _alias_ = info["name"]
    _version_ = info["version"]

    def get_info(self) -> dict:
        """This function returns data from plugin's info.yaml file"""
        global info
        return info

    def cipher(
        self, plain: str, key: str, alphabet: str, mode: str = "e" or "d"
    ) -> str:
        results = ""
        keyIndex = 0

        for char in plain:
            i = alphabet.find(char.upper())
            if i != -1:
                if mode == "e":
                    i += alphabet.find(key[keyIndex])
                else:
                    i -= alphabet.find(key[keyIndex])
                i %= len(alphabet)

                if char.isupper():
                    results += alphabet[i]
                else:
                    results += alphabet[i].lower()
                keyIndex += 1
                if keyIndex == len(key):
                    keyIndex = 0
            else:
                results += char

        return results

    def encode(self, plain: str, **kwargs) -> str:
        return self.cipher(plain, kwargs["key"], kwargs["alphabet"], "e")

    def decode(self, encoded: str, **kwargs) -> str:
        return self.cipher(encoded, kwargs["key"], kwargs["alphabet"], "d")
