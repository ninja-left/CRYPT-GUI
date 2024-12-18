from modules.parent import Cipher
from ruamel.yaml import YAML

y = YAML(typ="safe")
with open("modules/plugins/Caesar Cipher/info.yaml") as f:
    info = y.load(f)
del y


class CaesarCipher(Cipher):
    global info
    _alias_ = info["name"]
    _version_ = info["version"]

    def get_info(self) -> dict:
        """This function returns data from plugin's info.yaml file"""
        global info
        return info

    def encode(self, plain: str, **kwargs) -> str:
        """
        Parameters:
        -----------
        *   plain: the plain-text that needs to be encoded
        *   key: the number of letters to shift the message by

        Optional:
        *   alphabet (str): the alphabet used to encode the cipher, if not
            specified, the standard english alphabet with upper and lowercase
            letters is used
        """
        result = ""
        alphabet = kwargs["alphabet"]
        key = int(kwargs["key"])

        for character in plain:
            if character not in alphabet:
                result += character
            else:
                # Get the index of the new key and make sure it isn't too large
                new_key = (alphabet.index(character) + key) % len(alphabet)

                # Append the encoded character to the alphabet
                result += alphabet[new_key]

        return result

    def decode(self, encoded: str, **kwargs) -> str:
        key = int(kwargs["key"]) * -1
        alphabet = kwargs["alphabet"]

        return self.encode(encoded, key=key, alphabet=alphabet)

    def brute_force(self, encoded, **kwargs) -> dict:
        alphabet = kwargs["alphabet"]
        brute_force_data = dict()
        for key in range(1, len(alphabet) + 1):
            key = -key
            keyMatch = self.encode(encoded, key=key, alphabet=alphabet)
            brute_force_data[f"Key {abs(key)}"] = keyMatch

        return brute_force_data
