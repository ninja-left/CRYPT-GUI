from ruamel.yaml import YAML
from modules.parent import Cipher

y = YAML(typ="safe")
with open("modules/plugins/Base16/info.yaml") as f:
    info = y.load(f)
del y


class BadKeyError(Exception):
    def __init__(self, message: str = "Key is not valid"):
        self.message = message
        super().__init__(self.message)


class BadLengthError(Exception):
    def __init__(
        self, message: str = "Data does not have an even number of hex digits."
    ):
        super().__init__(self.message)


class BadCharError(Exception):
    def __init__(
        self,
        message: str = "Data is not uppercase hex or it contains invalid characters.",
    ):
        self.message = message
        super().__init__(self.message)


class Base16(Cipher):
    global info
    _alias_ = info["name"]
    _version_ = info["version"]

    def get_info(self) -> dict:
        global info
        return info

    def encode(self, plain: str, **kwargs) -> str:
        """
        Encodes the given bytes into base16.
        Turn the data into a list of integers (where each integer is a byte),
        Then turn each byte into its hexadecimal representation, make sure
        it is uppercase, and then join everything together and return it.

        >>> base16_encode(b'Hello World!')
        '48656C6C6F20576F726C6421'
        >>> base16_encode(b'HELLO WORLD!')
        '48454C4C4F20574F524C4421'
        >>> base16_encode(b'')
        ''
        """
        data = plain.encode("utf-8")
        return "".join([hex(byte)[2:].zfill(2).upper() for byte in list(data)])

    def decode(self, encoded: str, **kwargs) -> str:
        """
        Decodes the given base16 encoded data into bytes.

        >>> base16_decode('48656C6C6F20576F726C6421')
        b'Hello World!'
        >>> base16_decode('48454C4C4F20574F524C4421')
        b'HELLO WORLD!'
        >>> base16_decode('')
        b''
        """
        data = encoded
        # Check data validity, following RFC3548
        # https://www.ietf.org/rfc/rfc3548.txt
        if (len(data) % 2) != 0:
            raise BadLengthError()
        # Check the character set - the standard base16 alphabet
        # is uppercase according to RFC3548 section 6
        if not set(data) <= set("0123456789ABCDEF"):
            raise BadCharError()
        # For every two hexadecimal digits (= a byte), turn it into an integer.
        # Then, string the result together into bytes, and return the utf-8 decoded format of it.
        return bytes(
            int(data[i] + data[i + 1], 16) for i in range(0, len(data), 2)
        ).decode("utf-8")
