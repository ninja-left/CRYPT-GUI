from pluginlib import Parent, abstractmethod


@Parent()
class Cipher(object):
    @abstractmethod
    def get_info(self) -> dict:
        return dict()

    def encode(self, plain):
        return plain

    def decode(self, encoded):
        return encoded

    def brute_force(self, encoded):
        return encoded
