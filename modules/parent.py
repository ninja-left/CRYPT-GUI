from pluginlib import Parent, abstractmethod


@Parent()
class Cipher(object):
    @abstractmethod
    def get_info(self) -> dict:
        return dict()

    def encode(self, plain, **kwargs):
        """
        **kwargs:
        key, alphabet, rounds

        These keyword arguments will be passed to the function when encode is called in the app.
        """
        return "encoded"

    def decode(self, encoded, **kwargs):
        """
        **kwargs:
        key, alphabet, plaintext

        These keyword arguments will be passed to the function when decode is called in the app.
        """
        return "decoded"

    def brute_force(self, encoded, **kwargs) -> str | dict:
        """
        **kwargs:
        alphabet, rounds
        """
        return {"keyX": "decoded"} or "decoded"
