# Overall CRYPT Development & Features Roadmap
### Last update: 2024-08-27
## Pending
- [ ] Implement a plugin system
    - Use `pluginlib`
    - Define 3 parents: Encoder, Decoder, Bruteforcer
    - Example encoder named SomeCipher:
        ```python
        import pluginlib

        import numpy
        import ML1
        # All required libraries should be
        #added to a list named as below;
        # User will be prompted to install
        #them if needed.
        requirements = ("MyLib1", "numpy")

        @pluginlib.Parent('encoder')
        class SomeCipher(object):
            @pluginlib.abstractmethod
            def encode(self, string):
                # encode function
                return "encoded"
        ```
- [ ] Implement the following functions:
    - Enigma Machine
    - Affine Cipher
    - A1Z26
    - Rail fence cipher
    - Polybius square
    - Bifid cipher
    - Nihilist cipher
    - RC4
    - HMAC
    - XOR
    - Different Compression algorithms

## Done
- [X] Implement brute-forcers
- [X] Implement a configuration system
    - Using a config file (Named `config.yaml`)
    - a Dialog for editing the file when config button pressed
- [X] Changing the default (english) alphabet
    - Editing current alphabet
    - Typing new alphabet
    - Reverting to default alphabet (By deleting `config.yaml`)
    - Setting new default alphabet (By editing `config.yaml` using any text editor or config button)
