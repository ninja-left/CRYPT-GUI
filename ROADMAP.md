# Overall CRYPT Development & Features Roadmap
- [X] Implement brute-forcers
- [ ] Implement a configuration system
    - [X] Using a config file (Named `config.yaml`)
    - a Dialog for editing the file when config button pressed
- [X] Changing the default (english) alphabet
    - Editing current alphabet
    - Typing new alphabet
    - Reverting to default alphabet (By deleting `config.yaml`)
    - Setting new default alphabet (By editing `config.yaml`)
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
    - Different Compression algorithms
- [ ] Implement a plugin system
    - Use `pluginlib`
    - Define 3 parents: Encoder, Decoder, Bruteforcer
    - Sample code for an encoder:
        ```python
        import pluginlib
        @pluginlib.Parent('encoder')
        class SomeCipher(object):
            @pluginlib.abstractmethod
            def encode(self, string):
                # encode function
                return "encoded"
        ```
#### Last update: 2024-07-04
