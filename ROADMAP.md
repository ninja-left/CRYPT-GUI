# Overall CRYPT Development & Features Roadmap
- [X] Implement brute-forcers
- [ ] Implement a configuration system
    - Using a config file maybe
    - A menu entry for editing the file
- [ ] Changing the default (english) alphabet
    - [X] Editing current alphabet
    - [X] Typing new alphabet
    - Reverting to default alphabet
    - Setting new default alphabet (using the config system?)
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
        ```python3
        import pluginlib
        @pluginlib.Parent('encoder')
        class Encoder(object):
            @pluginlib.abstractmethod
            def encode(self, string):
                # encode function
                return "encoded"
        ```
#### Last update: 2024-06-26
