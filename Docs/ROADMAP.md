# Overall CRYPT Development & Features Roadmap
### Last update: 2024-11-17
## Pending
- [ ] Implement the following:
    - RSA
    - Enigma Machine
    - Rail fence cipher
    - Polybius square
    - Bifid cipher
    - Trifid cipher
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
- [X] Implement a plugin system
    - Uses `pluginlib`
    - an Example cipher (named `a1z26`) is included
    - All plugins must be placed in `modules/plugins` folder under their own folder
    - All plugins must have a `info.yaml` file
- Implemented the following (as Plugins):
  - A1Z26
  - Affine Cipher
  - XOR
