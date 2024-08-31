# Overall CRYPT Development & Features Roadmap
### Last update: 2024-08-27
## Pending
- [ ] Implement a plugin system
    - [X] Use `pluginlib`
    - [X] Define 1 parent with 4 functions: encode, decode, brute_force, & get_info
    - [X] Example cipher (name `a1z26`) is included
    - All plugins must be placed in `modules/plugins` folder under their own folder
    - All plugins must have a `info.yaml` file
    - [ ] Load plugins in the app
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
