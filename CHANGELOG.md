# Changelog
## [0.1.2]
### Added
- ciphers.py: file containing functions for encoding, decoding input.
- cracker.py: Contains functions for brute-forcing hashes and some ciphers.
- Alphabets for encoders and decoders
- Setting fields turn on based on chosen operation
### Changes
- GUI Setting tab: Added fields alphabet, key, salt, and salt pattern.
- Crypt.py: Using a variable for the paste timeout
- compile.sh: Moved environment activation from individual scripts to there.
### Fixes
- compile.sh: Now it works.

## [0.1.1] - 2024-06-21
### Added
- Timeout for paste function (It won't freeze in case of empty clipboard on KDE Plasma Wayland)
### Changed
- Paste now appends data
- Renamed Crypt-VERSION.py to Crypt.py

## [0.1.0] - 2024-06-13
### Added
- Copy and Paste functions
- Buttons change based on chosen operation mode

[0.1.2]: https://github.com/ninja-left/CRYPT/releases/tag/v0.1.2
[0.1.1]: https://github.com/ninja-left/CRYPT/releases/tag/v0.1.1
[0.1.0]: https://github.com/ninja-left/CRYPT/releases/tag/v0.1.0
