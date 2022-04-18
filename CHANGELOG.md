# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [4.0.0]
### Changed
- **BREAKING**: Do not allow re-initialization of keyring instance ([#55](https://github.com/MetaMask/eth-hd-keyring/pull/55))
    - Consumers are now required to call generateRandomMnemonic() after initialization for creating new SRPs.
- **BREAKING**: Update minimum Node.js version from v10 to v12 ([#45](https://github.com/MetaMask/eth-hd-keyring/pull/45))
- Add `@lavamoat/allow-scripts` ([#47](https://github.com/MetaMask/eth-hd-keyring/pull/47))
    - We now have an allowlist for all post-install scripts. The standard setup script has been added, along with new contributor documentation in the README to explain this script.
- Obfuscate serialized mnemonic ([#59](https://github.com/MetaMask/eth-hd-keyring/pull/59))
- Package name changed from `eth-hd-keyring` to `@metamask/eth-hd-keyring`

[Unreleased]: https://github.com/MetaMask/eth-hd-keyring/compare/v4.0.0...HEAD
[4.0.0]: https://github.com/MetaMask/eth-hd-keyring/releases/tag/v4.0.0
