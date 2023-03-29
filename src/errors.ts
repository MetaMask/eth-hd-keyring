/* eslint-disable no-shadow */
/* eslint-disable no-unused-vars */
export enum HDKeyringErrors {
  MissingMnemonic = 'Eth-Hd-Keyring: Missing mnemonic when serializing',
  DeserializeErrorNumberOfAccountWithMissingMnemonic = 'Eth-Hd-Keyring: Deserialize method cannot be called with an opts value for numberOfAccounts and no menmonic',
  NoSRPProvided = 'Eth-Hd-Keyring: No secret recovery phrase provided',
  OriginNotEmpty = `Eth-Hd-Keyring: 'origin' must be a non-empty string`,
  AddressNotFound = 'Eth-Hd-Keyring: Address $address not found in this keyring',
  AddressNotProvided = 'Eth-Hd-Keyring: Must specify address.',
  NoMatchingAddress = 'Eth-Hd-Keyring: Unable to find matching address.',
  InvalidSRP = 'Eth-Hd-Keyring: Invalid secret recovery phrase provided',
  SRPAlreadyProvided = 'Eth-Hd-Keyring: Secret recovery phrase already provided',
  MissingHdPath = 'Eth-Hd-Keyring: Missing hd path',
  MissingPrivateKey = 'Eth-Hd-Keyring: Missing private key in wallet',
  MissingPublicKey = 'Eth-Hd-Keyring: Missing public key in wallet',
}
