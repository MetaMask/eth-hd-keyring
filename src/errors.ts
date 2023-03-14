/* eslint-disable no-shadow */
/* eslint-disable no-unused-vars */
export enum HDKeyringErrors {
  MISSING_MNEMONIC = 'Eth-Hd-Keyring: Missing mnemonic when serializing',
  DESERIALIZE_ERROR_NUMBER_OF_ACCOUNT_WITH_MISSING_MNEMONIC = 'Eth-Hd-Keyring: Deserialize method cannot be called with an opts value for numberOfAccounts and no menmonic',
  NO_SRP_PROVIDED = 'Eth-Hd-Keyring: No secret recovery phrase provided',
  ORIGIN_NOT_EMPTY = `Eth-Hd-Keyring: 'origin' must be a non-empty string`,
  ADDRESS_NOT_FOUND = 'Eth-Hd-Keyring: Address $address not found in this keyring',
  ADDRESS_NOT_PROVIDED = 'Eth-Hd-Keyring: Must specify address.',
  NO_MATCHING_ADDRESS = 'Eth-Hd-Keyring: Unable to find matching address.',
  INVALID_SRP = 'Eth-Hd-Keyring: Invalid secret recovery phrase provided',
  SRP_ALREADY_PROVIDED = 'Eth-Hd-Keyring: Secret recovery phrase already provided',
  MISSING_HD_PATH = 'Eth-Hd-Keyring: Missing hd path',
  MISSING_PRIVATE_KEY = 'Eth-Hd-Keyring: Missing private key in wallet',
  MISSING_PUBLIC_KEY = 'Eth-Hd-Keyring: Missing public key in wallet',
}
