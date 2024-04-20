import { TxData, TypedTransaction } from '@ethereumjs/tx';
import {
  stripHexPrefix,
  privateToPublic,
  publicToAddress,
  ecsign,
  arrToBufArr,
  bufferToHex,
  ECDSASignature,
} from '@ethereumjs/util';
import {
  concatSig,
  decrypt,
  getEncryptionPublicKey,
  normalize,
  personalSign,
  signTypedData,
  SignTypedDataVersion,
  TypedDataV1,
  TypedMessage,
} from '@metamask/eth-sig-util';
import { wordlist } from '@metamask/scure-bip39/dist/wordlists/english';
import { Hex, Keyring, Eip1024EncryptedData } from '@metamask/utils';
import { HDKey } from 'ethereum-cryptography/hdkey';
import { keccak256 } from 'ethereum-cryptography/keccak';
import { bytesToHex } from 'ethereum-cryptography/utils';

import { HDKeyringErrors } from './errors';

// TODO: Find out why when imported usin ES6, mnemonic changes
// eslint-disable-next-line @typescript-eslint/no-var-requires, @typescript-eslint/no-require-imports, no-restricted-globals
const bip39 = require('@metamask/scure-bip39');

type JsCastedBuffer = {
  type: string;
  data: any;
};
export type KeyringOpt = {
  mnemonic?: Buffer | JsCastedBuffer | string | Uint8Array | number[];
  numberOfAccounts?: number;
  hdPath?: string;
  withAppKeyOrigin?: string;
  version?: SignTypedDataVersion;
  validateMessage?: boolean;
};

type SerializedHdKeyringState = {
  mnemonic: number[];
  numberOfAccounts: number;
  hdPath: string;
};

// Options:
const hdPathString = `m/44'/60'/0'/0`;
const type = 'HD Key Tree';

export default class HDKeyring implements Keyring<SerializedHdKeyringState> {
  static type: string = type;

  type: string = type;

  #wallets: HDKey[] = [];

  root: HDKey | undefined | null;

  mnemonic: Uint8Array | undefined | null;

  hdWallet: HDKey | undefined | null;

  hdPath: string = hdPathString;

  opts: KeyringOpt | undefined | null;

  /* PUBLIC METHODS */
  constructor(opts: KeyringOpt = {}) {
    this.type = type;
    this.#wallets = [];
    this.deserialize(opts).catch((error: Error) => {
      throw error;
    });
  }

  /**
   * Generates a random mnemonic and initializes the HDKeyring from it.
   */
  generateRandomMnemonic() {
    this.#initFromMnemonic(bip39.generateMnemonic(wordlist));
  }

  /**
   * Converts a Uint8Array to a string representation using the provided wordlist.
   *
   * @private
   * @param mnemonic - The Uint8Array to convert.
   * @returns The string representation of the Uint8Array.
   */
  #uint8ArrayToString(mnemonic: Uint8Array): string {
    const recoveredIndices = Array.from(
      new Uint16Array(new Uint8Array(mnemonic).buffer),
    );
    return recoveredIndices.map((i) => wordlist[i]).join(' ');
  }

  /**
   * Converts a mnemonic string to a Uint8Array.
   *
   * @private
   * @param mnemonic - The mnemonic string to convert.
   * @returns The Uint8Array representation of the mnemonic.
   */
  #stringToUint8Array(mnemonic: string): Uint8Array {
    const indices = mnemonic.split(' ').map((word) => wordlist.indexOf(word));
    return new Uint8Array(new Uint16Array(indices).buffer);
  }

  /**
   * Converts the mnemonic to a Uint8Array.
   *
   * @private
   * @param mnemonic - The mnemonic to convert.
   * @returns The converted Uint8Array.
   */
  #mnemonicToUint8Array(
    mnemonic: Buffer | JsCastedBuffer | string | Uint8Array | number[],
  ): Uint8Array {
    let mnemonicData = mnemonic;
    // when encrypted/decrypted, buffers get cast into js object with a property type set to buffer
    if (
      mnemonic &&
      typeof mnemonic !== 'string' &&
      !ArrayBuffer.isView(mnemonic) &&
      !Array.isArray(mnemonic) &&
      !Buffer.isBuffer(mnemonic) &&
      mnemonic.type === 'Buffer'
    ) {
      mnemonicData = mnemonic.data;
    }

    if (
      // this block is for backwards compatibility with vaults that were previously stored as buffers, number arrays or plain text strings
      typeof mnemonicData === 'string' ||
      Buffer.isBuffer(mnemonicData) ||
      Array.isArray(mnemonicData)
    ) {
      let mnemonicAsString;
      if (Array.isArray(mnemonicData)) {
        mnemonicAsString = Buffer.from(mnemonicData).toString();
      } else if (Buffer.isBuffer(mnemonicData)) {
        mnemonicAsString = mnemonicData.toString();
      } else {
        mnemonicAsString = mnemonicData;
      }
      return this.#stringToUint8Array(mnemonicAsString);
    } else if (
      mnemonicData instanceof Object &&
      !(mnemonicData instanceof Uint8Array)
    ) {
      // when encrypted/decrypted the Uint8Array becomes a js object we need to cast back to a Uint8Array
      return Uint8Array.from(Object.values(mnemonicData));
    }
    return mnemonicData;
  }

  /**
   * Serializes the HDKeyring instance into a serialized state.
   *
   * @returns A promise that resolves to the serialized state of the HDKeyring.
   * @throws {Error} If the mnemonic is missing.
   */
  async serialize(): Promise<SerializedHdKeyringState> {
    if (!this.mnemonic) {
      throw new Error(HDKeyringErrors.MissingMnemonic);
    }

    const mnemonicAsString = this.#uint8ArrayToString(this.mnemonic);
    const uint8ArrayMnemonic = new TextEncoder().encode(mnemonicAsString);

    return Promise.resolve({
      mnemonic: Array.from(uint8ArrayMnemonic),
      numberOfAccounts: this.#wallets.length,
      hdPath: this.hdPath,
    });
  }

  /**
   * Deserializes the keyring state.
   *
   * @param state - The keyring state to deserialize.
   * @returns A promise that resolves when the deserialization is complete.
   * @throws {Error} If the `numberOfAccounts` is provided without the `mnemonic`.
   * @throws {Error} If the keyring has already been initialized.
   */
  async deserialize(state: KeyringOpt = {}): Promise<void> {
    if (state.numberOfAccounts && !state.mnemonic) {
      throw new Error(
        HDKeyringErrors.DeserializeErrorNumberOfAccountWithMissingMnemonic,
      );
    }

    if (this.root) {
      throw new Error(HDKeyringErrors.SRPAlreadyProvided);
    }
    this.opts = state;
    this.#wallets = [];
    this.mnemonic = null;
    this.root = null;
    this.hdPath = state.hdPath ?? hdPathString;

    if (state.mnemonic) {
      this.#initFromMnemonic(state.mnemonic);
    }

    if (state.numberOfAccounts) {
      await this.addAccounts(state.numberOfAccounts);
    }
  }

  /**
   * Adds accounts to the HDKeyring.
   *
   * @param index - The index of the account to add. Defaults to 1.
   * @returns A promise that resolves to an array of hexadecimal account addresses.
   * @throws {Error} If no SRP (Secure Remote Password) is provided.
   */
    if (!this.root) {
      throw new Error(HDKeyringErrors.NoSRPProvided);
    }

    const oldLen = this.#wallets.length;
    const newWallets: HDKey[] = [];
    for (let i = oldLen; i < numberOfAccounts + oldLen; i++) {
      const wallet = this.root.deriveChild(i);
      newWallets.push(wallet);
      this.#wallets.push(wallet);
    }

  /**
   * Retrieves the accounts associated with the HD keyring that is ordered by index.
   *
   * @returns A promise that resolves to an array of hexadecimal account addresses.
   * @throws {Error} If the public key is missing for any wallet.
   */
  async getAccounts(): Promise<Hex[]> {
      if (!wallet.publicKey) {
        throw new Error(HDKeyringErrors.MissingPublicKey);
      }
      // HDKey's method publicKey can return null
      return this.#addressfromPublicKey(wallet.publicKey);
    });
    return Promise.resolve(hexWallets);
  }

  async getAccounts(): Promise<Hex[]> {
    return Promise.resolve(
      this.#wallets.map((wallet) => {
        if (!wallet.publicKey) {
          throw new Error(HDKeyringErrors.MissingPublicKey);
        }
        return this.#addressfromPublicKey(wallet.publicKey);
      }),
    );
  }

  /* BASE KEYRING METHODS */

  /**
   * Retrieves the application key address for a given Ethereum address and origin.
   *
   * @param address - The Ethereum address for which to retrieve the application key address.
   * @param origin - The origin of the application key.
   * @returns The application key address as a hexadecimal string.
   * @throws {Error} If the origin is empty or not a string, or if the wallet's public key is missing.
   */
  async getAppKeyAddress(address: Hex, origin: string): Promise<Hex> {
    if (!origin || typeof origin !== 'string') {
      throw new Error(HDKeyringErrors.OriginNotEmpty);
    }
    const wallet = this.#getWalletForAccount(address, {
      withAppKeyOrigin: origin,
    });

    if (!wallet.publicKey) {
      throw new Error(HDKeyringErrors.MissingPublicKey);
    }
    // normalize will prefix the address with 0x
    const appKeyAddress = normalize(
      publicToAddress(Buffer.from(wallet.publicKey)).toString('hex'),
    ) as Hex;

    return appKeyAddress;
  }

  /**
   * Exports the account associated with the given address that is hex-encoded private key.
   *
   * @param address - The address of the account to export.
   * @param opts - Optional parameters for exporting the account.
   * @returns A Promise that resolves to the exported account as a string.
   * @throws {Error} If the private key is missing for the account.
   */
  async exportAccount(address: Hex, opts: KeyringOpt = {}): Promise<string> {
    const wallet = this.#getWalletForAccount(address, opts);
    if (!wallet.privateKey) {
      throw new Error(HDKeyringErrors.MissingPrivateKey);
    }
    return bytesToHex(wallet.privateKey);
  }

  /**
   * Signs a transaction using the private key associated with the given address.
   *
   * @param address - The address to sign the transaction for.
   * @param transaction - The transaction to sign.
   * @param options - Additional options for signing the transaction.
   * @returns A promise that resolves to the signed transaction data.
   */
  async signTransaction(
    address: Hex,
    transaction: TypedTransaction,
    options: KeyringOpt = {},
  ): Promise<TxData> {
    const privKey = this.#getPrivateKeyFor(address, options);
    const signedTx = transaction.sign(Buffer.from(privKey));

    // Newer versions of Ethereumjs-tx are immutable and return a new tx object
    return signedTx === undefined ? transaction : signedTx;
  }

  /**
   * Signs a message with the private key associated with the given address.
   *
   * @param address - The address to sign the message with.
   * @param data - The message to sign.
   * @param opts - Optional parameters for signing the message.
   * @returns The raw message signature.
   * @throws {Error} If the message is invalid and `validateMessage` is set to `true`.
   */
  async signMessage(
    address: Hex,
    data: string,
    opts: KeyringOpt = { validateMessage: true },
  ): Promise<string> {
    const message: string = stripHexPrefix(data);
    if (
      opts.validateMessage &&
      (message.length === 0 || !message.match(/^[a-fA-F0-9]*$/u))
    ) {
      throw new Error(HDKeyringErrors.InvalidMessage);
    }
    const privKey: Uint8Array = this.#getPrivateKeyFor(address, opts);
    const msgSig: ECDSASignature = ecsign(
      Buffer.from(message, 'hex'),
      Buffer.from(privKey),
    );
    const rawMsgSig: string = concatSig(
      msgSig.v as unknown as Buffer,
      msgSig.r,
      msgSig.s,
    );
    return rawMsgSig;
  }

  /**
   * Signs a personal message using the private key associated with the given address.
   * **Note:** The message will be prefixed according to the Ethereum Signed Message standard.
   *
   * @param address - The Ethereum address to sign the message with.
   * @param message - The message to sign.
   * @param options - Additional options for signing the message.
   * @returns A promise that resolves to the signature of the message.
   */
  async signPersonalMessage(
    address: Hex,
    message: Hex,
    options: Record<string, unknown> = {},
  ): Promise<string> {
    const privKey: Uint8Array = this.#getPrivateKeyFor(address, options);
    const privateKey = Buffer.from(privKey);
    const signature = personalSign({ privateKey, data: message as string });
    return signature;
  }

  /**
   * Decrypts a message using the private key associated with the specified account.
   *
   * @param withAccount - The account for which to decrypt the message.
   * @param encryptedData - The encrypted data to be decrypted.
   * @returns The decrypted message.
   * @throws {Error} If the private key is missing.
   */
  async decryptMessage(
    withAccount: Hex,
    encryptedData: Eip1024EncryptedData,
  ): Promise<string> {
    const wallet = this.#getWalletForAccount(withAccount);
    const { privateKey: privateKeyAsUint8Array } = wallet;
    if (!privateKeyAsUint8Array) {
      throw new Error(HDKeyringErrors.MissingPrivateKey);
    }
    const privateKeyAsHex = Buffer.from(privateKeyAsUint8Array).toString('hex');
    const signature = decrypt({ privateKey: privateKeyAsHex, encryptedData });
    return signature;
  }

  /**
   * Signs the provided typed data using the specified account's private key.
   *
   * @param withAccount - The account to sign the typed data with.
   * @param typedData - The typed data to be signed.
   * @param opts - Optional parameters for signing the typed data.
   * @returns A promise that resolves to the signature of the signed typed data.
   */
  async signTypedData(
    withAccount: Hex,
    typedData: Record<string, unknown> | TypedDataV1 | TypedMessage<any>,
    opts: KeyringOpt = { version: SignTypedDataVersion.V1 },
  ): Promise<string> {
    let version: SignTypedDataVersion;
    if (
      opts.version &&
      Object.keys(SignTypedDataVersion).includes(opts.version as string)
    ) {
      version = opts.version;
    } else {
      // Treat invalid versions as "V1"
      version = SignTypedDataVersion.V1;
    }

    const privateKey: Uint8Array = this.#getPrivateKeyFor(withAccount, opts);
    return signTypedData({
      privateKey: Buffer.from(privateKey),
      data: typedData as unknown as TypedDataV1 | TypedMessage<any>,
      version,
    });
  }

  /**
   * Removes an account from the HDKeyring.
   * @param account - The account to be removed.
   * @throws {Error} If the account is not found or if the public key is missing.
   */
  removeAccount(account: Hex): void {
    const address = account;
    if (
      !this.#wallets
        .map(({ publicKey }) => {
          if (!publicKey) {
            throw new Error(HDKeyringErrors.MissingPublicKey);
          }
          return this.#addressfromPublicKey(publicKey);
        })
        .includes(address)
    ) {
      throw new Error(
        HDKeyringErrors.AddressNotFound.replace('$address', address),
      );
    }

    this.#wallets = this.#wallets.filter(({ publicKey }) => {
      if (!publicKey) {
        // should never be here
        throw new Error(HDKeyringErrors.MissingPublicKey);
      }
      return this.#addressfromPublicKey(publicKey) !== address;
    });
  }

  /**
   * Retrieves the encryption public key for a given account.
   * Get public key for nacl.
   *
   * @param withAccount - The account for which to retrieve the encryption public key.
   * @param opts - Additional options for retrieving the encryption public key.
   * @returns The encryption public key as a string.
   */
  async getEncryptionPublicKey(
    withAccount: Hex,
    opts: KeyringOpt = {},
  ): Promise<string> {
    const privKey = this.#getPrivateKeyFor(withAccount, opts);
    const publicKey = getEncryptionPublicKey(
      Buffer.from(privKey).toString('hex'),
    );
    return publicKey;
  }

  /**
   * Retrieves the private key for a given address.
   *
   * @param address - The address for which to retrieve the private key.
   * @param opts - Optional parameters for keyring.
   * @returns The private key as a Uint8Array.
   * @throws {Error} If the address is not provided or if the private key is missing.
   */
  #getPrivateKeyFor(address: Hex, opts: KeyringOpt = {}): Uint8Array {
    if (!address) {
      throw new Error(HDKeyringErrors.AddressNotProvided);
    }
    const wallet = this.#getWalletForAccount(address, opts);
    if (!wallet.privateKey) {
      throw new Error(HDKeyringErrors.MissingPrivateKey);
    }
    return wallet.privateKey;
  }

  /**
   * Retrieves the HDKey wallet for the specified account address.
   *
   * @param address - The account address to retrieve the wallet for.
   * @param opts - Optional parameters for retrieving the wallet.
   * @returns The HDKey wallet for the specified account address.
   * @throws {Error} If the public key is missing or no matching address is found.
   * @throws {Error} If the private key is missing when `opts.withAppKeyOrigin` is provided.
   */
  #getWalletForAccount(address: string, opts: KeyringOpt = {}): HDKey {
    const normalizedAddress = normalize(address);
    let wallet = this.#wallets.find(({ publicKey }) => {
      if (!publicKey) {
        throw new Error(HDKeyringErrors.MissingPublicKey);
      }
      // If a wallet is found, public key will not be null
      return this.#addressfromPublicKey(publicKey) === normalizedAddress;
    });

    if (opts.withAppKeyOrigin) {
      if (!wallet) {
        throw new Error(HDKeyringErrors.NoMatchingAddress);
      }
      const { privateKey } = wallet;
      if (!privateKey) {
        throw new Error(HDKeyringErrors.MissingPrivateKey);
      }
      const appKeyOriginBuffer = Buffer.from(opts.withAppKeyOrigin, 'utf8');
      const appKeyBuffer = Buffer.concat([privateKey, appKeyOriginBuffer]);
      const appKeyPrivateKey = arrToBufArr(keccak256(appKeyBuffer));
      const appKeyPublicKey = privateToPublic(appKeyPrivateKey);
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore special case for appKey
      wallet = { privateKey: appKeyPrivateKey, publicKey: appKeyPublicKey };
    }

    if (!wallet) {
      throw new Error(HDKeyringErrors.NoMatchingAddress);
    }

    return wallet;
  }

  /* PRIVATE / UTILITY METHODS */

  /**
   * Sets appropriate properties for the keyring based on the given
   * BIP39-compliant mnemonic.
   *
   * @param mnemonic - A seed phrase represented
   * as a string, an array of UTF-8 bytes, or a Buffer. Mnemonic input
   * passed as type buffer or array of UTF-8 bytes must be NFKD normalized.
   */
  #initFromMnemonic(
    mnemonic: string | number[] | Buffer | Uint8Array | JsCastedBuffer,
  ): void {
    if (this.root) {
      throw new Error(HDKeyringErrors.SRPAlreadyProvided);
    }

    this.mnemonic = this.#mnemonicToUint8Array(mnemonic);

    // validate before initializing
    const isValid = bip39.validateMnemonic(this.mnemonic, wordlist);
    if (!isValid) {
      throw new Error(HDKeyringErrors.InvalidSRP);
    }

    // eslint-disable-next-line node/no-sync
    const seed = bip39.mnemonicToSeedSync(this.mnemonic, wordlist);
    this.hdWallet = HDKey.fromMasterSeed(seed);
    if (!this.hdPath) {
      throw new Error(HDKeyringErrors.MissingHdPath);
    }
    this.root = this.hdWallet.derive(this.hdPath);
  }

  /**
   * Converts a public key to an Ethereum address.
   *
   * @param publicKey - The public key to convert.
   * @returns The Ethereum address corresponding to the public key.
   */
  #addressfromPublicKey(publicKey: Uint8Array): Hex {
    // bufferToHex adds a 0x prefix
    const address = bufferToHex(
      publicToAddress(Buffer.from(publicKey), true),
    ).toLowerCase() as Hex;

    return address;
  }
}
