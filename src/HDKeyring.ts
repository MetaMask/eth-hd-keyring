import { HDKey } from 'ethereum-cryptography/hdkey';
import { keccak256 } from 'ethereum-cryptography/keccak';
import { bytesToHex } from 'ethereum-cryptography/utils';
import {
  stripHexPrefix,
  privateToPublic,
  publicToAddress,
  ecsign,
  arrToBufArr,
  bufferToHex,
  ECDSASignature,
} from '@ethereumjs/util';

import { wordlist } from '@metamask/scure-bip39/dist/wordlists/english';
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
import { Hex, Keyring, Eip1024EncryptedData } from '@metamask/utils';
import { TxData, TypedTransaction } from '@ethereumjs/tx';
import { HDKeyringErrors } from './errors';

const bip39 = require('@metamask/scure-bip39');

type JsCastedBuffer = {
  type: string;
  data: any;
};
interface KeyringOpt {
  mnemonic?: Buffer | JsCastedBuffer | string | Uint8Array | Array<number>;
  numberOfAccounts?: number;
  hdPath?: string;
  withAppKeyOrigin?: string;
  version?: SignTypedDataVersion;
}

type SerializedHdKeyringState = {
  mnemonic: number[];
  numberOfAccounts: number;
  hdPath: string;
};

// Options:
const hdPathString = `m/44'/60'/0'/0`;
const type = 'HD Key Tree';

export default class HdKeyring implements Keyring<SerializedHdKeyringState> {
  static type: string = type;

  type: string;

  #wallets: HDKey[] = [];

  root: HDKey | undefined | null;

  mnemonic: Uint8Array | undefined | null;

  hdWallet: HDKey | undefined | null;

  hdPath: string | undefined | null;

  opts: KeyringOpt | undefined | null;

  /* PUBLIC METHODS */
  constructor(opts: KeyringOpt = {}) {
    this.type = type;
    this.#wallets = [];
    this.deserialize(opts);
  }

  generateRandomMnemonic() {
    this.#initFromMnemonic(bip39.generateMnemonic(wordlist));
  }

  #uint8ArrayToString(mnemonic: Uint8Array): string {
    const recoveredIndices = Array.from(
      new Uint16Array(new Uint8Array(mnemonic).buffer),
    );
    return recoveredIndices.map((i) => wordlist[i]).join(' ');
  }

  #stringToUint8Array(mnemonic: string): Uint8Array {
    const indices = mnemonic.split(' ').map((word) => wordlist.indexOf(word));
    return new Uint8Array(new Uint16Array(indices).buffer);
  }

  #mnemonicToUint8Array(
    mnemonic: Buffer | JsCastedBuffer | string | Uint8Array | Array<number>,
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

  serialize(): Promise<SerializedHdKeyringState> {
    if (!this.mnemonic) {
      throw new Error(HDKeyringErrors.MISSING_MNEMONIC);
    }

    if (!this.hdPath) {
      throw new Error(HDKeyringErrors.MISSING_HD_PATH);
    }

    const mnemonicAsString = this.#uint8ArrayToString(this.mnemonic);
    const uint8ArrayMnemonic = new TextEncoder().encode(mnemonicAsString);

    return Promise.resolve({
      mnemonic: Array.from(uint8ArrayMnemonic),
      numberOfAccounts: this.#wallets.length,
      hdPath: this.hdPath,
    });
  }

  // @ts-ignore return type is void
  deserialize(state: KeyringOpt = {}): Promise<string[]> {
    if (state.numberOfAccounts && !state.mnemonic) {
      throw new Error(
        HDKeyringErrors.DESERIALIZE_ERROR_NUMBER_OF_ACCOUNT_WITH_MISSING_MNEMONIC,
      );
    }

    if (this.root) {
      throw new Error(HDKeyringErrors.SRP_ALREADY_PROVIDED);
    }
    this.opts = state;
    this.#wallets = [];
    this.mnemonic = null;
    this.root = null;
    this.hdPath = state.hdPath || hdPathString;

    if (state.mnemonic) {
      this.#initFromMnemonic(state.mnemonic);
    }

    if (state.numberOfAccounts) {
      return this.addAccounts(state.numberOfAccounts);
    }

    return Promise.resolve([]);
  }

  addAccounts(numberOfAccounts = 1): Promise<Hex[]> {
    if (!this.root) {
      throw new Error(HDKeyringErrors.NO_SRP_PROVIDED);
    }

    const oldLen = this.#wallets.length;
    const newWallets: HDKey[] = [];
    for (let i = oldLen; i < numberOfAccounts + oldLen; i++) {
      const wallet = this.root.deriveChild(i);
      newWallets.push(wallet);
      this.#wallets.push(wallet);
    }

    const hexWallets: Hex[] = newWallets.map((w) => {
      // HDKey's method publicKey can return null
      return this.#addressfromPublicKey(w.publicKey!);
    });
    return Promise.resolve(hexWallets);
  }

  getAccounts(): Promise<Hex[]> {
    return Promise.resolve(
      this.#wallets.map((w) => this.#addressfromPublicKey(w.publicKey!)),
    );
  }

  /* BASE KEYRING METHODS */

  // returns an address specific to an app
  async getAppKeyAddress(address: Hex, origin: string): Promise<Hex> {
    if (!origin || typeof origin !== 'string') {
      throw new Error(HDKeyringErrors.ORIGIN_NOT_EMPTY);
    }
    const wallet = this.#getWalletForAccount(address, {
      withAppKeyOrigin: origin,
    });
    // normalize will prefix the address with 0x
    const appKeyAddress = normalize(
      publicToAddress(Buffer.from(wallet.publicKey!)).toString('hex'),
    ) as Hex;

    return appKeyAddress;
  }

  // exportAccount should return a hex-encoded private key:
  async exportAccount(address: Hex, opts: KeyringOpt = {}): Promise<string> {
    const wallet = this.#getWalletForAccount(address, opts);
    if (!wallet.privateKey) {
      throw new Error(HDKeyringErrors.MISSING_PRIVATE_KEY);
    }
    return bytesToHex(wallet.privateKey);
  }

  // tx is an instance of the ethereumjs-transaction class.
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

  // For eth_sign, we need to sign arbitrary data:
  async signMessage(
    address: Hex,
    data: string,
    opts: KeyringOpt = {},
  ): Promise<string> {
    const message: string = stripHexPrefix(data);
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

  // For personal_sign, we need to prefix the message:
  async signPersonalMessage(
    address: Hex,
    message: Hex,
    options: Record<string, unknown> = {},
  ): Promise<string> {
    const privKey: Uint8Array = this.#getPrivateKeyFor(address, options);
    const privateKey = Buffer.from(privKey);
    const sig = personalSign({ privateKey, data: message as string });
    return sig;
  }

  // For eth_decryptMessage:
  async decryptMessage(
    withAccount: Hex,
    encryptedData: Eip1024EncryptedData,
  ): Promise<string> {
    const wallet = this.#getWalletForAccount(withAccount);
    const { privateKey: privateKeyAsUint8Array } = wallet;
    if (!privateKeyAsUint8Array) {
      throw new Error(HDKeyringErrors.MISSING_PRIVATE_KEY);
    }
    const privateKeyAsHex = Buffer.from(privateKeyAsUint8Array).toString('hex');
    const sig = decrypt({ privateKey: privateKeyAsHex, encryptedData });
    return sig;
  }

  // personal_signTypedData, signs data along with the schema
  async signTypedData(
    withAccount: Hex,
    typedData: Record<string, unknown> | TypedDataV1 | TypedMessage<any>,
    opts: KeyringOpt = { version: SignTypedDataVersion.V1 },
  ): Promise<string> {
    // Treat invalid versions as "V1"
    const version: SignTypedDataVersion = Object.keys(
      SignTypedDataVersion,
    ).includes(opts.version as string)
      ? opts.version!
      : SignTypedDataVersion.V1;

    const privateKey: Uint8Array = this.#getPrivateKeyFor(withAccount, opts);
    return signTypedData({
      privateKey: Buffer.from(privateKey),
      data: typedData as unknown as TypedDataV1 | TypedMessage<any>,
      version,
    });
  }

  removeAccount(account: Hex): void {
    const address = account;
    if (
      !this.#wallets
        .map(({ publicKey }) => this.#addressfromPublicKey(publicKey!))
        .includes(address)
    ) {
      throw new Error(
        HDKeyringErrors.ADDRESS_NOT_FOUND.replace('$address', address),
      );
    }

    this.#wallets = this.#wallets.filter(({ publicKey }) => {
      if (!publicKey) {
        // should never be here
        throw new Error(HDKeyringErrors.MISSING_PUBLIC_KEY);
      }
      return this.#addressfromPublicKey(publicKey) !== address;
    });
  }

  // get public key for nacl
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

  #getPrivateKeyFor(address: Hex, opts: KeyringOpt = {}): Uint8Array {
    if (!address) {
      throw new Error(HDKeyringErrors.ADDRESS_NOT_PROVIDED);
    }
    const wallet = this.#getWalletForAccount(address, opts);
    if (!wallet.privateKey) {
      throw new Error(HDKeyringErrors.MISSING_PRIVATE_KEY);
    }
    return wallet.privateKey;
  }

  #getWalletForAccount(address: string, opts: KeyringOpt = {}): HDKey {
    const normalizedAddress = normalize(address);
    let wallet = this.#wallets.find(({ publicKey }) => {
      // If a wallet is found, public key will not be null
      return this.#addressfromPublicKey(publicKey!) === normalizedAddress;
    })!;
    if (!wallet) {
      throw new Error(HDKeyringErrors.NO_MATCHING_ADDRESS);
    }

    if (opts.withAppKeyOrigin) {
      const { privateKey } = wallet;
      if (!privateKey) {
        throw new Error(HDKeyringErrors.MISSING_PRIVATE_KEY);
      }
      const appKeyOriginBuffer = Buffer.from(opts.withAppKeyOrigin, 'utf8');
      const appKeyBuffer = Buffer.concat([privateKey, appKeyOriginBuffer]);
      const appKeyPrivateKey = arrToBufArr(keccak256(appKeyBuffer));
      const appKeyPublicKey = privateToPublic(appKeyPrivateKey);
      // @ts-ignore special case for appKey
      wallet = { privateKey: appKeyPrivateKey, publicKey: appKeyPublicKey };
    }

    return wallet;
  }

  /* PRIVATE / UTILITY METHODS */

  /**
   * Sets appropriate properties for the keyring based on the given
   * BIP39-compliant mnemonic.
   *
   * @param {string|Array<number>|Buffer} mnemonic - A seed phrase represented
   * as a string, an array of UTF-8 bytes, or a Buffer. Mnemonic input
   * passed as type buffer or array of UTF-8 bytes must be NFKD normalized.
   */
  #initFromMnemonic(
    mnemonic: string | Array<number> | Buffer | Uint8Array | JsCastedBuffer,
  ): void {
    if (this.root) {
      throw new Error(HDKeyringErrors.SRP_ALREADY_PROVIDED);
    }

    this.mnemonic = this.#mnemonicToUint8Array(mnemonic);

    // validate before initializing
    const isValid = bip39.validateMnemonic(this.mnemonic, wordlist);
    if (!isValid) {
      throw new Error(HDKeyringErrors.INVALID_SRP);
    }

    // eslint-disable-next-line node/no-sync
    const seed = bip39.mnemonicToSeedSync(this.mnemonic, wordlist);
    this.hdWallet = HDKey.fromMasterSeed(seed);
    if (!this.hdPath) {
      throw new Error(HDKeyringErrors.MISSING_HD_PATH);
    }
    this.root = this.hdWallet.derive(this.hdPath!);
  }

  // small helper function to convert publicKey in Uint8Array form to a publicAddress as a hex
  #addressfromPublicKey(publicKey: Uint8Array): Hex {
    // bufferToHex adds a 0x prefix
    const address = bufferToHex(
      publicToAddress(Buffer.from(publicKey), true),
    ).toLowerCase() as Hex;

    return address;
  }
}