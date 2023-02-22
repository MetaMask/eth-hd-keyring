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
} from '@ethereumjs/util';
const bip39 = require('@metamask/scure-bip39');

import { wordlist } from '@metamask/scure-bip39/dist/wordlists/english';
import {
  concatSig,
  decrypt,
  getEncryptionPublicKey,
  MessageTypes,
  normalize,
  personalSign,
  signTypedData,
  SignTypedDataVersion,
  TypedDataV1,
  TypedMessage,
} from '@metamask/eth-sig-util';
import { Transaction, TypedTransaction } from '@ethereumjs/tx';

interface KeyringOpt {
  numberOfAccounts?: number;
  mnemonic?: Uint8Array | Buffer | string | number[];
  hdPath?: string;
  withAppKeyOrigin?: string;
  version?: SignTypedDataVersion;
}

// Options:
const hdPathString = `m/44'/60'/0'/0`;
const type = 'HD Key Tree';

export default class HdKeyring {
  static type: string = type;
  type: string;
  _wallets: HDKey[] = [];
  root: HDKey | undefined | null;
  mnemonic: Uint8Array | undefined | null;
  hdWallet: HDKey | undefined | null;
  hdPath: string | undefined | null;
  opts: KeyringOpt | undefined | null;

  /* PUBLIC METHODS */
  constructor(opts: KeyringOpt = {}) {
    this.type = type;
    this._wallets = [];
    this.deserialize(opts);
  }

  generateRandomMnemonic() {
    this.initFromMnemonic(bip39.generateMnemonic(wordlist));
  }

  private uint8ArrayToString(mnemonic: Uint8Array): string {
    const recoveredIndices = Array.from(
      new Uint16Array(new Uint8Array(mnemonic).buffer),
    );
    return recoveredIndices.map((i) => wordlist[i]).join(' ');
  }

  private stringToUint8Array(mnemonic: string): Uint8Array {
    const indices = mnemonic.split(' ').map((word) => wordlist.indexOf(word));
    return new Uint8Array(new Uint16Array(indices).buffer);
  }

  private mnemonicToUint8Array(
    mnemonic: Buffer | string | Uint8Array | Array<number>,
  ): Uint8Array {
    let mnemonicData = mnemonic;
    // when encrypted/decrypted, buffers get cast into js object with a property type set to buffer
    // @ts-ignore
    if (mnemonic && mnemonic.type && mnemonic.type === 'Buffer') {
      // @ts-ignore
      mnemonicData = mnemonic.data;
    }

    if (
      // this block is for backwards compatibility with vaults that were previously stored as buffers, number arrays or plain text strings
      typeof mnemonicData === 'string' ||
      Buffer.isBuffer(mnemonicData) ||
      Array.isArray(mnemonicData)
    ) {
      let mnemonicAsString = mnemonicData;
      if (Array.isArray(mnemonicData)) {
        mnemonicAsString = Buffer.from(mnemonicData).toString();
      } else if (Buffer.isBuffer(mnemonicData)) {
        mnemonicAsString = mnemonicData.toString();
      }
      return this.stringToUint8Array(mnemonicAsString as string);
    } else if (
      mnemonicData instanceof Object &&
      !(mnemonicData instanceof Uint8Array)
    ) {
      // when encrypted/decrypted the Uint8Array becomes a js object we need to cast back to a Uint8Array
      return Uint8Array.from(Object.values(mnemonicData));
    }
    return mnemonicData;
  }

  serialize() {
    if (!this.mnemonic)
      throw new Error('Eth-Hd-Keyring: Missing mnemonic when serializing');

    const mnemonicAsString = this.uint8ArrayToString(this.mnemonic);
    const uint8ArrayMnemonic = new TextEncoder().encode(mnemonicAsString);

    return Promise.resolve({
      mnemonic: Array.from(uint8ArrayMnemonic),
      numberOfAccounts: this._wallets.length,
      hdPath: this.hdPath,
    });
  }

  deserialize(opts: KeyringOpt = {}): Promise<string[]> {
    if (opts.numberOfAccounts && !opts.mnemonic) {
      throw new Error(
        'Eth-Hd-Keyring: Deserialize method cannot be called with an opts value for numberOfAccounts and no menmonic',
      );
    }

    if (this.root) {
      throw new Error(
        'Eth-Hd-Keyring: Secret recovery phrase already provided',
      );
    }
    this.opts = opts;
    this._wallets = [];
    this.mnemonic = null;
    this.root = null;
    this.hdPath = opts.hdPath || hdPathString;

    if (opts.mnemonic) {
      this.initFromMnemonic(opts.mnemonic);
    }

    if (opts.numberOfAccounts) {
      return this.addAccounts(opts.numberOfAccounts);
    }

    return Promise.resolve([]);
  }

  addAccounts(numberOfAccounts = 1): Promise<string[]> {
    if (!this.root) {
      throw new Error('Eth-Hd-Keyring: No secret recovery phrase provided');
    }

    const oldLen = this._wallets.length;
    const newWallets: HDKey[] = [];
    for (let i = oldLen; i < numberOfAccounts + oldLen; i++) {
      const wallet = this.root.deriveChild(i);
      newWallets.push(wallet);
      this._wallets.push(wallet);
    }

    const hexWallets: string[] = newWallets.map((w) => {
      //HDKey's method publicKey can return null
      return this.addressfromPublicKey(w.publicKey!);
    });
    return Promise.resolve(hexWallets);
  }

  getAccounts(): string[] {
    return this._wallets.map((w) => this.addressfromPublicKey(w.publicKey!));
  }

  /* BASE KEYRING METHODS */

  // returns an address specific to an app
  async getAppKeyAddress(address: string, origin: string): Promise<string> {
    if (!origin || typeof origin !== 'string') {
      throw new Error(`'origin' must be a non-empty string`);
    }
    const wallet = this.getWalletForAccount(address, {
      withAppKeyOrigin: origin,
    });
    const appKeyAddress = normalize(
      publicToAddress(wallet.publicKey! as Buffer).toString('hex'),
    );

    return appKeyAddress;
  }

  // exportAccount should return a hex-encoded private key:
  async exportAccount(address: string, opts: KeyringOpt = {}): Promise<string> {
    const wallet = this.getWalletForAccount(address, opts);
    return bytesToHex(wallet.privateKey!);
  }

  // tx is an instance of the ethereumjs-transaction class.
  async signTransaction(
    address: string,
    tx: TypedTransaction,
    opts: KeyringOpt = {},
  ): Promise<TypedTransaction> {
    const privKey = this.getPrivateKeyFor(address, opts);
    const signedTx = tx.sign(privKey as Buffer);
    // Newer versions of Ethereumjs-tx are immutable and return a new tx object
    return signedTx === undefined ? tx : signedTx;
  }

  // For eth_sign, we need to sign arbitrary data:
  async signMessage(
    address: string,
    data: any,
    opts: KeyringOpt = {},
  ): Promise<string> {
    const message = stripHexPrefix(data);
    const privKey = this.getPrivateKeyFor(address, opts);
    const msgSig = ecsign(Buffer.from(message, 'hex'), privKey as Buffer);
    const rawMsgSig = concatSig(
      msgSig.v as unknown as Buffer,
      msgSig.r,
      msgSig.s,
    );
    return rawMsgSig;
  }

  // For personal_sign, we need to prefix the message:
  async signPersonalMessage(
    address: string,
    msgHex: string,
    opts: KeyringOpt = {},
  ): Promise<string> {
    const privKey = this.getPrivateKeyFor(address, opts);
    const privateKey = Buffer.from(privKey);
    const sig = personalSign({ privateKey, data: msgHex });
    return sig;
  }

  // For eth_decryptMessage:
  async decryptMessage(
    withAccount: string,
    encryptedData: any,
  ): Promise<string> {
    const wallet = this.getWalletForAccount(withAccount);
    const { privateKey: privateKeyAsUint8Array } = wallet;
    const privateKeyAsHex = Buffer.from(privateKeyAsUint8Array!).toString(
      'hex',
    );
    const sig = decrypt({ privateKey: privateKeyAsHex, encryptedData });
    return sig;
  }

  // personal_signTypedData, signs data along with the schema
  async signTypedData<T extends MessageTypes>(
    withAccount: string,
    typedData: TypedDataV1 | TypedMessage<T>,
    opts: KeyringOpt = { version: SignTypedDataVersion.V1 },
  ): Promise<string> {
    // Treat invalid versions as "V1"
    const version: SignTypedDataVersion = Object.keys(
      SignTypedDataVersion,
    ).includes(opts.version as string)
      ? opts.version!
      : SignTypedDataVersion.V1;

    const privateKey: Uint8Array = this.getPrivateKeyFor(withAccount, opts);
    return signTypedData({
      privateKey: privateKey as Buffer,
      data: typedData,
      version,
    });
  }

  removeAccount(account: string): void {
    const address = normalize(account);
    if (
      !this._wallets
        .map(({ publicKey }) => this.addressfromPublicKey(publicKey!))
        .includes(address)
    ) {
      throw new Error(`Address ${address} not found in this keyring`);
    }

    this._wallets = this._wallets.filter(
      ({ publicKey }) => this.addressfromPublicKey(publicKey!) !== address,
    );
  }

  // get public key for nacl
  async getEncryptionPublicKey(
    withAccount: string,
    opts: KeyringOpt = {},
  ): Promise<string> {
    const privKey = this.getPrivateKeyFor(withAccount, opts);
    const publicKey = getEncryptionPublicKey(privKey as unknown as string);
    return publicKey;
  }

  private getPrivateKeyFor(address: string, opts: KeyringOpt = {}): Uint8Array {
    if (!address) {
      throw new Error('Must specify address.');
    }
    const wallet = this.getWalletForAccount(address, opts);
    return wallet.privateKey!;
  }

  private getWalletForAccount(address: string, opts: KeyringOpt = {}): HDKey {
    const normalizedAddress = normalize(address);
    let wallet: HDKey = this._wallets.find(({ publicKey }) => {
      // If a wallet is found, public key will not be null
      return this.addressfromPublicKey(publicKey!) === normalizedAddress;
    })!;
    if (!wallet) {
      throw new Error('HD Keyring - Unable to find matching address.');
    }

    if (opts.withAppKeyOrigin) {
      const { privateKey } = wallet;
      const appKeyOriginBuffer = Buffer.from(opts.withAppKeyOrigin, 'utf8');
      const appKeyBuffer = Buffer.concat([privateKey!, appKeyOriginBuffer]);
      const appKeyPrivateKey = arrToBufArr(keccak256(appKeyBuffer));
      const appKeyPublicKey = privateToPublic(appKeyPrivateKey);
      // @ts-ignore
      // wallet = { privateKey: appKeyPrivateKey, publicKey: appKeyPublicKey };
      wallet = new HDKey({ privateKey: appKeyPrivateKey });
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
  private initFromMnemonic(
    mnemonic: string | Array<number> | Buffer | Uint8Array,
  ): void {
    if (this.root) {
      throw new Error(
        'Eth-Hd-Keyring: Secret recovery phrase already provided',
      );
    }

    this.mnemonic = this.mnemonicToUint8Array(mnemonic);

    // validate before initializing
    const isValid = bip39.validateMnemonic(this.mnemonic, wordlist);
    if (!isValid) {
      throw new Error(
        'Eth-Hd-Keyring: Invalid secret recovery phrase provided',
      );
    }

    // eslint-disable-next-line node/no-sync
    const seed = bip39.mnemonicToSeedSync(this.mnemonic, wordlist);
    this.hdWallet = HDKey.fromMasterSeed(seed);
    this.root = this.hdWallet.derive(this.hdPath!);
  }

  // small helper function to convert publicKey in Uint8Array form to a publicAddress as a hex
  private addressfromPublicKey(publicKey: Uint8Array): string {
    return bufferToHex(
      publicToAddress(Buffer.from(publicKey), true),
    ).toLowerCase();
  }
}
