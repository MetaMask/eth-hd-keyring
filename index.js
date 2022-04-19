const { hdkey } = require('ethereumjs-wallet');
const SimpleKeyring = require('eth-simple-keyring');
const bip39 = require('@metamask/bip39');
const { normalize } = require('@metamask/eth-sig-util');

// Options:
const hdPathString = `m/44'/60'/0'/0`;
const type = 'HD Key Tree';

class HdKeyring extends SimpleKeyring {
  /* PUBLIC METHODS */
  constructor(opts = {}) {
    super();
    this.type = type;
    this.deserialize(opts);
  }

  generateRandomMnemonic() {
    this._initFromMnemonic(bip39.generateMnemonic());
  }

  serialize() {
    const mnemonicAsBuffer =
      typeof this.mnemonic === 'string'
        ? Buffer.from(this.mnemonic, 'utf8')
        : this.mnemonic;

    return Promise.resolve({
      mnemonic: Array.from(mnemonicAsBuffer.values()),
      numberOfAccounts: this.wallets.length,
      hdPath: this.hdPath,
    });
  }

  deserialize(opts = {}) {
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
    this.wallets = [];
    this.mnemonic = null;
    this.root = null;
    this.hdPath = opts.hdPath || hdPathString;

    if (opts.mnemonic) {
      this._initFromMnemonic(opts.mnemonic);
    }

    if (opts.numberOfAccounts) {
      return this.addAccounts(opts.numberOfAccounts);
    }

    return Promise.resolve([]);
  }

  addAccounts(numberOfAccounts = 1) {
    if (!this.root) {
      throw new Error('Eth-Hd-Keyring: No secret recovery phrase provided');
    }

    const oldLen = this.wallets.length;
    const newWallets = [];
    for (let i = oldLen; i < numberOfAccounts + oldLen; i++) {
      const child = this.root.deriveChild(i);
      const wallet = child.getWallet();
      newWallets.push(wallet);
      this.wallets.push(wallet);
    }
    const hexWallets = newWallets.map((w) => {
      return normalize(w.getAddress().toString('hex'));
    });
    return Promise.resolve(hexWallets);
  }

  getAccounts() {
    return Promise.resolve(
      this.wallets.map((w) => {
        return normalize(w.getAddress().toString('hex'));
      }),
    );
  }

  /* PRIVATE METHODS */

  /**
   * Sets appropriate properties for the keyring based on the given
   * BIP39-compliant mnemonic.
   *
   * @param {string|Array<number>|Buffer} mnemonic - A seed phrase represented
   * as a string, an array of UTF-8 bytes, or a Buffer. Mnemonic input
   * passed as type buffer or array of UTF-8 bytes must be NFKD normalized.
   */
  _initFromMnemonic(mnemonic) {
    if (this.root) {
      throw new Error(
        'Eth-Hd-Keyring: Secret recovery phrase already provided',
      );
    }
    // validate before initializing
    const isValid = bip39.validateMnemonic(mnemonic);
    if (!isValid) {
      throw new Error(
        'Eth-Hd-Keyring: Invalid secret recovery phrase provided',
      );
    }

    if (typeof mnemonic === 'string') {
      this.mnemonic = Buffer.from(mnemonic, 'utf8');
    } else if (Array.isArray(mnemonic)) {
      this.mnemonic = Buffer.from(mnemonic);
    } else {
      this.mnemonic = mnemonic;
    }

    // eslint-disable-next-line node/no-sync
    const seed = bip39.mnemonicToSeedSync(this.mnemonic);
    this.hdWallet = hdkey.fromMasterSeed(seed);
    this.root = this.hdWallet.derivePath(this.hdPath);
  }
}

HdKeyring.type = type;
module.exports = HdKeyring;
