const { hdkey } = require('ethereumjs-wallet');
const SimpleKeyring = require('eth-simple-keyring');
const bip39 = require('bip39');
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
    return Promise.resolve({
      mnemonic: this.mnemonic,
      numberOfAccounts: this.wallets.length,
      hdPath: this.hdPath,
    });
  }

  deserialize(opts = {}) {
    if (this.root) {
      throw new Error(
        'Eth-Hd-Keyring: Secret recovery phrase already provided',
      );
    }

    this.opts = opts || {};
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
    this.mnemonic = mnemonic;
    // eslint-disable-next-line node/no-sync
    const seed = bip39.mnemonicToSeedSync(mnemonic);
    this.hdWallet = hdkey.fromMasterSeed(seed);
    this.root = this.hdWallet.derivePath(this.hdPath);
  }
}

HdKeyring.type = type;
module.exports = HdKeyring;
