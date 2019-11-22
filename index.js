const EventEmitter = require('events').EventEmitter
const hdkey = require('./eth-hdkey.js')
const Wallet = require('eth-simple-keyring/eth-wallet')
const SimpleKeyring = require('eth-simple-keyring')
const bip39 = require('bip39')
const ethUtil = require('ethereumjs-util')
const sigUtil = require('eth-sig-util')

// Options:
const hdPathString = `m/44'/60'/0'/0`
const type = 'HD Key Tree'

class HdKeyring extends SimpleKeyring {

  /* PUBLIC METHODS */
  constructor (opts = {}) {
    super()
    this.type = type
    this.deserialize(opts)
  }

  serialize () {
    return Promise.resolve({
      mnemonic: this.mnemonic,
      numberOfAccounts: this.wallets.length,
      hdPath: this.hdPath,
    })
  }

  deserialize (opts = {}) {
    this.opts = opts || {}
    this.wallets = []
    this.mnemonic = null
    this.root = null
    this.hdPath = opts.hdPath || hdPathString

    if (opts.mnemonic) {
      this._initFromMnemonic(opts.mnemonic)
    }

    if (opts.numberOfAccounts) {
      return this.addAccounts(opts.numberOfAccounts)
    }

    return Promise.resolve([])
  }

  addAccounts (numberOfAccounts = 1) {
    if (!this.root) {
      this._initFromMnemonic(bip39.generateMnemonic())
    }

    const oldLen = this.wallets.length
    const newWallets = []
    for (let i = oldLen; i < numberOfAccounts + oldLen; i++) {
      const child = this.root.deriveChild(i)
      const wallet = child.getWallet()
      newWallets.push(wallet)
      this.wallets.push(wallet)
    }
    const hexWallets = newWallets.map((w) => {
      return sigUtil.normalize(w.getAddress().toString('hex'))
    })
    return Promise.resolve(hexWallets)
  }

  getAccounts () {
    return Promise.resolve(this.wallets.map((w) => {
      return sigUtil.normalize(w.getAddress().toString('hex'))
    }))
  }

  exportAccount (address) {
    const wallet = this._getWalletForAccount(address)
    return Promise.resolve(wallet.getPrivateKey().toString('hex'))
  }

  /* PRIVATE METHODS */

  _initFromMnemonic (mnemonic) {
    this.mnemonic = mnemonic
    const seed = bip39.mnemonicToSeed(mnemonic)
    this.hdWallet = hdkey.fromMasterSeed(seed)
    this.root = this.hdWallet.derivePath(this.hdPath)
  }


  _getWalletForAccount (account, opts = {}) {
    const targetAddress = sigUtil.normalize(account)

    let wallet = this.wallets.find((w) => {
      const address = sigUtil.normalize(w.getAddress().toString('hex'))
      return ((address === targetAddress) ||
              (sigUtil.normalize(address) === targetAddress))
    })

    if (opts.withAppKeyOrigin) {
      const privKey = wallet.getPrivateKey()
      const appKeyOriginBuffer = Buffer.from(opts.withAppKeyOrigin, 'utf8')
      const appKeyBuffer = Buffer.concat([privKey, appKeyOriginBuffer])
      const appKeyPrivKey = ethUtil.keccak(appKeyBuffer, 256)
      wallet = Wallet.fromPrivateKey(appKeyPrivKey)
    }

    return wallet
  }

  getPrivateKeyFor (address, opts = {}) {
    if (!address) {
      throw new Error('Must specify address.');
    }
    const wallet = this._getWalletForAccount(address, opts)
    const privKey = ethUtil.toBuffer(wallet.getPrivateKey())
    return privKey;
  }

}

HdKeyring.type = type
module.exports = HdKeyring
