const Wallet = require('eth-simple-keyring/eth-wallet')
const HDKey = require('hdkey') // Bitcoins hdkey

// ====== ethereumjs-wallet/hdkey drop-in replacement ======================
// Issue:   https://github.com/MetaMask/eth-hd-keyring/issues/7
//
// 
class EthereumHDKey {

    constructor(hdkey) {
      this._hdkey = hdkey;
    }
  
     static fromMasterSeed(seedBuffer) {
      return new EthereumHDKey(HDKey.fromMasterSeed(seedBuffer))
    }
  
    derivePath(path) {
      return new EthereumHDKey(this._hdkey.derive(path))
    }
  
    deriveChild(index) {
      return new EthereumHDKey(this._hdkey.deriveChild(index))
    } 
  
    getWallet() {
      if (this._hdkey._privateKey) {
        return Wallet.fromPrivateKey(this._hdkey._privateKey)
      }
      return Wallet.fromPublicKey(this._hdkey._publicKey, true)
    }
    
}

module.exports = EthereumHDKey;
