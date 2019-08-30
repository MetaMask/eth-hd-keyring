const assert = require('assert')
const extend = require('xtend')
const HdKeyring = require('../')
const sigUtil = require('eth-sig-util')
const ethUtil = require('ethereumjs-util')


// Sample account:
const privKeyHex = 'b8a9c05beeedb25df85f8d641538cbffedf67216048de9c678ee26260eb91952'

const sampleMnemonic = 'finish oppose decorate face calm tragic certain desk hour urge dinosaur mango'
const firstAcct = '0x1c96099350f13d558464ec79b9be4445aa0ef579'
const secondAcct = '0x1b00aed43a693f3a957f9feb5cc08afa031e37a0'

describe('hd-keyring', function() {

  let keyring
  beforeEach(function() {
    keyring = new HdKeyring()
  })

  describe('constructor', function(done) {
    it('constructs', function (done) {
      keyring = new HdKeyring({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 2,
      })

      const accounts = keyring.getAccounts()
      .then((accounts) => {
        assert.equal(accounts[0], firstAcct)
        assert.equal(accounts[1], secondAcct)
        done()
      })
    })
  })

  describe('Keyring.type', function() {
    it('is a class property that returns the type string.', function() {
      const type = HdKeyring.type
      assert.equal(typeof type, 'string')
    })
  })

  describe('#type', function() {
    it('returns the correct value', function() {
      const type = keyring.type
      const correct = HdKeyring.type
      assert.equal(type, correct)
    })
  })

  describe('#serialize empty wallets.', function() {
    it('serializes a new mnemonic', function() {
      keyring.serialize()
      .then((output) => {
        assert.equal(output.numberOfAccounts, 0)
        assert.equal(output.mnemonic, null)
      })
    })
  })

  describe('#deserialize a private key', function() {
    it('serializes what it deserializes', function(done) {
      keyring.deserialize({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 1
      })
      .then(() => {
        assert.equal(keyring.wallets.length, 1, 'restores two accounts')
        return keyring.addAccounts(1)
      }).then(() => {
        return keyring.getAccounts()
      }).then((accounts) => {
        assert.equal(accounts[0], firstAcct)
        assert.equal(accounts[1], secondAcct)
        assert.equal(accounts.length, 2)

        return keyring.serialize()
      }).then((serialized) => {
        assert.equal(serialized.mnemonic, sampleMnemonic)
        done()
      })
    })
  })

  describe('#addAccounts', function() {
    describe('with no arguments', function() {
      it('creates a single wallet', function(done) {
        keyring.addAccounts()
        .then(() => {
          assert.equal(keyring.wallets.length, 1)
          done()
        })
      })
    })

    describe('with a numeric argument', function() {
      it('creates that number of wallets', function(done) {
        keyring.addAccounts(3)
        .then(() => {
          assert.equal(keyring.wallets.length, 3)
          done()
        })
      })
    })
  })

  describe('#getAccounts', function() {
    it('calls getAddress on each wallet', function(done) {

      // Push a mock wallet
      const desiredOutput = 'foo'
      keyring.wallets.push({
        getAddress() {
          return {
            toString() {
              return desiredOutput
            }
          }
        }
      })

      const output = keyring.getAccounts()
      .then((output) => {
        assert.equal(output[0], '0x' + desiredOutput)
        assert.equal(output.length, 1)
        done()
      })
    })
  })

  describe('#signPersonalMessage', function () {
    it('returns the expected value', function (done) {
      const address = firstAcct
      const privateKey = new Buffer(privKeyHex, 'hex')
      const message = '0x68656c6c6f20776f726c64'

      keyring.deserialize({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 1,
      })
      .then(() => {
        return keyring.signPersonalMessage(address, message)
      })
      .then((sig) => {
        assert.notEqual(sig, message, 'something changed')

        const restored = sigUtil.recoverPersonalSignature({
          data: message,
          sig,
        })

        assert.equal(restored, sigUtil.normalize(address), 'recovered address')
        done()
      })
      .catch((reason) => {
        console.error('failed because', reason)
      })
    })
  })

  describe('#signTypedData', () => {
    const privKey = Buffer.from(privKeyHex, 'hex')

    const typedData = [
      {
        type: 'string',
        name: 'message',
        value: 'Hi, Alice!'
      }
    ]
    const msgParams = { data: typedData }

    it('can recover a basic signature', async () => {
      await keyring.addAccounts(1)
      const addresses = await keyring.getAccounts()
      const address = addresses[0]
      const sig = await keyring.signTypedData(address, typedData)
      const signedParams = Object.create(msgParams)
      signedParams.sig = sig;
      const restored = sigUtil.recoverTypedSignatureLegacy(signedParams)
      assert.equal(restored, address, 'recovered address')
    })
  })

  describe('#signTypedData_v1', () => {
    const typedData = [
      {
        type: 'string',
        name: 'message',
        value: 'Hi, Alice!'
      }
    ]
    const msgParams = { data: typedData }

    it('signs in a compliant and recoverable way', async () => {
      await keyring.addAccounts(1)
      const addresses = await keyring.getAccounts()
      const address = addresses[0]
      const sig = await keyring.signTypedData_v1(address, typedData)
      const signedParams = Object.create(msgParams)
      signedParams.sig = sig;
      const restored = sigUtil.recoverTypedSignatureLegacy(signedParams)
      assert.equal(restored, address, 'recovered address')
    })
  })

  describe('#signTypedData_v3', () => {
    it('signs in a compliant and recoverable way', async () => {
      const typedData = {
        types: {
          EIP712Domain: []
        },
        domain: {},
        primaryType: 'EIP712Domain',
        message: {}
      }

      await keyring.deserialize({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 1,
      })
      const addresses = await keyring.getAccounts()
      const address = addresses[0]
      const sig = await keyring.signTypedData_v3(address, typedData)
      const restored = sigUtil.recoverTypedSignature({ data: typedData, sig: sig })
      assert.equal(restored, address, 'recovered address')
    })
  })

  describe('#signTypedData_v3 signature verification', () => {
    it('signs in a recoverable way.', async () => {
      const typedData = {"data":{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"wallet","type":"address"}],"Mail":[{"name":"from","type":"Person"},{"name":"to","type":"Person"},{"name":"contents","type":"string"}]},"primaryType":"Mail","domain":{"name":"Ether Mail","version":"1","chainId":1,"verifyingContract":"0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"},"message":{"from":{"name":"Cow","wallet":"0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},"to":{"name":"Bob","wallet":"0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},"contents":"Hello, Bob!"}}}

      await keyring.addAccounts(1)
      const addresses = await keyring.getAccounts()
      const address = addresses[0]
      const sig = await keyring.signTypedData_v3(address, typedData.data)
      const signedData = Object.create(typedData)
      signedData.sig = sig
      const restored = sigUtil.recoverTypedSignature(signedData)
      assert.equal(restored, address, 'recovered address')
    })
  })

  describe('custom hd paths', function () {

    it('can deserialize with an hdPath param and generate the same accounts.', function (done) {
      const hdPathString = `m/44'/60'/0'/0`
      const sampleMnemonic = 'finish oppose decorate face calm tragic certain desk hour urge dinosaur mango'

      keyring.deserialize({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 1,
        hdPath: hdPathString,
      })
      .then(() => {
        return keyring.getAccounts()
      })
      .then((addresses) => {
        assert.equal(addresses[0], firstAcct)
        return keyring.serialize()
      })
      .then((serialized) => {
        assert.equal(serialized.hdPath, hdPathString)
        done()
      })
      .catch((reason) => {
        console.error('failed because', reason)
      })
    })

    it('can deserialize with an hdPath param and generate different accounts.', function (done) {
      const hdPathString = `m/44'/60'/0'/1`
      const sampleMnemonic = 'finish oppose decorate face calm tragic certain desk hour urge dinosaur mango'

      keyring.deserialize({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 1,
        hdPath: hdPathString,
      })
      .then(() => {
        return keyring.getAccounts()
      })
      .then((addresses) => {
        assert.notEqual(addresses[0], firstAcct)
        return keyring.serialize()
      })
      .then((serialized) => {
        assert.equal(serialized.hdPath, hdPathString)
        done()
      })
      .catch((reason) => {
        console.log('failed because', reason)
      })
    })
  })

  /*
  describe('create and restore 1k accounts', function () {
    it('should restore same accounts with no problem', async function () {
      this.timeout(20000)

      for (let i = 0; i < 1e3; i++) {

        keyring = new HdKeyring({
          numberOfAccounts: 1,
        })
        const originalAccounts = await keyring.getAccounts()
        const serialized = await keyring.serialize()
        const mnemonic = serialized.mnemonic

        keyring = new HdKeyring({
          numberOfAccounts: 1,
          mnemonic,
        })
        const restoredAccounts = await keyring.getAccounts()

        const first = originalAccounts[0]
        const restored = restoredAccounts[0]
        const msg = `Should restore same account from mnemonic: "${mnemonic}"`
        assert.equal(restoredAccounts[0], originalAccounts[0], msg)

      }

      return true
    })
  })
  */

  describe('getAppKeyAddress', function () {
    it('should return a public address custom to the provided app key origin', async function () {
      const address = firstAcct

      keyring = new HdKeyring({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 1,
      })
      const appKeyAddress = await keyring.getAppKeyAddress(address, 'someapp.origin.io')

      assert.notEqual(address, appKeyAddress)
      assert(ethUtil.isValidAddress(appKeyAddress))

      const accounts = await keyring.getAccounts()
      assert.equal(accounts[0], firstAcct)
    })

    it('should return different addresses when provided different app key origins', async function () {
      keyring = new HdKeyring({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 1,
      })

      const address = firstAcct

      const appKeyAddress1 = await keyring.getAppKeyAddress(address, 'someapp.origin.io')

      assert(ethUtil.isValidAddress(appKeyAddress1))

      const appKeyAddress2 = await keyring.getAppKeyAddress(address, 'anotherapp.origin.io')

      assert(ethUtil.isValidAddress(appKeyAddress2))

      assert.notEqual(appKeyAddress1, appKeyAddress2)
    })

    it('should return the same address when called multiple times with the same params', async function () {
      keyring = new HdKeyring({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 1,
      })

      const address = firstAcct

      const appKeyAddress1 = await keyring.getAppKeyAddress(address, 'someapp.origin.io')

      assert(ethUtil.isValidAddress(appKeyAddress1))

      const appKeyAddress2 = await keyring.getAppKeyAddress(address, 'someapp.origin.io')

      assert(ethUtil.isValidAddress(appKeyAddress2))

      assert.equal(appKeyAddress1, appKeyAddress2)
    })
  })

  describe('signing methods withAppKeyOrigin option', function () {
    it('should signPersonalMessage with the expected key when passed a withAppKeyOrigin', function (done) {
      const address = firstAcct
      const message = '0x68656c6c6f20776f726c64'

      const privateKeyBuffer = Buffer.from('8e82d2d74c50e5c8460f771d38a560ebe1151a9134c65a7e92b28ad0cfae7151', 'hex')
      const expectedSig = sigUtil.personalSign(privateKeyBuffer, { data: message })

      keyring.deserialize({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 1,
      })
      .then(() => {
        return keyring.signPersonalMessage(address, message, {
          withAppKeyOrigin: 'someapp.origin.io',
        })
      })
      .then((sig) => {
        assert.equal(sig, expectedSig, 'signed with app key')
        done()
      })
      .catch((reason) => {
        assert(!reason, reason.message)
        done()
      })
    })

    it('should signTypedData with the expected key when passed a withAppKeyOrigin', function (done) {
      const address = firstAcct
      const typedData = {
        types: {
          EIP712Domain: []
        },
        domain: {},
        primaryType: 'EIP712Domain',
        message: {}
      }

      const privateKeyBuffer = Buffer.from('8e82d2d74c50e5c8460f771d38a560ebe1151a9134c65a7e92b28ad0cfae7151', 'hex')
      const expectedSig = sigUtil.signTypedData(privateKeyBuffer, { data: typedData })

      keyring.deserialize({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 1
      }).then(() => {
        return keyring.signTypedData_v3(address, typedData, {
          withAppKeyOrigin: 'someapp.origin.io',
        })
      })
      .then((sig) => {
        assert.equal(sig, expectedSig, 'signed with app key')
        done()
      })
      .catch((reason) => {
        assert(!reason, reason.message)
        done()
      })
    })
  })
})
