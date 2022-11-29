const {
  normalize,
  personalSign,
  recoverPersonalSignature,
  recoverTypedSignature,
  signTypedData,
  SignTypedDataVersion,
} = require('@metamask/eth-sig-util');
const { wordlist } = require('@metamask/scure-bip39/dist/wordlists/english');
const oldMMForkBIP39 = require('@metamask/bip39');
const {
  isValidAddress,
  toChecksumAddress,
  bufferToHex,
  toBuffer,
  ecrecover,
  pubToAddress,
} = require('@ethereumjs/util');
const OldHdKeyring = require('@metamask/eth-hd-keyring');
const { keccak256 } = require('ethereum-cryptography/keccak');
const HdKeyring = require('..');

// Sample account:
const privKeyHex =
  'b8a9c05beeedb25df85f8d641538cbffedf67216048de9c678ee26260eb91952';

const sampleMnemonic =
  'finish oppose decorate face calm tragic certain desk hour urge dinosaur mango';
const firstAcct = '0x1c96099350f13D558464eC79B9bE4445AA0eF579';
const secondAcct = '0x1b00AeD43a693F3a957F9FeB5cC08AFA031E37a0';

const notKeyringAddress = '0xbD20F6F5F1616947a39E11926E78ec94817B3931';

describe('hd-keyring', () => {
  let keyring;
  beforeEach(() => {
    keyring = new HdKeyring();
  });

  describe('compare old bip39 implementation with new', () => {
    it('should derive the same accounts from the same mnemonics', async () => {
      const mnemonics = [];
      for (let i = 0; i < 99; i++) {
        mnemonics.push(oldMMForkBIP39.generateMnemonic());
      }

      await Promise.all(
        mnemonics.map(async (mnemonic) => {
          const newHDKeyring = new HdKeyring({ mnemonic, numberOfAccounts: 3 });
          const oldHDKeyring = new OldHdKeyring({
            mnemonic,
            numberOfAccounts: 3,
          });
          const newAccounts = await newHDKeyring.getAccounts();
          const oldAccounts = await oldHDKeyring.getAccounts();
          await expect(newAccounts[0]).toStrictEqual(
            toChecksumAddress(oldAccounts[0]),
          );

          await expect(newAccounts[1]).toStrictEqual(
            toChecksumAddress(oldAccounts[1]),
          );

          await expect(newAccounts[2]).toStrictEqual(
            toChecksumAddress(oldAccounts[2]),
          );
        }),
      );
    });
  });

  describe('constructor', () => {
    it('constructs with a typeof string mnemonic', async () => {
      keyring = new HdKeyring({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 2,
      });

      const accounts = await keyring.getAccounts();
      expect(accounts[0]).toStrictEqual(firstAcct);
      expect(accounts[1]).toStrictEqual(secondAcct);
    });

    it('constructs with a typeof buffer mnemonic', async () => {
      keyring = new HdKeyring({
        mnemonic: Buffer.from(sampleMnemonic, 'utf8'),
        numberOfAccounts: 2,
      });

      const accounts = await keyring.getAccounts();
      expect(accounts[0]).toStrictEqual(firstAcct);
      expect(accounts[1]).toStrictEqual(secondAcct);
    });

    it('constructs with a typeof Uint8Array mnemonic', async () => {
      const indices = sampleMnemonic
        .split(' ')
        .map((word) => wordlist.indexOf(word));
      const uInt8ArrayOfMnemonic = new Uint8Array(
        new Uint16Array(indices).buffer,
      );
      keyring = new HdKeyring({
        mnemonic: uInt8ArrayOfMnemonic,
        numberOfAccounts: 2,
      });

      const accounts = await keyring.getAccounts();
      expect(accounts[0]).toStrictEqual(firstAcct);
      expect(accounts[1]).toStrictEqual(secondAcct);
    });

    it('throws on invalid mnemonic', () => {
      expect(
        () =>
          new HdKeyring({
            mnemonic: 'abc xyz',
            numberOfAccounts: 2,
          }),
      ).toThrow('Eth-Hd-Keyring: Invalid secret recovery phrase provided');
    });

    it('throws when numberOfAccounts is passed with no mnemonic', () => {
      expect(
        () =>
          new HdKeyring({
            numberOfAccounts: 2,
          }),
      ).toThrow(
        'Eth-Hd-Keyring: Deserialize method cannot be called with an opts value for numberOfAccounts and no menmonic',
      );
    });
  });

  describe('re-initialization protection', () => {
    const alreadyProvidedError =
      'Eth-Hd-Keyring: Secret recovery phrase already provided';
    it('double generateRandomMnemonic', () => {
      keyring.generateRandomMnemonic();
      expect(() => {
        keyring.generateRandomMnemonic();
      }).toThrow(alreadyProvidedError);
    });

    it('constructor + generateRandomMnemonic', () => {
      keyring = new HdKeyring({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 2,
      });

      expect(() => {
        keyring.generateRandomMnemonic();
      }).toThrow(alreadyProvidedError);
    });

    it('constructor + deserialize', () => {
      keyring = new HdKeyring({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 2,
      });

      expect(() => {
        keyring.deserialize({
          mnemonic: sampleMnemonic,
          numberOfAccounts: 1,
        });
      }).toThrow(alreadyProvidedError);
    });
  });

  describe('Keyring.type', () => {
    it('is a class property that returns the type string.', () => {
      const { type } = HdKeyring;
      expect(typeof type).toBe('string');
    });
  });

  describe('#type', () => {
    it('returns the correct value', () => {
      const { type } = keyring;
      const correct = HdKeyring.type;
      expect(type).toStrictEqual(correct);
    });
  });

  describe('#serialize mnemonic.', () => {
    it('serializes mnemonic stored as a buffer to a Uint8Array', async () => {
      keyring.mnemonic = oldMMForkBIP39.generateMnemonic();
      const mnemonicAsUint8Array = keyring.stringToUint8Array(
        keyring.mnemonic.toString(),
      );
      const output = await keyring.serialize();
      expect(output.numberOfAccounts).toBe(0);
      expect(output.mnemonic).toStrictEqual(mnemonicAsUint8Array);
    });

    it('serializes keyring data with mnemonic stored as a Uint8Array', async () => {
      keyring.generateRandomMnemonic();
      const { mnemonic } = keyring;
      const hdpath = keyring.hdPath;
      keyring.addAccounts(1);
      const output = await keyring.serialize();
      expect(output.numberOfAccounts).toBe(1);
      expect(output.hdPath).toStrictEqual(hdpath);
      expect(output.mnemonic).toStrictEqual(mnemonic);
    });

    it('serializes mnemonic stored as a string', async () => {
      keyring.mnemonic = sampleMnemonic;
      const output = await keyring.serialize();
      expect(output.numberOfAccounts).toBe(0);
      expect(output.mnemonic).toStrictEqual(
        keyring.stringToUint8Array(sampleMnemonic),
      );
    });
  });

  describe('#deserialize a private key', () => {
    it('serializes what it deserializes', async () => {
      await keyring.deserialize({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 1,
      });
      const accountsFirstCheck = await keyring.getAccounts();

      expect(accountsFirstCheck).toHaveLength(1);
      await keyring.addAccounts(1);
      const accountsSecondCheck = await keyring.getAccounts();
      expect(accountsSecondCheck[0]).toStrictEqual(firstAcct);
      expect(accountsSecondCheck[1]).toStrictEqual(secondAcct);
      expect(accountsSecondCheck).toHaveLength(2);
      const serialized = await keyring.serialize();
      expect(keyring.uint8ArrayToString(serialized.mnemonic)).toStrictEqual(
        sampleMnemonic,
      );
    });
  });

  describe('#addAccounts', () => {
    describe('with no arguments', () => {
      it('creates a single wallet', async () => {
        keyring.generateRandomMnemonic();
        await keyring.addAccounts();
        const accounts = await keyring.getAccounts();
        expect(accounts).toHaveLength(1);
      });

      it('throws an error when no SRP has been generated yet', async () => {
        expect(() => keyring.addAccounts()).toThrow(
          'Eth-Hd-Keyring: No secret recovery phrase provided',
        );
      });
    });

    describe('with a numeric argument', () => {
      it('creates that number of wallets', async () => {
        keyring.generateRandomMnemonic();
        await keyring.addAccounts(3);
        const accounts = await keyring.getAccounts();
        expect(accounts).toHaveLength(3);
      });
    });
  });

  describe('#signPersonalMessage', () => {
    it('returns the expected value', async () => {
      const address = firstAcct;
      const message = '0x68656c6c6f20776f726c64';

      await keyring.deserialize({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 1,
      });
      const signature = await keyring.signPersonalMessage(address, message);
      expect(signature).not.toBe(message);

      const restored = recoverPersonalSignature({
        data: message,
        signature,
      });

      expect(restored).toStrictEqual(normalize(address));
    });
  });

  describe('#signTypedData', () => {
    it('can recover a basic signature', async () => {
      Buffer.from(privKeyHex, 'hex');

      const typedData = [
        {
          type: 'string',
          name: 'message',
          value: 'Hi, Alice!',
        },
      ];
      keyring.generateRandomMnemonic();
      await keyring.addAccounts(1);
      const addresses = await keyring.getAccounts();
      const address = addresses[0];
      const signature = await keyring.signTypedData(address, typedData);
      const restored = recoverTypedSignature({
        data: typedData,
        signature,
        version: SignTypedDataVersion.V1,
      });
      expect(toChecksumAddress(restored)).toStrictEqual(address);
    });
  });

  describe('#signTypedData_v1', () => {
    const typedData = [
      {
        type: 'string',
        name: 'message',
        value: 'Hi, Alice!',
      },
    ];

    it('signs in a compliant and recoverable way', async () => {
      keyring.generateRandomMnemonic();
      await keyring.addAccounts(1);
      const addresses = await keyring.getAccounts();
      const address = addresses[0];
      const signature = await keyring.signTypedData(address, typedData, {
        version: SignTypedDataVersion.V1,
      });
      const restored = recoverTypedSignature({
        data: typedData,
        signature,
        version: SignTypedDataVersion.V1,
      });
      expect(toChecksumAddress(restored)).toStrictEqual(address);
    });
  });

  describe('#signTypedData_v3', () => {
    it('signs in a compliant and recoverable way', async () => {
      const typedData = {
        types: {
          EIP712Domain: [],
        },
        domain: {},
        primaryType: 'EIP712Domain',
        message: {},
      };

      await keyring.deserialize({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 1,
      });
      const addresses = await keyring.getAccounts();
      const address = addresses[0];
      const signature = await keyring.signTypedData(address, typedData, {
        version: SignTypedDataVersion.V3,
      });
      const restored = recoverTypedSignature({
        data: typedData,
        signature,
        version: SignTypedDataVersion.V3,
      });
      expect(toChecksumAddress(restored)).toStrictEqual(address);
    });
  });

  describe('#signTypedData_v3 signature verification', () => {
    it('signs in a recoverable way.', async () => {
      const typedData = {
        types: {
          EIP712Domain: [
            { name: 'name', type: 'string' },
            { name: 'version', type: 'string' },
            { name: 'chainId', type: 'uint256' },
            { name: 'verifyingContract', type: 'address' },
          ],
          Person: [
            { name: 'name', type: 'string' },
            { name: 'wallet', type: 'address' },
          ],
          Mail: [
            { name: 'from', type: 'Person' },
            { name: 'to', type: 'Person' },
            { name: 'contents', type: 'string' },
          ],
        },
        primaryType: 'Mail',
        domain: {
          name: 'Ether Mail',
          version: '1',
          chainId: 1,
          verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
        },
        message: {
          from: {
            name: 'Cow',
            wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
          },
          to: {
            name: 'Bob',
            wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
          },
          contents: 'Hello, Bob!',
        },
      };

      keyring.generateRandomMnemonic();
      await keyring.addAccounts(1);
      const addresses = await keyring.getAccounts();
      const address = addresses[0];
      const signature = await keyring.signTypedData(address, typedData, {
        version: SignTypedDataVersion.V3,
      });
      const restored = recoverTypedSignature({
        data: typedData,
        signature,
        version: SignTypedDataVersion.V3,
      });
      expect(toChecksumAddress(restored)).toStrictEqual(address);
    });
  });

  describe('custom hd paths', () => {
    it('can deserialize with an hdPath param and generate the same accounts.', async () => {
      const hdPathString = `m/44'/60'/0'/0`;
      keyring.deserialize({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 1,
        hdPath: hdPathString,
      });
      const addresses = await keyring.getAccounts();
      expect(addresses[0]).toStrictEqual(firstAcct);
      const serialized = await keyring.serialize();
      expect(serialized.hdPath).toStrictEqual(hdPathString);
    });

    it('can deserialize with an hdPath param and generate different accounts.', async () => {
      const hdPathString = `m/44'/60'/0'/1`;

      keyring.deserialize({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 1,
        hdPath: hdPathString,
      });
      const addresses = await keyring.getAccounts();
      expect(addresses[0]).not.toBe(firstAcct);
      const serialized = await keyring.serialize();
      expect(serialized.hdPath).toStrictEqual(hdPathString);
    });
  });

  // eslint-disable-next-line
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

  describe('getAppKeyAddress', () => {
    it('should return a public address custom to the provided app key origin', async () => {
      const address = firstAcct;

      keyring = new HdKeyring({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 1,
      });
      const appKeyAddress = await keyring.getAppKeyAddress(
        address,
        'someapp.origin.io',
      );

      expect(address).not.toBe(appKeyAddress);
      expect(isValidAddress(appKeyAddress)).toBe(true);

      const accounts = await keyring.getAccounts();
      expect(accounts[0]).toStrictEqual(firstAcct);
    });

    it('should return different addresses when provided different app key origins', async () => {
      keyring = new HdKeyring({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 1,
      });

      const address = firstAcct;

      const appKeyAddress1 = await keyring.getAppKeyAddress(
        address,
        'someapp.origin.io',
      );

      expect(isValidAddress(appKeyAddress1)).toBe(true);

      const appKeyAddress2 = await keyring.getAppKeyAddress(
        address,
        'anotherapp.origin.io',
      );

      expect(isValidAddress(appKeyAddress2)).toBe(true);

      expect(appKeyAddress1).not.toBe(appKeyAddress2);
    });

    it('should return the same address when called multiple times with the same params', async () => {
      keyring = new HdKeyring({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 1,
      });

      const address = firstAcct;

      const appKeyAddress1 = await keyring.getAppKeyAddress(
        address,
        'someapp.origin.io',
      );

      expect(isValidAddress(appKeyAddress1)).toBe(true);

      const appKeyAddress2 = await keyring.getAppKeyAddress(
        address,
        'someapp.origin.io',
      );

      expect(isValidAddress(appKeyAddress2)).toBe(true);

      expect(appKeyAddress1).toStrictEqual(appKeyAddress2);
    });
  });

  describe('signing methods withAppKeyOrigin option', () => {
    it('should signPersonalMessage with the expected key when passed a withAppKeyOrigin', async () => {
      const address = firstAcct;
      const message = '0x68656c6c6f20776f726c64';

      const privateKey = Buffer.from(
        '8e82d2d74c50e5c8460f771d38a560ebe1151a9134c65a7e92b28ad0cfae7151',
        'hex',
      );
      const expectedSig = personalSign({ privateKey, data: message });

      await keyring.deserialize({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 1,
      });
      const sig = await keyring.signPersonalMessage(address, message, {
        withAppKeyOrigin: 'someapp.origin.io',
      });

      expect(sig).toStrictEqual(expectedSig);
    });

    it('should signTypedData with the expected key when passed a withAppKeyOrigin', async () => {
      const address = firstAcct;
      const typedData = {
        types: {
          EIP712Domain: [],
        },
        domain: {},
        primaryType: 'EIP712Domain',
        message: {},
      };

      const privateKey = Buffer.from(
        '8e82d2d74c50e5c8460f771d38a560ebe1151a9134c65a7e92b28ad0cfae7151',
        'hex',
      );
      const expectedSig = signTypedData({
        privateKey,
        data: typedData,
        version: SignTypedDataVersion.V3,
      });

      await keyring.deserialize({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 1,
      });

      const sig = await keyring.signTypedData(address, typedData, {
        withAppKeyOrigin: 'someapp.origin.io',
        version: SignTypedDataVersion.V3,
      });
      expect(sig).toStrictEqual(expectedSig);
    });
  });

  // /
  /* TESTS FOR BASE-KEYRING METHODS */
  // /

  describe('#signMessage', function () {
    const message =
      '0x879a053d4800c6354e76c7985a865d2922c82fb5b3f4577b2fe08b998954f2e0';
    const expectedResult =
      '0xb21867b2221db0172e970b7370825b71c57823ff8714168ce9748f32f450e2c43d0fe396eb5b5f59284b7fd108c8cf61a6180a6756bdd3d4b7b9ccc4ac6d51611b';

    it('passes the dennis test', async function () {
      await keyring.deserialize({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 1,
      });
      const result = await keyring.signMessage(firstAcct, message);
      expect(result).toBe(expectedResult);
    });

    it('reliably can decode messages it signs', async function () {
      await keyring.deserialize({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 1,
      });
      const localMessage = 'hello there!';
      const msgHashHex = bufferToHex(keccak256(Buffer.from(localMessage)));
      await keyring.addAccounts(9);
      const addresses = await keyring.getAccounts();
      const signatures = await Promise.all(
        addresses.map(async (accountAddress) => {
          return await keyring.signMessage(accountAddress, msgHashHex);
        }),
      );
      signatures.forEach((sgn, index) => {
        const accountAddress = addresses[index];

        const r = toBuffer(sgn.slice(0, 66));
        const s = toBuffer(`0x${sgn.slice(66, 130)}`);
        const v = BigInt(`0x${sgn.slice(130, 132)}`);
        const m = toBuffer(msgHashHex);
        const pub = ecrecover(m, v, r, s);
        const adr = `0x${pubToAddress(pub).toString('hex')}`;

        expect(toChecksumAddress(adr)).toBe(accountAddress);
      });
    });

    it('throw error for invalid message', async function () {
      await keyring.deserialize({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 1,
      });

      await expect(keyring.signMessage(firstAcct, '')).rejects.toThrow(
        'Cannot convert 0x to a BigInt',
      );
    });

    it('throw error if empty address is passed', async function () {
      await keyring.deserialize({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 1,
      });

      await expect(keyring.signMessage('', message)).rejects.toThrow(
        'Must specify address.',
      );
    });

    it('throw error if address not associated with the current keyring is passed', async function () {
      await keyring.deserialize({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 1,
      });

      await expect(
        keyring.signMessage(notKeyringAddress, message),
      ).rejects.toThrow('HD Keyring - Unable to find matching address.');
    });
  });
});
