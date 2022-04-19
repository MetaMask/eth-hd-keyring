const {
  normalize,
  personalSign,
  recoverPersonalSignature,
  recoverTypedSignature,
  signTypedData,
  SignTypedDataVersion,
} = require('@metamask/eth-sig-util');
const ethUtil = require('ethereumjs-util');
const HdKeyring = require('..');

// Sample account:
const privKeyHex =
  'b8a9c05beeedb25df85f8d641538cbffedf67216048de9c678ee26260eb91952';

const sampleMnemonic =
  'finish oppose decorate face calm tragic certain desk hour urge dinosaur mango';
const firstAcct = '0x1c96099350f13d558464ec79b9be4445aa0ef579';
const secondAcct = '0x1b00aed43a693f3a957f9feb5cc08afa031e37a0';

describe('hd-keyring', () => {
  let keyring;
  beforeEach(() => {
    keyring = new HdKeyring();
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

    it('constructs with a typeof array mnemonic', async () => {
      keyring = new HdKeyring({
        mnemonic: Array.from(Buffer.from(sampleMnemonic, 'utf8').values()),
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
    it('serializes mnemonic stored as a buffer in a class variable into a buffer array and does not add accounts', async () => {
      keyring.generateRandomMnemonic();
      const output = await keyring.serialize();
      expect(output.numberOfAccounts).toBe(0);
      expect(Array.isArray(output.mnemonic)).toBe(true);
    });

    it('serializes mnemonic stored as a string in a class variable into a buffer array and does not add accounts', async () => {
      keyring.mnemonic = sampleMnemonic;
      const output = await keyring.serialize();
      expect(output.numberOfAccounts).toBe(0);
      expect(Array.isArray(output.mnemonic)).toBe(true);
    });
  });

  describe('#deserialize a private key', () => {
    it('serializes what it deserializes', async () => {
      await keyring.deserialize({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 1,
      });
      expect(keyring.wallets).toHaveLength(1);
      await keyring.addAccounts(1);
      const accounts = await keyring.getAccounts();
      expect(accounts[0]).toStrictEqual(firstAcct);
      expect(accounts[1]).toStrictEqual(secondAcct);
      expect(accounts).toHaveLength(2);
      const serialized = await keyring.serialize();
      expect(Buffer.from(serialized.mnemonic).toString()).toStrictEqual(
        sampleMnemonic,
      );
    });
  });

  describe('#addAccounts', () => {
    describe('with no arguments', () => {
      it('creates a single wallet', async () => {
        keyring.generateRandomMnemonic();
        await keyring.addAccounts();
        expect(keyring.wallets).toHaveLength(1);
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
        expect(keyring.wallets).toHaveLength(3);
      });
    });
  });

  describe('#getAccounts', () => {
    it('calls getAddress on each wallet', async () => {
      // Push a mock wallet
      const desiredOutput = 'foo';
      keyring.wallets.push({
        getAddress() {
          return {
            toString() {
              return desiredOutput;
            },
          };
        },
      });

      const output = await keyring.getAccounts();
      expect(output[0]).toBe(`0x${desiredOutput}`);
      expect(output).toHaveLength(1);
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
      expect(restored).toStrictEqual(address);
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
      const signature = await keyring.signTypedData_v1(address, typedData);
      const restored = recoverTypedSignature({
        data: typedData,
        signature,
        version: SignTypedDataVersion.V1,
      });
      expect(restored).toStrictEqual(address);
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
      const signature = await keyring.signTypedData_v3(address, typedData);
      const restored = recoverTypedSignature({
        data: typedData,
        signature,
        version: SignTypedDataVersion.V3,
      });
      expect(restored).toStrictEqual(address);
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
      const signature = await keyring.signTypedData_v3(address, typedData);
      const restored = recoverTypedSignature({
        data: typedData,
        signature,
        version: SignTypedDataVersion.V3,
      });
      expect(restored).toStrictEqual(address);
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
      expect(ethUtil.isValidAddress(appKeyAddress)).toBe(true);

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

      expect(ethUtil.isValidAddress(appKeyAddress1)).toBe(true);

      const appKeyAddress2 = await keyring.getAppKeyAddress(
        address,
        'anotherapp.origin.io',
      );

      expect(ethUtil.isValidAddress(appKeyAddress2)).toBe(true);

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

      expect(ethUtil.isValidAddress(appKeyAddress1)).toBe(true);

      const appKeyAddress2 = await keyring.getAppKeyAddress(
        address,
        'someapp.origin.io',
      );

      expect(ethUtil.isValidAddress(appKeyAddress2)).toBe(true);

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

      const sig = await keyring.signTypedData_v3(address, typedData, {
        withAppKeyOrigin: 'someapp.origin.io',
      });
      expect(sig).toStrictEqual(expectedSig);
    });
  });
});
