import {
  normalize,
  personalSign,
  recoverPersonalSignature,
  recoverTypedSignature,
  signTypedData,
  SignTypedDataVersion,
  encrypt,
  EthEncryptedData,
} from '@metamask/eth-sig-util';
import { wordlist } from '@metamask/scure-bip39/dist/wordlists/english';
import { generateMnemonic as oldMMForkBIP39GenerateMnemonic } from '@metamask/bip39';
import {
  isValidAddress,
  bufferToHex,
  toBuffer,
  ecrecover,
  pubToAddress,
} from '@ethereumjs/util';
import { TransactionFactory, Transaction as EthereumTx } from '@ethereumjs/tx';
import { keccak256 } from 'ethereum-cryptography/keccak';
import { Eip1024EncryptedData, Hex, add0x, assert } from '@metamask/utils';

// we do not want to add this to dependency
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore - TS7016: Could not find a declaration file for module
// eslint-disable-next-line node/no-unpublished-import
import OldHDKeyring from '@metamask/eth-hd-keyring';
import { HDKeyring } from './HDKeyring';

// Sample account:
const privKeyHex =
  'b8a9c05beeedb25df85f8d641538cbffedf67216048de9c678ee26260eb91952';

const sampleMnemonic =
  'finish oppose decorate face calm tragic certain desk hour urge dinosaur mango';
const firstAcct = '0x1c96099350f13d558464ec79b9be4445aa0ef579';
const secondAcct = '0x1b00aed43a693f3a957f9feb5cc08afa031e37a0';

const notKeyringAddress = '0xbD20F6F5F1616947a39E11926E78ec94817B3931';

describe('hd-keyring', () => {
  describe('compare old bip39 implementation with new', () => {
    it('should derive the same accounts from the same mnemonics', async () => {
      const mnemonics: Buffer[] = [];
      for (let i = 0; i < 99; i++) {
        mnemonics.push(oldMMForkBIP39GenerateMnemonic());
      }

      await Promise.all(
        mnemonics.map(async (mnemonic) => {
          const newHDKeyring = new HDKeyring({ mnemonic, numberOfAccounts: 3 });
          const oldHDKeyring = new OldHDKeyring({
            mnemonic,
            numberOfAccounts: 3,
          });
          const newAccounts = await newHDKeyring.getAccounts();
          const oldAccounts = await oldHDKeyring.getAccounts();
          expect(newAccounts[0]).toStrictEqual(oldAccounts[0]);
          expect(newAccounts[1]).toStrictEqual(oldAccounts[1]);
          expect(newAccounts[2]).toStrictEqual(oldAccounts[2]);
        }),
      );
    });
  });

  describe('constructor', () => {
    it('constructs with a typeof string mnemonic', async () => {
      const keyring = new HDKeyring({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 2,
      });

      const accounts = await keyring.getAccounts();
      expect(accounts[0]).toStrictEqual(firstAcct);
      expect(accounts[1]).toStrictEqual(secondAcct);
    });

    it('constructs with a typeof buffer mnemonic', async () => {
      const keyring = new HDKeyring({
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
      const keyring = new HDKeyring({
        mnemonic: uInt8ArrayOfMnemonic,
        numberOfAccounts: 2,
      });

      const accounts = await keyring.getAccounts();
      expect(accounts[0]).toStrictEqual(firstAcct);
      expect(accounts[1]).toStrictEqual(secondAcct);
    });

    it('constructs with jscasted buffer', async () => {
      const jscastedBuffer = Buffer.from(sampleMnemonic).toJSON();
      const keyring = new HDKeyring({
        mnemonic: jscastedBuffer,
        numberOfAccounts: 2,
      });

      const accounts = await keyring.getAccounts();
      expect(accounts[0]).toStrictEqual(firstAcct);
      expect(accounts[1]).toStrictEqual(secondAcct);
    });

    it('throws on invalid mnemonic', () => {
      expect(
        () =>
          new HDKeyring({
            mnemonic: 'abc xyz',
            numberOfAccounts: 2,
          }),
      ).toThrow('Eth-Hd-Keyring: Invalid secret recovery phrase provided');
    });

    it('throws when numberOfAccounts is passed with no mnemonic', async () => {
      expect(() => {
        // eslint-disable-next-line no-new
        new HDKeyring({
          numberOfAccounts: 1,
        });
      }).toThrow(
        'Eth-Hd-Keyring: Deserialize method cannot be called with an opts value for numberOfAccounts and no menmonic',
      );
    });
  });

  describe('re-initialization protection', () => {
    const alreadyProvidedError =
      'Eth-Hd-Keyring: Secret recovery phrase already provided';
    it('double generateRandomMnemonic', () => {
      const keyring = new HDKeyring();
      keyring.generateRandomMnemonic();
      expect(() => {
        keyring.generateRandomMnemonic();
      }).toThrow(alreadyProvidedError);
    });

    it('constructor + generateRandomMnemonic', () => {
      const keyring = new HDKeyring({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 2,
      });

      expect(() => {
        keyring.generateRandomMnemonic();
      }).toThrow(alreadyProvidedError);
    });

    it('constructor + deserialize', () => {
      const keyring = new HDKeyring({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 2,
      });

      expect(() => {
        // eslint-disable-next-line @typescript-eslint/no-floating-promises
        keyring.deserialize({
          mnemonic: sampleMnemonic,
          numberOfAccounts: 1,
        });
      }).toThrow(alreadyProvidedError);
    });
  });

  describe('Keyring.type', () => {
    it('is a class property that returns the type string.', () => {
      const { type } = HDKeyring;
      expect(typeof type).toBe('string');
    });
  });

  describe('#type', () => {
    it('returns the correct value', () => {
      const keyring = new HDKeyring();

      const { type } = keyring;
      const correct = HDKeyring.type;
      expect(type).toStrictEqual(correct);
    });
  });

  describe('#serialize mnemonic.', () => {
    it('serializes the mnemonic in the same format as previous version (an array of utf8 encoded bytes)', async () => {
      const keyring = new HDKeyring({
        mnemonic: sampleMnemonic,
      });
      // uses previous version of eth-hd-keyring to ensure backwards compatibility
      const oldHDKeyring = new OldHDKeyring({ mnemonic: sampleMnemonic });
      const { mnemonic: oldKeyringSerializedMnemonic } =
        await oldHDKeyring.serialize();

      const output = await keyring.serialize();
      expect(output.mnemonic).toStrictEqual(oldKeyringSerializedMnemonic);
    });

    it('serializes mnemonic passed in as a string to an array of utf8 encoded bytes', async () => {
      const keyring = new HDKeyring({
        mnemonic: sampleMnemonic,
      });
      const output = await keyring.serialize();
      // this Buffer.from(...).toString() is the method of converting from an array of utf8 encoded bytes back to a string
      const mnemonicAsString = Buffer.from(output.mnemonic).toString();
      expect(mnemonicAsString).toStrictEqual(sampleMnemonic);
    });

    it('serializes mnemonic passed in as a an array of utf8 encoded bytes in the same format', async () => {
      const uint8Array = new TextEncoder().encode(sampleMnemonic);
      const mnemonicAsArrayOfUtf8EncodedBytes = Array.from(uint8Array);
      const keyring = new HDKeyring({
        mnemonic: mnemonicAsArrayOfUtf8EncodedBytes,
      });

      const output = await keyring.serialize();
      // this Buffer.from(...).toString() is the method of converting from an array of utf8 encoded bytes back to a string
      const mnemonicAsString = Buffer.from(output.mnemonic).toString();
      expect(mnemonicAsString).toStrictEqual(sampleMnemonic);
    });

    it('throws if mnemnoic is not set', async () => {
      const keyring = new HDKeyring({});
      await expect(keyring.serialize()).rejects.toThrow(
        'Eth-Hd-Keyring: Missing mnemonic when serializing',
      );
    });
  });

  describe('#deserialize a private key', () => {
    it('serializes what it deserializes', async () => {
      const keyring = new HDKeyring();
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
      expect(Buffer.from(serialized.mnemonic).toString()).toStrictEqual(
        sampleMnemonic,
      );
    });
  });

  describe('#addAccounts', () => {
    describe('with no arguments', () => {
      it('creates a single wallet', async () => {
        const keyring = new HDKeyring();
        keyring.generateRandomMnemonic();
        await keyring.addAccounts();
        const accounts = await keyring.getAccounts();
        expect(accounts).toHaveLength(1);
      });

      it('throws an error when no SRP has been generated yet', async () => {
        const keyring = new HDKeyring();
        await expect(keyring.addAccounts()).rejects.toThrow(
          'Eth-Hd-Keyring: No secret recovery phrase provided',
        );
      });
    });

    describe('with a numeric argument', () => {
      it('creates that number of wallets', async () => {
        const keyring = new HDKeyring();
        keyring.generateRandomMnemonic();
        await keyring.addAccounts(3);
        const accounts = await keyring.getAccounts();
        expect(accounts).toHaveLength(3);
      });
    });
  });

  describe('#signPersonalMessage', () => {
    it('returns the expected value', async () => {
      const keyring = new HDKeyring();

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
      const keyring = new HDKeyring();
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
      const [rawAddress] = await keyring.getAccounts();
      assert(rawAddress, 'addresses is empty');
      const address = add0x(rawAddress);
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
      const keyring = new HDKeyring();
      keyring.generateRandomMnemonic();
      await keyring.addAccounts(1);
      const [rawAddress] = await keyring.getAccounts();
      assert(rawAddress, 'addresses is empty');
      const address = add0x(rawAddress);
      const signature = await keyring.signTypedData(address, typedData, {
        version: SignTypedDataVersion.V1,
      });
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
      const keyring = new HDKeyring();
      const typedData = {
        types: {
          EIP712Domain: [],
        },
        domain: {},
        primaryType: 'EIP712Domain' as const,
        message: {},
      };

      await keyring.deserialize({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 1,
      });
      const [rawAddress] = await keyring.getAccounts();
      assert(rawAddress, 'addresses is empty');
      const address = add0x(rawAddress);
      const signature = await keyring.signTypedData(address, typedData, {
        version: SignTypedDataVersion.V3,
      });
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
      const keyring = new HDKeyring();
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
        primaryType: 'Mail' as const,
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
      const [rawAddress] = await keyring.getAccounts();
      assert(rawAddress, 'addresses is empty');
      const address = add0x(rawAddress);
      const signature = await keyring.signTypedData(address, typedData, {
        version: SignTypedDataVersion.V3,
      });
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
      const keyring = new HDKeyring();
      const hdPathString = `m/44'/60'/0'/0`;
      await keyring.deserialize({
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
      const keyring = new HDKeyring();
      const hdPathString = `m/44'/60'/0'/1`;
      await keyring.deserialize({
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

        const keyring = new HDKeyring({
          numberOfAccounts: 1,
        })
        const originalAccounts = await keyring.getAccounts()
        const serialized = await keyring.serialize()
        const mnemonic = serialized.mnemonic

        const keyring = new HDKeyring({
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

  describe('signing methods withAppKeyOrigin option', () => {
    it('should signPersonalMessage with the expected key when passed a withAppKeyOrigin', async () => {
      const keyring = new HDKeyring();
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
      const keyring = new HDKeyring();
      const address = firstAcct;
      const typedData = {
        types: {
          EIP712Domain: [],
        },
        domain: {},
        primaryType: 'EIP712Domain' as const,
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
      const keyring = new HDKeyring();
      await keyring.deserialize({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 1,
      });
      const result = await keyring.signMessage(firstAcct, message);
      expect(result).toBe(expectedResult);
    });

    it('reliably can decode messages it signs', async function () {
      const keyring = new HDKeyring();
      await keyring.deserialize({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 1,
      });
      const localMessage = 'hello there!';
      const msgHashHex = bufferToHex(
        Buffer.from(keccak256(Buffer.from(localMessage))),
      );
      await keyring.addAccounts(9);
      const addresses = await keyring.getAccounts();
      const signatures = await Promise.all(
        addresses.map(async (accountAddress: Hex) => {
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

        expect(adr).toBe(accountAddress);
      });
    });

    it('throw error for invalid message', async function () {
      const keyring = new HDKeyring();
      await keyring.deserialize({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 1,
      });

      await expect(keyring.signMessage(firstAcct, '')).rejects.toThrow(
        'Cannot convert 0x to a BigInt',
      );
    });

    it('throw error if empty address is passed', async function () {
      const keyring = new HDKeyring();
      await keyring.deserialize({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 1,
      });

      // @ts-expect-error we inputting an invalid address
      await expect(keyring.signMessage('', message)).rejects.toThrow(
        'Must specify address.',
      );
    });

    it('throw error if address not associated with the current keyring is passed', async function () {
      const keyring = new HDKeyring();
      await keyring.deserialize({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 1,
      });

      await expect(
        keyring.signMessage(notKeyringAddress, message),
      ).rejects.toThrow('Eth-Hd-Keyring: Unable to find matching address.');
    });
  });

  describe('#removeAccount', function () {
    let keyring: HDKeyring;
    beforeEach(() => {
      keyring = new HDKeyring({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 1,
      });
    });

    describe('if the account exists', function () {
      it('should remove that account', async function () {
        const rawAddresses = await keyring.getAccounts();
        const [rawAddress] = rawAddresses;
        expect(rawAddresses).toHaveLength(1);
        assert(rawAddress, 'rawAddress should be empty');
        const address = add0x(rawAddress);
        keyring.removeAccount(address);
        const addressesAfterRemoval = await keyring.getAccounts();
        expect(addressesAfterRemoval).toHaveLength(0);
      });
    });

    describe('if the account does not exist', function () {
      it('should throw an error', function () {
        const unexistingAccount = '0x0000000000000000000000000000000000000000';
        expect(() => keyring.removeAccount(unexistingAccount)).toThrow(
          `Address ${unexistingAccount} not found in this keyring`,
        );
      });
    });
  });

  describe('getAppKeyAddress', function () {
    let keyring: HDKeyring;
    beforeEach(() => {
      keyring = new HDKeyring({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 1,
      });
    });

    it('should return a public address custom to the provided app key origin', async function () {
      const appKeyAddress = await keyring.getAppKeyAddress(
        firstAcct,
        'someapp.origin.io',
      );

      expect(firstAcct).not.toBe(appKeyAddress);
      expect(isValidAddress(appKeyAddress)).toBe(true);
    });

    it('should return different addresses when provided different app key origins', async function () {
      const appKeyAddress1 = await keyring.getAppKeyAddress(
        firstAcct,
        'someapp.origin.io',
      );

      expect(isValidAddress(appKeyAddress1)).toBe(true);

      const appKeyAddress2 = await keyring.getAppKeyAddress(
        firstAcct,
        'anotherapp.origin.io',
      );

      expect(isValidAddress(appKeyAddress2)).toBe(true);
      expect(appKeyAddress1).not.toBe(appKeyAddress2);
    });

    it('should return the same address when called multiple times with the same params', async function () {
      const appKeyAddress1 = await keyring.getAppKeyAddress(
        firstAcct,
        'someapp.origin.io',
      );

      expect(isValidAddress(appKeyAddress1)).toBe(true);

      const appKeyAddress2 = await keyring.getAppKeyAddress(
        firstAcct,
        'someapp.origin.io',
      );

      expect(isValidAddress(appKeyAddress2)).toBe(true);
      expect(appKeyAddress1).toBe(appKeyAddress2);
    });

    it('should throw error if the provided origin is not a string', async function () {
      // @ts-expect-error we are providing an incorrect origin key
      await expect(keyring.getAppKeyAddress(firstAcct, [])).rejects.toThrow(
        `'origin' must be a non-empty string`,
      );
    });

    it('should throw error if the provided origin is an empty string', async function () {
      await expect(keyring.getAppKeyAddress(firstAcct, '')).rejects.toThrow(
        `'origin' must be a non-empty string`,
      );
    });
  });

  describe('exportAccount', function () {
    let keyring: HDKeyring;
    beforeEach(() => {
      keyring = new HDKeyring({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 1,
      });
    });

    it('should return a hex-encoded private key', async function () {
      const expectedPrivateKeyResult =
        '0xd3cc16948a02a91b9fcf83735653bf3dfd82c86543fdd1e9a828bd25e8a7b68d';
      const privKeyHexValue = await keyring.exportAccount(firstAcct);

      expect(expectedPrivateKeyResult).toBe(`0x${privKeyHexValue}`);
    });

    it('throw error if account is not present', async function () {
      await expect(keyring.exportAccount(notKeyringAddress)).rejects.toThrow(
        'Eth-Hd-Keyring: Unable to find matching address.',
      );
    });
  });

  describe('#encryptionPublicKey', function () {
    const publicKey = 'LV7lWhd0mUDcvxkMU2o6uKXftu25zq4bMYdmMqppXic=';
    let keyring: HDKeyring;
    beforeEach(() => {
      keyring = new HDKeyring({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 1,
      });
    });

    it('returns the expected value', async function () {
      const encryptionPublicKey = await keyring.getEncryptionPublicKey(
        firstAcct,
      );
      expect(publicKey).toBe(encryptionPublicKey);
    });

    it('throw error if address is blank', async function () {
      // @ts-expect-error provide an invalid key
      await expect(keyring.getEncryptionPublicKey('')).rejects.toThrow(
        'Must specify address.',
      );
    });

    it('throw error if address is not present in the keyring', async function () {
      await expect(
        keyring.getEncryptionPublicKey(notKeyringAddress),
      ).rejects.toThrow('Eth-Hd-Keyring: Unable to find matching address.');
    });
  });

  describe('#signTypedData V4 signature verification', function () {
    let keyring: HDKeyring;
    beforeEach(() => {
      keyring = new HDKeyring({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 1,
      });
    });

    const expectedSignature =
      '0x220917664ef676d592bd709a5bffedaf69c5f6c72f13c6c4547a41d211f0923c3180893b1dec023433f11b664fabda22b74b57d21094f7798fc85b7650f8edbb1b';

    it('returns the expected value', async function () {
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
            { name: 'wallets', type: 'address[]' },
          ],
          Mail: [
            { name: 'from', type: 'Person' },
            { name: 'to', type: 'Person[]' },
            { name: 'contents', type: 'string' },
          ],
          Group: [
            { name: 'name', type: 'string' },
            { name: 'members', type: 'Person[]' },
          ],
        },
        domain: {
          name: 'Ether Mail',
          version: '1',
          chainId: 1,
          verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
        },
        primaryType: 'Mail' as const,
        message: {
          from: {
            name: 'Cow',
            wallets: [
              '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
              '0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF',
            ],
          },
          to: [
            {
              name: 'Bob',
              wallets: [
                '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
                '0xB0BdaBea57B0BDABeA57b0bdABEA57b0BDabEa57',
                '0xB0B0b0b0b0b0B000000000000000000000000000',
              ],
            },
          ],
          contents: 'Hello, Bob!',
        },
      };

      const addresses = await keyring.getAccounts();
      const [address] = addresses;

      const signature = await keyring.signTypedData(address as Hex, typedData, {
        version: SignTypedDataVersion.V4,
      });
      expect(signature).toBe(expectedSignature);
      const restored = recoverTypedSignature({
        data: typedData,
        signature,
        version: SignTypedDataVersion.V4,
      });
      expect(restored).toBe(address);
    });
  });

  describe('#decryptMessage', function () {
    const message = 'Hello world!';
    let encryptedMessage: EthEncryptedData, keyring: HDKeyring;

    beforeEach(async () => {
      keyring = new HDKeyring({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 1,
      });

      const encryptionPublicKey = await keyring.getEncryptionPublicKey(
        firstAcct,
      );
      encryptedMessage = encrypt({
        publicKey: encryptionPublicKey,
        data: message,
        version: 'x25519-xsalsa20-poly1305',
      });
    });

    it('returns the expected value', async function () {
      const decryptedMessage = await keyring.decryptMessage(
        firstAcct,
        encryptedMessage,
      );
      expect(message).toBe(decryptedMessage);
    });

    it('throw error if address passed is not present in the keyring', async function () {
      await expect(
        keyring.decryptMessage(notKeyringAddress, encryptedMessage),
      ).rejects.toThrow('Eth-Hd-Keyring: Unable to find matching address.');
    });

    it('throw error if wrong encrypted data object is passed', async function () {
      await expect(
        keyring.decryptMessage(firstAcct, {} as Eip1024EncryptedData),
      ).rejects.toThrow('Encryption type/version not supported.');
    });
  });

  describe('#signTransaction', function () {
    let keyring: HDKeyring;
    beforeEach(() => {
      keyring = new HDKeyring({
        mnemonic: sampleMnemonic,
        numberOfAccounts: 1,
      });
    });

    const txParams = {
      from: firstAcct,
      nonce: '0x00',
      gasPrice: '0x09184e72a000',
      gasLimit: '0x2710',
      to: firstAcct,
      value: '0x1000',
    };

    it('returns a signed legacy tx object', async function () {
      const tx = new EthereumTx(txParams);
      expect(tx.isSigned()).toBe(false);

      const signed = await keyring.signTransaction(firstAcct, tx);
      const signedTx = TransactionFactory.fromTxData(signed);
      expect(signedTx.isSigned()).toBe(true);
    });

    it('returns a signed tx object', async function () {
      const tx = TransactionFactory.fromTxData(txParams);
      expect(tx.isSigned()).toBe(false);

      const signed = await keyring.signTransaction(firstAcct, tx);
      const signedTx = TransactionFactory.fromTxData(signed);
      expect(signedTx.isSigned()).toBe(true);
    });

    it('returns rejected promise if empty address is passed', async function () {
      const tx = TransactionFactory.fromTxData(txParams);
      // @ts-expect-error provide invalid address
      await expect(keyring.signTransaction('', tx)).rejects.toThrow(
        'Must specify address.',
      );
    });

    it('throw error if wrong address is passed', async function () {
      const tx = TransactionFactory.fromTxData(txParams);
      await expect(
        keyring.signTransaction(notKeyringAddress, tx),
      ).rejects.toThrow('Eth-Hd-Keyring: Unable to find matching address.');
    });
  });
});
