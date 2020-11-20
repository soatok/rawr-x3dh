import { expect } from 'chai';
import 'mocha';
import { CryptographyKey, SodiumPlus } from "sodium-plus";
import { encryptData, decryptData, deriveKeys } from '../lib/symmetric';

let sodium;

describe('Symmetric Encryption Functions', () => {
    it('Key derivation', async() => {
        if (!sodium) sodium = await SodiumPlus.auto();
        const testInput = new CryptographyKey(await sodium.crypto_generichash('Dhole fursonas rule <3'));
        const {encKey, commitment} = await deriveKeys(testInput, Buffer.alloc(24));
        const test1: string = await sodium.sodium_bin2hex(encKey.getBuffer());
        const test2: string = await sodium.sodium_bin2hex(commitment);
        expect(test1).to.not.equal(test2, 'Different outputs were expected');

        // Test vectors for key derivation:
        expect(test1).to.be.equal('3b368faa76856300d81db67f3578ecfa5e00e331b42749bf07da63f11da8f12b');
        expect(test2).to.be.equal('03cf2a39983ae6da8046bc7ee0091827bd2c3c7eda475660b04cbff30bf8a94b');
    });

    it('Encryption / Decryption', async() => {
        if (!sodium) sodium = await SodiumPlus.auto();
        const key = await sodium.crypto_secretbox_keygen();

        const plaintext = "Rawr x3 nuzzles how are you *pounces on you* you're so warm o3o *notices you have a bulge*";
        const encrypted = await encryptData(plaintext, key);
        expect(encrypted).to.not.equal(plaintext);
        expect(encrypted[0]).to.be.equal("v");
        const decrypted = await decryptData(encrypted, key);
        expect(decrypted.toString()).to.be.equal(plaintext);
    });
});
