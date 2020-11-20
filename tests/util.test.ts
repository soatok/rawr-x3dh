import { expect } from 'chai';
import 'mocha';

import {
    concat,
    generateKeyPair,
    generateBundle,
    preHashPublicKeysForSigning,
    wipe,
    signBundle,
    verifyBundle
} from "../lib/util";
import {Ed25519PublicKey, Ed25519SecretKey, SodiumPlus, X25519PublicKey, X25519SecretKey} from "sodium-plus";

describe('Utilities', () => {
    it('concat', async () => {
        const A = new Uint8Array([0x02, 0x04, 0x08, 0x10]);
        const B = new Uint8Array([0x03, 0x09, 0x1b, 0x51]);
        const C = new Uint8Array([0x02, 0x04, 0x08, 0x10, 0x03, 0x09, 0x1b, 0x51]);
        expect(C.join(',')).to.be.equal(concat(A, B).join(','));
    });

    it('generateKeypair', async() => {
        const kp = await generateKeyPair();
        expect(true).to.be.equal(kp.secretKey instanceof X25519SecretKey);
        expect(true).to.be.equal(kp.publicKey instanceof X25519PublicKey);
    });

    it('generateBundle', async() => {
        const bundle = await generateBundle(5);
        expect(5).to.be.equal(bundle.length);
        for (let i = 0; i < 5; i++) {
            expect(true).to.be.equal(bundle[i].secretKey instanceof X25519SecretKey);
            expect(true).to.be.equal(bundle[i].publicKey instanceof X25519PublicKey);
        }
    });

    it('preHashPublicKeysForSigning', async() => {
        const sodium = await SodiumPlus.auto();
        const bundle = [
            X25519PublicKey.from('c52bb1d803b9721453b99a5d596e74d6d3ba48b1a07303244b0d76172bb55207', 'hex'),
            X25519PublicKey.from('9abdd18b8ad24a6352bcca74bcd4156657d277348291cd8911660cc78836ad70', 'hex'),
            X25519PublicKey.from('6cbeb8b66c686996ec65f59035445d65c2326781c44b9962d5bc8f6425c4e27b', 'hex'),
            X25519PublicKey.from('e8d98550abea5c878a373bf5a06366d043b4c091b9a2e69bfffa69ae561bc877', 'hex'),
            X25519PublicKey.from('19005e50996b96b4a9711a749a04a90fbd6a5781c4dc8d2a27219258354d5362', 'hex'),
        ];
        const prehashed = await sodium.sodium_bin2hex(
            Buffer.from(await preHashPublicKeysForSigning(bundle))
        );
        expect('fa59e2c4aaac08dd4186719ff9c436ca8cb0b1906ff6d230d68129cfba57d1a9').to.be.equal(prehashed);
        const prehash2 = await sodium.sodium_bin2hex(
            Buffer.from(await preHashPublicKeysForSigning(bundle.slice(1)))
        );
        expect('c70d2b33b89971a621ab4c46e13819762f1dba63547f77500087f3107c1c248e').to.be.equal(prehash2);
    });

    it('signBundle / VerifyBundle', async() => {
        const sodium = await SodiumPlus.auto();
        const keypair = await sodium.crypto_sign_keypair();
        const sk: Ed25519SecretKey = await sodium.crypto_sign_secretkey(keypair);
        const pk: Ed25519PublicKey = await sodium.crypto_sign_publickey(keypair);
        const bundle = [
            X25519PublicKey.from('c52bb1d803b9721453b99a5d596e74d6d3ba48b1a07303244b0d76172bb55207', 'hex'),
            X25519PublicKey.from('9abdd18b8ad24a6352bcca74bcd4156657d277348291cd8911660cc78836ad70', 'hex'),
            X25519PublicKey.from('6cbeb8b66c686996ec65f59035445d65c2326781c44b9962d5bc8f6425c4e27b', 'hex'),
            X25519PublicKey.from('e8d98550abea5c878a373bf5a06366d043b4c091b9a2e69bfffa69ae561bc877', 'hex'),
            X25519PublicKey.from('19005e50996b96b4a9711a749a04a90fbd6a5781c4dc8d2a27219258354d5362', 'hex'),
        ];
        const signature = await signBundle(sk, bundle);
        expect(true).to.be.equal(
            await verifyBundle(pk, bundle, signature)
        );
        expect(false).to.be.equal(
            await verifyBundle(pk, bundle.slice(1), signature)
        );
        expect(false).to.be.equal(
            await verifyBundle(pk, bundle.slice().reverse(), signature)
        );
    });

    it('wipe', async () => {
        const sodium = await SodiumPlus.auto();
        const buf = await sodium.crypto_secretbox_keygen();
        expect('0000000000000000000000000000000000000000000000000000000000000000').to.not.equal(
            await sodium.sodium_bin2hex(buf.getBuffer())
        );
        await wipe(buf);
        expect('0000000000000000000000000000000000000000000000000000000000000000').to.be.equal(
            await sodium.sodium_bin2hex(buf.getBuffer())
        );
    });
});
