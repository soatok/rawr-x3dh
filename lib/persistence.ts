import {
    CryptographyKey,
    Ed25519PublicKey,
    Ed25519SecretKey,
    SodiumPlus,
    X25519PublicKey,
    X25519SecretKey
} from "sodium-plus";
import {Keypair, wipe} from "./util";
import { promises as fsp } from 'fs';
import * as path from 'path';
import * as os from 'os';

export type IdentityKeyPair = {identitySecret: Ed25519SecretKey, identityPublic: Ed25519PublicKey};
export type PreKeyPair = {preKeySecret: X25519SecretKey, preKeyPublic: X25519PublicKey};
type SessionKeys = {sending: CryptographyKey, receiving: CryptographyKey};

export interface IdentityKeyManagerInterface {
    fetchAndWipeOneTimeSecretKey(pk: string):
        Promise<X25519SecretKey>;
    generateIdentityKeypair():
        Promise<IdentityKeyPair>;
    generatePreKeypair():
        Promise<PreKeyPair>;
    getIdentityKeypair():
        Promise<IdentityKeyPair>;
    getMyIdentityString():
        Promise<string>;
    getPreKeypair():
        Promise<PreKeyPair>;
    persistOneTimeKeys(bundle: Keypair[]):
        Promise<void>;
    setIdentityKeypair(identitySecret: Ed25519SecretKey, identityPublic?: Ed25519PublicKey):
        Promise<IdentityKeyManagerInterface>;
    setMyIdentityString(id: string):
        Promise<void>;
}

export interface SessionKeyManagerInterface {
    getAssocData(id: string):
        Promise<string>;
    getEncryptionKey(id: string, recipient?: boolean):
        Promise<CryptographyKey>;
    destroySessionKey(id: string):
        Promise<void>;
    listSessionIds():
        Promise<string[]>;
    setAssocData(id: string, assocData: string):
        Promise<void>;
    setSessionKey(id: string, key: CryptographyKey, recipient?: boolean):
        Promise<void>;
}

/**
 * This is a very basic example class for a session key manager.
 *
 * If you do not specify one, the X3DH library will use this.
 */
export class DefaultSessionKeyManager implements SessionKeyManagerInterface {
    assocData: Map<string, string>;
    sodium: SodiumPlus;
    sessions: Map<string, SessionKeys>;

    constructor(sodium?: SodiumPlus) {
        if (sodium) {
            this.sodium = sodium;
        } else {
            // Just do this up-front.
            this.getSodium().then(() => {});
        }
        this.sessions = new Map<string, SessionKeys>();
        this.assocData = new Map<string, string>();
    }

    /**
     * @returns {SodiumPlus}
     */
    async getSodium(): Promise<SodiumPlus> {
        if (!this.sodium) {
            this.sodium = await SodiumPlus.auto();
        }
        return this.sodium;
    }

    async getAssocData(id: string): Promise<string> {
        return this.assocData[id];
    }

    async listSessionIds(): Promise<string[]> {
        const ids = [];
        for (let i in this.sessions) {
            ids.push(i);
        }
        return ids;
    }

    async setAssocData(id: string, assocData: string): Promise<void> {
        this.assocData[id] = assocData;
    }

    /**
     * Override the session key for a given participation partner.
     *
     * Note that the actual sending/receiving keys will be derived from a BLAKE2b
     * hash with domain separation (sending vs receiving) to ensure that messages
     * sent/received are encrypted under different keys.
     *
     * @param {string} id           Participant ID.
     * @param {CryptographyKey} key Incoming key.
     * @param {boolean} recipient   Are we the recipient? (Default: No.)
     */
    async setSessionKey(id: string, key: CryptographyKey, recipient?: boolean): Promise<void> {
        const sodium = await this.getSodium();
        this.sessions[id] = {};
        if (recipient) {
            this.sessions[id].receiving = new CryptographyKey(
                await sodium.crypto_generichash('sending', key)
            );
            this.sessions[id].sending = new CryptographyKey(
                await sodium.crypto_generichash('receiving', key)
            );
        } else {
            this.sessions[id].receiving = new CryptographyKey(
                await sodium.crypto_generichash('receiving', key)
            );
            this.sessions[id].sending = new CryptographyKey(
                await sodium.crypto_generichash('sending', key)
            );
        }
    }

    /**
     * Get the encryption key for a given message.
     *
     * !!!! IMPORTANT !!!!
     * This is a very rough proof-of-concept that doesn't
     * support out-of-order messages.
     *
     * Instead, it derives a 512-bit hash from the current key, then
     * updates the session key with the leftmost 256 bits of that hash,
     * and returns the rightmost 256 bits as the encryption key.
     *
     * You should design your session key management protocol more
     * appropriately for your use case.
     *
     * @param {string} id
     * @param {boolean} recipient
     * @returns {CryptographyKey}
     */
    async getEncryptionKey(id: string, recipient?: boolean): Promise<CryptographyKey> {
        if (!this.sessions[id]) {
            throw new Error('Key does not exist for client: ' + id);
        }
        if (recipient) {
            const keys = await this.symmetricRatchet(this.sessions[id].receiving);
            this.sessions[id].receiving = keys[0];
            return keys[1];
        } else {
            const keys = await this.symmetricRatchet(this.sessions[id].sending);
            this.sessions[id].sending = keys[0];
            return keys[1];
        }
    }

    /**
     * This is a very basic symmetric ratchet based on
     * BLAKE2b-512.
     *
     * The first 256 bits of the output are stored as the
     * future ratcheting key.
     *
     * The remaining bits are returned as the encryption key.
     *
     * @param {CryptographyKey} inKey
     * @returns {CryptographyKey[]}
     */
    async symmetricRatchet(inKey: CryptographyKey): Promise<CryptographyKey[]> {
        const sodium = await this.getSodium();
        const fullhash = await sodium.crypto_generichash(
            'Symmetric Ratchet',
            inKey,
            64
        );
        return [
            new CryptographyKey(fullhash.slice(0,  32)),
            new CryptographyKey(fullhash.slice(32, 64)),
        ]
    }

    /**
     * Delete the session.
     *
     * @param {string} id
     */
    async destroySessionKey(id: string): Promise<void> {
        if (!this.sessions[id]) {
            return;
        }
        if (this.sessions[id].sending) {
            await wipe(this.sessions[id].sending);
        }
        if (this.sessions[id].receiving) {
            await wipe(this.sessions[id].receiving);
        }
        delete this.sessions[id];
    }
}

/**
 * This is an example implementation of an identity management class.
 *
 * You almost certainly want to build your own.
 */
export class DefaultIdentityKeyManager implements IdentityKeyManagerInterface {
    identitySecret?: Ed25519SecretKey;
    identityPublic?: Ed25519PublicKey;
    myIdentityString?: string;
    preKey?: PreKeyPair;
    oneTimeKeys: Map<string, X25519SecretKey>;
    sodium: SodiumPlus;

    constructor(sodium?: SodiumPlus, sk?: Ed25519SecretKey, pk?: Ed25519PublicKey) {
        if (sodium) {
            this.sodium = sodium;
        } else {
            // Just do this up-front.
            this.getSodium().then(() => {
            });
        }
        if (sk) {
            this.identitySecret = sk;
            if (pk) {
                this.identityPublic = pk;
            }
        }
        this.oneTimeKeys = new Map<string, X25519SecretKey>();
    }

    /**
     * Get the instance of libsodium.
     *
     * @returns {SodiumPlus}
     */
    async getSodium(): Promise<SodiumPlus> {
        if (!this.sodium) {
            this.sodium = await SodiumPlus.auto();
        }
        return this.sodium;
    }

    /**
     * Search the one-time-keys pool for a given X25519 public key.
     * Return the corresponding secret key (and delete it from the pool).
     *
     * @param {string} pk
     * @returns {CryptographyKey}
     */
    async fetchAndWipeOneTimeSecretKey(pk: string): Promise<X25519SecretKey> {
        if (!this.oneTimeKeys[pk]) {
            throw new Error('One-time key not found: ' + pk);
        }
        const sk = new X25519SecretKey(
            Buffer.from(this.oneTimeKeys[pk].secretKey.getBuffer().slice())
        );
        // Wipe one-time keys:
        await wipe(this.oneTimeKeys[pk].secretKey);
        await wipe(this.oneTimeKeys[pk].publicKey);
        delete this.oneTimeKeys[pk];
        return sk;
    }

    /**
     * Generates an identity keypair (Ed25519).
     */
    async generateIdentityKeypair(): Promise<IdentityKeyPair> {
        const sodium = await this.getSodium();
        const keypair = await sodium.crypto_sign_keypair();
        const identitySecret = await sodium.crypto_sign_secretkey(keypair);
        const identityPublic = await sodium.crypto_sign_publickey(keypair);
        return {identitySecret, identityPublic};
    }

    /**
     * Get (and generate, if it doesn't exist) the pre-key keypair.
     *
     * This only returns the X25519 keys. It doesn't include the Ed25519 signature.
     */
    async generatePreKeypair(): Promise<PreKeyPair> {
        const sodium = await this.getSodium();
        const kp = await sodium.crypto_box_keypair();
        return {
            preKeySecret: await sodium.crypto_box_secretkey(kp),
            preKeyPublic: await sodium.crypto_box_publickey(kp)
        };
    }

    /**
     * Get the stored identity keypair (Ed25519).
     *
     * @returns {IdentityKeyPair}
     */
    async getIdentityKeypair(): Promise<IdentityKeyPair> {
        if (!this.identitySecret) {
            const keypair = await this.loadIdentityKeypair();
            await this.setIdentityKeypair(keypair.identitySecret, keypair.identityPublic);
            return keypair;
        }
        return {identitySecret: this.identitySecret, identityPublic: this.identityPublic};
    }

    async getMyIdentityString(): Promise<string> {
        return this.myIdentityString;
    }

    /**
     * Get (and generate, if it doesn't exist) the pre-key keypair.
     *
     * This only returns the X25519 keys. It doesn't include the Ed25519 signature.
     */
    async getPreKeypair(): Promise<PreKeyPair> {
        const sodium = await this.getSodium();
        if (!this.preKey) {
            this.preKey = await this.generatePreKeypair();
        }
        return this.preKey;
    }

    /**
     * Load an Ed25519 keypair from the filesystem.
     *
     * @param {string} filePath
     * @returns {IdentityKeyPair}
     */
    async loadIdentityKeypair(filePath?: string): Promise<IdentityKeyPair> {
        const sodium = await this.getSodium();
        if (!filePath) {
            filePath = path.join(os.homedir(), 'rawr-identity.json')
        }
        await fsp.access(filePath);
        const data: Buffer = await fsp.readFile(filePath);
        const decoded = await JSON.parse(data.toString());
        const sk = new Ed25519SecretKey(
            await sodium.sodium_hex2bin(decoded.sk)
        );
        const pk = new Ed25519PublicKey(
            await sodium.sodium_hex2bin(decoded.pk)
        );
        return {identitySecret: sk, identityPublic: pk};
    }

    /**
     * Store one-time keys in memory.
     *
     * @param {Keypair[]} bundle
     */
    async persistOneTimeKeys(bundle: Keypair[]): Promise<void> {
        const sodium = await this.getSodium();
        for (let kp of bundle) {
            this.oneTimeKeys[await sodium.sodium_bin2hex(kp.publicKey.getBuffer())] = kp;
        }
    }

    /**
     * Save a given identity keypair (Ed25519) to the filesystem.
     *
     * @param {Ed25519SecretKey} identitySecret
     * @param {string|null} filePath
     */
    async saveIdentityKeypair(identitySecret: Ed25519SecretKey, filePath?: string): Promise<void> {
        const sodium = await this.getSodium();
        if (!filePath) {
            filePath = path.join(os.homedir(), 'rawr-identity.json')
        }
        await fsp.writeFile(
            filePath,
            JSON.stringify({
                'sk': await sodium.sodium_bin2hex(identitySecret.getBuffer()),
                'pk': await sodium.sodium_bin2hex(identitySecret.getBuffer().slice(32)),
            })
        );
    }

    /**
     * Sets the identity keys stored in this object.
     *
     * @param {Ed25519SecretKey} identitySecret
     * @param {Ed25519PublicKey} identityPublic
     */
    async setIdentityKeypair(identitySecret: Ed25519SecretKey, identityPublic?: Ed25519PublicKey): Promise<this> {
        if (!identityPublic) {
            identityPublic = new Ed25519PublicKey(
                identitySecret.getBuffer().slice(32)
            );
        }
        this.identitySecret = identitySecret;
        this.identityPublic = identityPublic;
        return this;
    }

    async setMyIdentityString(id: string): Promise<void> {
        this.myIdentityString = id;
    }
}
