import { CryptographyKey, SodiumPlus } from "sodium-plus";
import { concat } from "./util";
let sodium;

const VERSION = "v1";
const VERSION_BUF = Buffer.from(VERSION, 'utf-8');

const PREFIX_ENCRYPTION_KEY = new Uint8Array([
    0x53, 0x6f, 0x61, 0x74, 0x6f, 0x6b, 0x01, 0x01
]);
const PREFIX_COMMIT_KEY = new Uint8Array([
    0x53, 0x6f, 0x61, 0x74, 0x6f, 0x6b, 0x01, 0xff
]);

/**
 * Interface for symmetric encryption classes supported by this library.
 */
export interface SymmetricEncryptionInterface {
    encrypt(
        message: string|Buffer,
        key: CryptographyKey,
        assocData?: string
    ): Promise<string>;
    decrypt(
        message: string,
        key: CryptographyKey,
        assocData?: string
    ): Promise<string|Buffer>;
}

/**
 * Default implementation for SymmetricEncryptionInterface.
 */
export class SymmetricCrypto implements SymmetricEncryptionInterface {
    async encrypt(
        message: string|Buffer,
        key: CryptographyKey,
        assocData?: string
    ): Promise<string> {
        return encryptData(message, key, assocData);
    }
    async decrypt(
        message: string,
        key: CryptographyKey,
        assocData?: string
    ): Promise<string|Buffer> {
        return decryptData(message, key, assocData);
    }
}

export type KeyDerivationFunction = (ikm: Uint8Array, salt?: Uint8Array, info?: Uint8Array) => Promise<Uint8Array>;

/**
 * Derive an encryption key and a commitment hash.
 *
 * @param {CryptographyKey} key
 * @param {Uint8Array} nonce
 * @returns {{encKey: CryptographyKey, commitment: Uint8Array}}
 */
export async function deriveKeys(key, nonce) {
    if (!sodium) sodium = await SodiumPlus.auto();

    const encKey = new CryptographyKey(await sodium.crypto_generichash(
        Buffer.from(concat(PREFIX_ENCRYPTION_KEY, nonce)),
        key,
        32
    ));
    const commitment = await sodium.crypto_generichash(
        Buffer.from(concat(PREFIX_COMMIT_KEY, nonce)),
        key,
        32
    );
    return {encKey, commitment};
}

/**
 * Encrypt data using XChaCha20-Poly1305.
 * Provides key commitment.
 *
 * @param {string|Buffer} message
 * @param {Uint8Array} key
 * @param {string|null} assocData
 * @returns {string}
 */
export async function encryptData(
    message: string|Buffer,
    key: CryptographyKey,
    assocData?: string
): Promise<string> {
    // Load libsodium
    if (!sodium) sodium = await SodiumPlus.auto();

    const nonce = await sodium.randombytes_buf(24);
    const aad = JSON.stringify({
        'version': VERSION,
        'nonce': await sodium.sodium_bin2hex(nonce),
        'extra': assocData
    });
    const {encKey, commitment} = await deriveKeys(key, nonce);
    const encrypted = await sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        message,
        nonce,
        encKey,
        aad
    );
    return (
        VERSION +
        await sodium.sodium_bin2hex(nonce) +
        await sodium.sodium_bin2hex(commitment) +
        await sodium.sodium_bin2hex(encrypted)
    );
}

/**
 * Encrypt data using XChaCha20-Poly1305.
 * Asserts key commitment.
 *
 * @param {string} encrypted
 * @param {CryptographyKey} key
 * @param {string|null} assocData
 * @returns {string}
 */
export async function decryptData(
    encrypted: string,
    key: CryptographyKey,
    assocData?: string
): Promise<string|Buffer> {
    // Load libsodium
    if (!sodium) sodium = await SodiumPlus.auto();

    const ver = Buffer.from(encrypted.slice(0, 2), 'utf-8');
    if (!await sodium.sodium_memcmp(ver, VERSION_BUF)) {
        throw new Error("Incorrect version: " + encrypted.slice(0, 2));
    }
    const nonce = await sodium.sodium_hex2bin(encrypted.slice(2, 50));
    const ciphertext = await sodium.sodium_hex2bin(encrypted.slice(114));
    const aad = JSON.stringify({
        'version': encrypted.slice(0, 2),
        'nonce': encrypted.slice(2, 50),
        'extra': assocData
    });
    const storedCommitment = await sodium.sodium_hex2bin(encrypted.slice(50, 114));
    const {encKey, commitment} = await deriveKeys(key, nonce);
    if (!(await sodium.sodium_memcmp(storedCommitment, commitment))) {
        throw new Error("Incorrect commitment value");
    }
    return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        ciphertext,
        nonce,
        encKey,
        aad
    );
}

/**
 * HKDF using BLAKE2b
 *
 * @param ikm
 * @param salt
 * @param info
 */
export async function blakeKdf(
    ikm: Uint8Array,
    salt?: Uint8Array|CryptographyKey,
    info?: Uint8Array
): Promise<Uint8Array> {
    if (!sodium) sodium = await SodiumPlus.auto();
    if (!salt) {
        salt = new CryptographyKey(Buffer.alloc(32));
    } else if (!(salt instanceof CryptographyKey)) {
        salt = new CryptographyKey(Buffer.from(salt));
    }
    if (!info) {
        info = Buffer.from('Soatok Dreamseeker test code');
    }
    const prk: Uint8Array = await sodium.crypto_generichash(
        Buffer.from(ikm),
        salt
    );
    return sodium.crypto_generichash(
        Buffer.from(concat(info, new Uint8Array([0x01]))),
        new CryptographyKey(Buffer.from(prk))
    );
}
