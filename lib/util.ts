import {
    CryptographyKey,
    Ed25519PublicKey,
    Ed25519SecretKey,
    SodiumPlus,
    X25519PublicKey,
    X25519SecretKey
} from "sodium-plus";

let sodium;
export type Keypair = {secretKey: X25519SecretKey, publicKey: X25519PublicKey};

/**
 * Concatenate some number of Uint8Array objects
 *
 * @param {Uint8Array[]} args
 * @returns {Uint8Array}
 */
export function concat(...args: Uint8Array[]): Uint8Array {
    let length = 0;
    for (let arg of args) {
        length += arg.length;
    }
    const output = new Uint8Array(length);
    length = 0;
    for (let arg of args) {
        output.set(arg, length);
        length += arg.length;
    }
    return output;
}

/**
 * Generate a keypair.
 *
 * @returns {Keypair}
 */
export async function generateKeyPair(): Promise<Keypair> {
    if (!sodium) sodium = await SodiumPlus.auto();
    const kp = await sodium.crypto_box_keypair();
    return {
        secretKey: await sodium.crypto_box_secretkey(kp),
        publicKey: await sodium.crypto_box_publickey(kp)
    };
}

/**
 * Generate a bundle of keypairs.
 *
 * @param {number} preKeyCount
 * @returns {Keypair[]}
 */
export async function generateBundle(preKeyCount: number = 100): Promise<Keypair[]> {
    const bundle: Keypair[] = [];
    for (let i = 0; i < preKeyCount; i++) {
        bundle.push(await generateKeyPair());
    }
        
    return bundle;
}

/**
 * BLAKE2b( len(PK) | PK_0, PK_1, ... PK_n )
 *
 * @param {X25519PublicKey[]} publicKeys
 * @returns {Uint8Array}
 */
export async function preHashPublicKeysForSigning(publicKeys): Promise<Uint8Array> {
    if (!sodium) sodium = await SodiumPlus.auto();
    const hashState = await sodium.crypto_generichash_init();
    // First, update the state with the number of public keys
    const pkLen = Buffer.from([
        (publicKeys.length >>> 24) & 0xff,
        (publicKeys.length >>> 16) & 0xff,
        (publicKeys.length >>> 8) & 0xff,
        publicKeys.length & 0xff
    ]);
    await sodium.crypto_generichash_update(hashState, pkLen);
    // Next, update the state with each public key
    for (let pk of publicKeys) {
        await sodium.crypto_generichash_update(
            hashState,
            pk.getBuffer()
        );
    }
    // Return the finalized BLAKE2b hash
    return await sodium.crypto_generichash_final(hashState);
}

/**
 * Signs a bundle. Returns the signature.
 *
 * @param {Ed25519SecretKey} signingKey
 * @param {X25519PublicKey[]} publicKeys
 * @returns {Uint8Array}
 */
export async function signBundle(
    signingKey: Ed25519SecretKey,
    publicKeys: X25519PublicKey[]
) {
    if (!sodium) sodium = await SodiumPlus.auto();
    return sodium.crypto_sign_detached(
        Buffer.from(await preHashPublicKeysForSigning(publicKeys)),
        signingKey
    );
}

/**
 * This is just so you can see how verification looks.
 *
 * @param {Ed25519PublicKey} verificationKey
 * @param {X25519PublicKey[]} publicKeys
 * @param {Buffer} signature
 */
export async function verifyBundle(
    verificationKey: Ed25519PublicKey,
    publicKeys: X25519PublicKey[],
    signature: Buffer
): Promise<boolean> {
    if (!sodium) sodium = await SodiumPlus.auto();
    return sodium.crypto_sign_verify_detached(
        Buffer.from(await preHashPublicKeysForSigning(publicKeys)),
        verificationKey,
        signature
    );
}

/**
 * Wipe a cryptography key's internal buffer.
 *
 * @param {CryptographyKey} key
 */
export async function wipe(key: CryptographyKey): Promise<void> {
    if (!sodium) sodium = await SodiumPlus.auto();
    await sodium.sodium_memzero(key.getBuffer());
}