/**
 * Rawr-X3DH -- eXtended 3-way Diffie-Hellman
 *
 * Specification by Open Whisper Systems <https://signal.org/docs/specifications/x3dh/>
 * Powered by Libsodium <https://libsodium.gitbook.io/doc/>
 *
 * Implemented by Soatok Dreamseeker <https://soatok.blog>
 *
 * ................................:.................
 * .............................-+yd-................
 * ............/+:-.....+/oys++://:m:................
 * --........../y///oyssyyyyhddh+-:y/................
 * --------.....o--+syyso/syyyhho:--+..........:-....
 * ----------.....:/ssss+ooyoosyo//yo.--------oy:....
 * --------------:+//+//++:`-/o-syyy/-------+yo------
 * --------------:oy++:s. ++:+: `ys/------/ss:-------
 * ---------------:+++syh--/++++oss//---:oy+---------
 * ----------------:syyhhysosssyyyyhso/+yo:----------
 * ----------------::shddyyhyyyyshdhyyyy/------------
 * ----------------:shhhyyyssssssoyhhhyhho/::--------
 * ::::::---------:+shhhddd+o+++++yddhhhhhyyyso+::::-
 * ::::::::::::o+oyssyhyhdh+///:+hhoshhhhhhhhyo+:::::
 * ::::::::::::+syyssss/:yyoo+sydo/o+s+/+osyysoo/::::
 * ::::::::::::/+ssyyyyy/:oyyhhhs/ss/y/::::::::::::::
 * :::::::::::::::/+syhhhsyhhhhyyss+oo/::::::::::::::
 * :::::::::/o+/:::::/+syhddddysyso+so/:::::////:::::
 * ::::::+yhhyhhs::::::/yhdddddssso/ss:::::::///:::::
 * :::::::::hhhh+/+/:/shoshyysss/  `+s:::::://::::/::
 * ::::::::+hhhho:+sshhsyhhhs+:.     `-//::::::::::::
 * ::::::::ohhyoo+oyhyyhhhyyssoo/:-`    .:/::::::::::
 * :::::::::syso+syhhhhhhhhhhhhhhyyyo:`   ./:::::::::
 * :::::::::--://+o++osyo+yhhhhhhhhhhyys/`  :::::::::
 * ::::::--.:/+/::::-::::yhhhhhhhhhhhyyy+.  :::::::::
 * :------://:::::----:::/yhyyyyyyyyyys+`   :+:::::::
 * ------::-----------:shyhhyyyyss+/:-...-::+//::::::
 * ------------------/yhhhhhhyyyssso+::::::::::::::::
 * -----------------+yyyhhhhhhhyyssso+/---------:::::
 * ---------------/syyys/yhhhhhhyyyysss+-------------
 * .............:syyyyo---oyhhhhhhhhyyyhs------------
 * ...........-oyyyyyo....-+syyhyyhhhhddy------------
 * ...........syyyyys-......-::::+:////:.------------
 * ...........yyyyys:............-...............----
 * ...........+sss:..................................
 * .....````````.``..................................
 *
 */
import {
    CryptographyKey,
    Ed25519PublicKey,
    Ed25519SecretKey,
    SodiumPlus,
    X25519PublicKey, X25519SecretKey
} from "sodium-plus";
import {
    KeyDerivationFunction,
    blakeKdf,
    SymmetricEncryptionInterface,
    SymmetricCrypto
} from "./lib/symmetric";
import {
    DefaultSessionKeyManager,
    SessionKeyManagerInterface,
    IdentityKeyManagerInterface,
    DefaultIdentityKeyManager
} from "./lib/persistence";
import {
    concat,
    generateKeyPair,
    generateBundle,
    signBundle,
    verifyBundle,
    wipe
} from "./lib/util";

/**
 * Initial server info.
 *
 * Contains the information necessary to complete
 * the X3DH handshake from a sender's side.
 */
export type InitServerInfo = {
    IdentityKey: string,
    SignedPreKey: {
        Signature: string,
        PreKey: string
    },
    OneTimeKey?: string
};

/**
 * Initial information about a sender
 */
export type InitSenderInfo = {
    Sender: string,
    IdentityKey: string,
    EphemeralKey: string,
    OneTimeKey?: string,
    CipherText: string
};

/**
 * Send a network request to the server to obtain the public keys needed
 * to complete the sender's handshake.
 */
export type InitClientFunction = (id: string) => Promise<InitServerInfo>;

/**
 * Signed key bundle.
 */
export type SignedBundle = {signature: string, bundle: string[]};

/**
 * Initialization information for receiving a handshake message.
 */
type RecipientInitWithSK = {
    IK: Ed25519PublicKey,
    EK: X25519PublicKey,
    SK: CryptographyKey,
    OTK?: string
};

/**
 * Pluggable X3DH implementation, powered by libsodium.
 */
export class X3DH {
    encryptor: SymmetricEncryptionInterface;
    kdf: KeyDerivationFunction;
    identityKeyManager: IdentityKeyManagerInterface;
    sessionKeyManager: SessionKeyManagerInterface;
    sodium: SodiumPlus;

    constructor(
        identityKeyManager?: IdentityKeyManagerInterface,
        sessionKeyManager?: SessionKeyManagerInterface,
        encryptor?: SymmetricEncryptionInterface,
        kdf?: KeyDerivationFunction
    ) {
        if (!sessionKeyManager) {
            sessionKeyManager = new DefaultSessionKeyManager();
        }
        if (!identityKeyManager) {
            identityKeyManager = new DefaultIdentityKeyManager();
        }
        if (!encryptor) {
            encryptor = new SymmetricCrypto();
        }
        if (!kdf) {
            kdf = blakeKdf;
        }
        this.encryptor = encryptor;
        this.kdf = kdf;
        this.sessionKeyManager = sessionKeyManager;
        this.identityKeyManager = identityKeyManager;
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

    /**
     * Generates and signs a bundle of one-time keys.
     *
     * Useful for pushing more OTKs to the server.
     *
     * @param {Ed25519SecretKey} signingKey
     * @param {number} numKeys
     */
    async generateOneTimeKeys(
        signingKey: Ed25519SecretKey,
        numKeys: number = 100
    ): Promise<SignedBundle> {
        const sodium = await this.getSodium();
        const bundle = await generateBundle(numKeys);
        const publicKeys = bundle.map(x => x.publicKey);
        const signature = await signBundle(signingKey, publicKeys);
        await this.identityKeyManager.persistOneTimeKeys(bundle);

        // Hex-encode all the public keys
        const encodedBundle : string[] = [];
        for (let pk of publicKeys) {
            encodedBundle.push(await sodium.sodium_bin2hex(pk.getBuffer()));
        }

        return {
            'signature': await sodium.sodium_bin2hex(signature),
            'bundle': encodedBundle
        };
    }

    /**
     * Get the shared key when sending an initial message.
     *
     * @param {InitServerInfo} res
     * @param {Ed25519SecretKey} senderKey
     */
    async initSenderGetSK(
        res: InitServerInfo,
        senderKey: Ed25519SecretKey
    ): Promise<RecipientInitWithSK> {
        const sodium = await this.getSodium();
        const identityKey = new Ed25519PublicKey(
            await sodium.sodium_hex2bin(res.IdentityKey)
        );
        const signedPreKey = new X25519PublicKey(
            await sodium.sodium_hex2bin(res.SignedPreKey.PreKey)
        );
        const signature = await sodium.sodium_hex2bin(res.SignedPreKey.Signature);

        // Check signature
        const valid = await verifyBundle(identityKey, [signedPreKey], signature);
        if (!valid) {
            throw new Error("Invalid signature");
        }
        const ephemeral = await generateKeyPair();
        const ephSecret = ephemeral.secretKey;
        const ephPublic = ephemeral.publicKey;

        // Turn the Ed25519 keys into X25519 keys for X3DH:
        const senderX = await sodium.crypto_sign_ed25519_sk_to_curve25519(senderKey);
        const recipientX = await sodium.crypto_sign_ed25519_pk_to_curve25519(identityKey);

        // See the X3DH specification to really understand this part:
        const DH1 = await sodium.crypto_scalarmult(senderX, signedPreKey);
        const DH2 = await sodium.crypto_scalarmult(ephSecret, recipientX);
        const DH3 = await sodium.crypto_scalarmult(ephSecret, signedPreKey);
        let SK;
        if (res.OneTimeKey) {
            let DH4 = await sodium.crypto_scalarmult(
                ephSecret,
                new X25519PublicKey(await sodium.sodium_hex2bin(res.OneTimeKey))
            );
            SK = new CryptographyKey(
                Buffer.from(await this.kdf(
                    concat(
                        DH1.getBuffer(),
                        DH2.getBuffer(),
                        DH3.getBuffer(),
                        DH4.getBuffer()
                    )
                ))
            );
            await wipe(DH4);
        } else {
            SK = new CryptographyKey(
                Buffer.from(await this.kdf(
                    concat(
                        DH1.getBuffer(),
                        DH2.getBuffer(),
                        DH3.getBuffer()
                    )
                ))
            );
        }

        // Wipe DH keys since we have SK
        await wipe(DH1);
        await wipe(DH2);
        await wipe(DH3);
        await wipe(ephSecret);
        await wipe(senderX);

        return {
            IK: identityKey,
            EK: ephPublic,
            SK: SK,
            OTK: res.OneTimeKey
        };
    }

    /**
     * Initialize for sending.
     *
     * @param {string} recipientIdentity
     * @param {InitClientFunction} getServerResponse
     * @param {string|Buffer} message
     */
    async initSend(
        recipientIdentity: string,
        getServerResponse: InitClientFunction,
        message: string|Buffer
    ): Promise<InitSenderInfo> {
        const sodium = await this.getSodium();

        // Get the identity key for the sender:
        const senderIdentity = await this.identityKeyManager.getMyIdentityString();
        const identity = await this.identityKeyManager.getIdentityKeypair();
        const senderSecretKey = identity.identitySecret;
        const senderPublicKey = identity.identityPublic;

        // Stub out a call to get the server response:
        const response = await getServerResponse(recipientIdentity);

        // Get the shared symmetric key (and other handshake data):
        const {IK, EK, SK, OTK} = await this.initSenderGetSK(response, senderSecretKey);

        // Get the assocData for AEAD:
        const assocData = await sodium.sodium_bin2hex(
            Buffer.concat([senderPublicKey.getBuffer(), IK.getBuffer()])
        );

        // Set the session key (as a sender):
        await this.sessionKeyManager.setSessionKey(recipientIdentity, SK, false);
        await this.sessionKeyManager.setAssocData(recipientIdentity, assocData);
        return {
            "Sender": senderIdentity,
            "IdentityKey": await sodium.sodium_bin2hex(senderPublicKey.getBuffer()),
            "EphemeralKey": await sodium.sodium_bin2hex(EK.getBuffer()),
            "OneTimeKey": OTK,
            "CipherText": await this.encryptor.encrypt(
                message,
                await this.sessionKeyManager.getEncryptionKey(recipientIdentity),
                assocData
            )
        };
    }

    /**
     * Get the shared key when receiving an initial message.
     *
     * @param {InitSenderInfo} req
     * @param {Ed25519SecretKey} identitySecret
     * @param preKeySecret
     */
    async initRecvGetSk(
        req: InitSenderInfo,
        identitySecret: Ed25519SecretKey,
        preKeySecret: X25519SecretKey
    ) {
        const sodium = await this.getSodium();

        // Decode strings
        const senderIdentityKey = new Ed25519PublicKey(
            await sodium.sodium_hex2bin(req.IdentityKey),
        );
        const ephemeral = new X25519PublicKey(
            await sodium.sodium_hex2bin(req.EphemeralKey),
        );

        // Ed25519 -> X25519
        const senderX = await sodium.crypto_sign_ed25519_pk_to_curve25519(senderIdentityKey);
        const recipientX = await sodium.crypto_sign_ed25519_sk_to_curve25519(identitySecret);

        // See the X3DH specification to really understand this part:
        const DH1 = await sodium.crypto_scalarmult(preKeySecret, senderX);
        const DH2 = await sodium.crypto_scalarmult(recipientX, ephemeral);
        const DH3 = await sodium.crypto_scalarmult(preKeySecret, ephemeral);

        let SK;
        if (req.OneTimeKey) {
            let DH4 = await sodium.crypto_scalarmult(
                await this.identityKeyManager.fetchAndWipeOneTimeSecretKey(req.OneTimeKey),
                ephemeral
            );
            SK = new CryptographyKey(
                Buffer.from(await this.kdf(
                    concat(
                        DH1.getBuffer(),
                        DH2.getBuffer(),
                        DH3.getBuffer(),
                        DH4.getBuffer()
                    )
                ))
            );
            await wipe(DH4);
        } else {
            SK = new CryptographyKey(
                Buffer.from(await this.kdf(
                    concat(
                        DH1.getBuffer(),
                        DH2.getBuffer(),
                        DH3.getBuffer()
                    )
                ))
            );
        }
        // Wipe DH keys since we have SK
        await wipe(DH1);
        await wipe(DH2);
        await wipe(DH3);
        await wipe(recipientX);
        return {
            Sender: req.Sender,
            SK: SK,
            IK: senderIdentityKey
        };
    }

    /**
     * Initialize keys for receiving an initial message.
     * Returns the initial plaintext message on success.
     * Throws on failure.
     *
     * @param {InitSenderInfo} req
     * @returns {(string|Buffer)[]}
     */
    async initRecv(req: InitSenderInfo): Promise<(string|Buffer)[]> {
        const sodium = await this.getSodium();
        const {identitySecret, identityPublic} = await this.identityKeyManager.getIdentityKeypair();
        const {preKeySecret} = await this.identityKeyManager.getPreKeypair();
        const {Sender, SK, IK} = await this.initRecvGetSk(
            req,
            identitySecret,
            preKeySecret
        );
        const assocData = await sodium.sodium_bin2hex(
            Buffer.from(concat(IK.getBuffer(), identityPublic.getBuffer()))
        );
        try {
            await this.sessionKeyManager.setSessionKey(Sender, SK, true);
            await this.sessionKeyManager.setAssocData(Sender, assocData);
            return [
                Sender,
                await this.encryptor.decrypt(
                    req.CipherText,
                    await this.sessionKeyManager.getEncryptionKey(Sender, true),
                    assocData
                )
            ];
        } catch (e) {
            // Decryption failure! Destroy the session.
            await this.sessionKeyManager.destroySessionKey(Sender);
            throw e;
        }
    }

    /**
     * Encrypt the next message to send to the recipient.
     *
     * @param {string} recipient
     * @param {string|Buffer} message
     * @returns {string}
     */
    async encryptNext(recipient: string, message: string|Buffer): Promise<string> {
        return this.encryptor.encrypt(
            message,
            await this.sessionKeyManager.getEncryptionKey(recipient, false),
            await this.sessionKeyManager.getAssocData(recipient)
        );
    }

    /**
     * Decrypt the next message received by the sender.
     *
     * @param {string} sender
     * @param {string} encrypted
     * @returns {string|Buffer}
     */
    async decryptNext(sender: string, encrypted: string) {
        return this.encryptor.decrypt(
            encrypted,
            await this.sessionKeyManager.getEncryptionKey(sender, true),
            await this.sessionKeyManager.getAssocData(sender)
        );
    }

    /**
     * Sets the identity string for the current user.
     *
     * @param {string} id
     */
    async setIdentityString(id: string): Promise<void> {
        return this.identityKeyManager.setMyIdentityString(id);
    }
}

/* Let's make sure we export the interfaces/etc. we use. */
export * from "./lib/symmetric";
export * from "./lib/persistence";
export * from "./lib/util";
