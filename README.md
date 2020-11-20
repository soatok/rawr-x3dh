# Rawr X3DH

TypeScript implementation of X3DH, as described in
[Going Bark: A Furry's Guide to End-to-End Encryption](https://soatok.blog/2020/11/14/going-bark-a-furrys-guide-to-end-to-end-encryption/).

[![Support me on Patreon](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Fshieldsio-patreon.vercel.app%2Fapi%3Fusername%3Dsoatok%26type%3Dpatrons&style=for-the-badge)](https://patreon.com/soatok)



## What Is This?

This library implements the [Extended Triple Diffie-Hellman](https://signal.org/docs/specifications/x3dh/)
key exchange, with a few minor tweaks:

1. Identity keys are Ed25519 public keys, not X25519 public keys.
   [See this for an explanation](https://soatok.blog/2020/11/14/going-bark-a-furrys-guide-to-end-to-end-encryption/#why-ed25519-keys-x3dh).
2. Encryption/decryption and KDF implementations are pluggable
   (assuming you implement the interface I provide), so you aren't
   married to HKDF or a particular cipher. (Although I recommend hard-coding
   it to your application!)

## Usage

First, you'll want to import the X3DH class from our module.

```typescript
import { X3DH } from 'rawr-x3dh';

const x3dh = new X3DH();
```

Note: You can pass some classes to the constructor to replace my algorithm implementations
for your own.

```typescript
import { X3DH } from 'rawr-x3dh';

const x3dh = new X3DH(
    sessionKeyManager,
    identityKeyManager,
    symmetricEncryptionHandler,
    keyDerivationFunction
);
```

Once your X3DH object's instantiated, you will be able to initialize handshakes
either as a sender or as a recipient. Then you will be able to encrypt additional
messages on either side, and the encryption key shall ratchet forward.

```typescript
const firstEncrypted = await x3dh.initSend(
    'recipient@server2',
    serverApiCallFunc,
    firstMessage
); 
```

The `serverApiCallFunc` parameter should be a function that sends a request to the server
to obtain the identity key, signed pre-key, and optional one-time key for the handshake.

See the definition of the `InitClientFunction` type in `lib/index.ts`.

Once this has completed, you can call `encryptNext()` multiple times to append messages
to send.

```typescript
const nextEncrypted = await x3dh.encryptNext(
    'recipient@server2',
    'This is a follow-up message UwU'
);
```

On the other side, your communication partner will use the following feature.

```typescript
const firstMessage = await x3dh.initRecv(senderInfo);
const nextMessage = await x3dh.decryptNext('sender@server1', nextEncrypted);
```

