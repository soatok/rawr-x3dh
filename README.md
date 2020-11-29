# ![Rawr X3DH](RawrX3DH-Github.png)

TypeScript implementation of X3DH, as described in
***[Going Bark: A Furry's Guide to End-to-End Encryption](https://soatok.blog/2020/11/14/going-bark-a-furrys-guide-to-end-to-end-encryption/)***.

[![Support me on Patreon](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Fshieldsio-patreon.vercel.app%2Fapi%3Fusername%3Dsoatok%26type%3Dpatrons&style=for-the-badge)](https://patreon.com/soatok)

[![Travis CI](https://travis-ci.org/soatok/rawr-x3dh.svg?branch=master)](https://travis-ci.org/soatok/rawr-x3dh)
[![npm version](https://img.shields.io/npm/v/rawr-x3dh.svg)](https://npm.im/rawr-x3dh)

## [OwO](https://soatok.files.wordpress.com/2020/09/soatoktelegrams2020-06.png) What's This?

This library implements the [Extended Triple Diffie-Hellman](https://signal.org/docs/specifications/x3dh/)
key exchange, with a few minor tweaks:

1. Identity keys are Ed25519 public keys, not X25519 public keys.
   [See this for an explanation](https://soatok.blog/2020/11/14/going-bark-a-furrys-guide-to-end-to-end-encryption/#why-ed25519-keys-x3dh).
2. Encryption/decryption and KDF implementations are pluggable
   (assuming you implement the interface I provide), so you aren't
   married to HKDF or a particular cipher. (Although I recommend hard-coding
   it to your application!)

## Installation

First, you'll want to install this library via your package manager.

```terminal
npm install rawr-x3dh
```

If you're working server-side, you'll also want to install [sodium-native](https://www.npmjs.com/package/sodium-native),
so that [sodium-plus](https://www.npmjs.com/package/sodium-plus) will run faster.

If you're working in a browser or browser extension, don't install sodium-native.

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
    sessionKeyManager, /* SessionKeyManagerInterface */
    identityKeyManager, /* IdentityKeyManagerInterface */
    symmetricEncryptionHandler, /* SymmetricEncryptionInterface */
    keyDerivationFunction /* KeyDerivationFunction */
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
const [sender, firstMessage] = await x3dh.initRecv(senderInfo);
const nextMessage = await x3dh.decryptNext(sender, nextEncrypted);
```

Note: `initRecv()` will always return the sender identity (a string) and the
message (a `Buffer` that can be converted to a string). The sender identity
should be usable for `decryptNext()` calls.

However, that doesn't mean it's trustworthy! This library only implements
the X3DH pattern. It doesn't implement the 
[Gossamer integration](https://soatok.blog/2020/11/14/going-bark-a-furrys-guide-to-end-to-end-encryption/#identity-key-management).

## Should I Use This?

Don't use it in production until version 1.0.0 has been tagged.
The API can break at any moment until that happens (especially if
I decide I hate the default key management classes I wrote).

However, feel free to test and play with it.

## Questions and Answers

### Any Interest in Porting This to $LANG?

I'd love to port this to more languages! That will also allow me to write end-to-end integration tests.

As long as there's a good [libsodium implementation](https://libsodium.gitbook.io/doc/bindings_for_other_languages),
it should be doable.

However, I don't have *nearly* as much free time as I'd like, so I can't commit to
building or supporting multiple implementations right now.

Conversely, if you've ported this to another language, let me know and I'll maintain
a list here:

* (Currently, none.)

### Why "Rawr"?

The canonical abbreviation for the eXtended 3-way Diffie Hellman
deniable authenticated key exchange is X3DH.

There is a [cursed furry copypasta/meme](https://knowyourmeme.com/memes/notices-bulge-owo-whats-this) 
that begins with "rawr x3". The juxtaposition of "x3" and "X3DH" is too perfect
an opportunity for dumb jokes to pass up.

### Is this a furry thing?

[![You betcha!](https://soatok.files.wordpress.com/2020/08/soatoktelegrams2020-03.png)](https://soatok.blog/2020/11/14/going-bark-a-furrys-guide-to-end-to-end-encryption/)

And remember: It's not *furry trash*, it's *yiff-raff*.

#### Why? Just, Why?

I've written a lot of words to answer this line of questioning already on [my blog](https://soatok.blog).

You will probably find the answer you're seeking [here](https://soatok.blog/2020/07/09/a-word-on-anti-furry-sentiments-in-the-tech-community/)
or [here](https://soatok.blog/2020/10/23/solving-for-why-furry-blogging-about-cryptography/).

![Comic by loviesophiee](https://soatok.files.wordpress.com/2020/07/increase-the-thing.png)

#### This is Unprofessional

Folks often say there's an XKCD for Everything! And thus:

[![XKCD](https://imgs.xkcd.com/comics/dreams.png)](https://xkcd.com/137/)

#### Who Made That Awesome Project Logo?

[Sophie](https://twitter.com/loviesophiee) made it.
