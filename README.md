# BIP0340
### _Anton Kovalenko <anton@sw4me.com>_

Implementation of Schnorr signatures according to
[BIP-0340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki):
key generation, signing and verification, using IRONCLAD's secp256k1
primitives.

Not enough functionality for Bitcoin's taproot: no key tweaks etc.

Not enough security for signing: even IRONCLAD itself doesn't promise
absence of side channels, and my layer over IRONCLAD probably makes it
worse.

I'm planning on using the library for nothing more serious than
experimenting with [Nostr](https://github.com/nostr-protocol/)
protocol.

## License

Public Domain
