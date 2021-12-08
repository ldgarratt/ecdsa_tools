< not finished yet >

This is a GO API to do various nefarious things with ECDSA signatures.

For a given elliptic curve, a base point G of prime order n (i.e., nG == O where
O is the identity element), a private key d_A with corresponding public key Q_A
and a message m, an ECDSA signature of m is a pair (r, s) (or (r -s mod n).

ECDSA is weak in various ways and this code is about how to exploit these
weaknesses.

For example:
- If the nonce k used in creating the signature (r, s) of (hashed) message m,
 one can recover the private key with recoverSecretKeyFromKnownNonce(r, s, m, k)
- To recover the public key from an ECDSA signature (r,s), run: <TODO>
- Given a repeated nonce, we recover the private key, run: <TODO>

TODO: add more functionality, add clearer APIs in the README.

Further reading:
https://blog.trailofbits.com/2020/06/11/ecdsa-handle-with-care/
