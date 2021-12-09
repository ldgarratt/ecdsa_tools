This is a Go API to do various nefarious things with ECDSA signatures.

For a given elliptic curve, a base point G of prime order n (i.e., nG == O where
O is the identity element), a private key d_A with corresponding public key Q_A
and a message m, an ECDSA signature of m is a pair (r, s) (or (r -s mod n).

ECDSA is weak in various ways and this code is about how to exploit these
weaknesses.

For example:
- If the nonce k used in creating the signature (r, s) of (hashed) message m is
  leaked, one can recover the private key with
  RecoverSecretKeyFromKnownNonce(r, s, m, k)
- Given a repeated nonce, we recover the private key, one can recover it with
  RecoverSecretKeyFromRepeatNonce(r, s1, s2, m1, m2)

The main.go file here gives an example of usage.

There are all sorts of attacks of Elliptic curve cryptography so this work is
far from complete.

Further reading:
https://blog.trailofbits.com/2020/06/11/ecdsa-handle-with-care/
