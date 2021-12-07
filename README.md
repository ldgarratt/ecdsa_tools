This is a GO API to do various nefarious things with ECDSA signatures.

For a given elliptic curve, a base point G of prime order n (i.e., nG == O where
O is the identity element), a private key d_A with corresponding public key Q_A
and a message m, an ECDSA signature of m is a pair (r, s) (or (r -s mod n). To
verify the signature:
- Verify that r and s are integers in [1, n-1]
- Calculate e = H(m).
- z = L_n leftmost bits of e
- u_1 = zs^(-1) mod n and u_2 = rs^(-1) mod n
- (x_1, y_1) = u_1G + u_2Q_A. If (x_1, y_1) = O then the signature is invalid
- The signature is valid if r = x_1 mod n and invalid otherwise.


For example:
- To recover the public key from an ECDSA signature (r,s), run:
- Given a repeated nonce, we recover the private key, run:

Further reading:
https://blog.trailofbits.com/2020/06/11/ecdsa-handle-with-care/
