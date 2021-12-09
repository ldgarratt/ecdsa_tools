package main

import (
    "bytes"
	"crypto/elliptic"
    "crypto/ecdsa"
	"crypto/rand"
    "encoding/hex"
	"fmt"
	"math/big"
    // Golang does not have secp256k1 in crypto/elliptic, so this is a
    // Go wrapper for the bitcoin secp256k1 C library with constant-time curve
    // operations
    "github.com/ethereum/go-ethereum/crypto/secp256k1"
)

// TODO: make more generic than just using secp256k1.
// TODO: Currently assuming the message is the hash already rather than the
// plaintext which is then hashed.

type PublicKey struct {
	Curve elliptic.Curve
	X, Y *big.Int
}

type PrivateKey struct {
	*PublicKey
	D *big.Int
}

func printPointData (pubkey *PublicKey) {
    fmt.Println("Curve : ", pubkey.Curve)
    curveParams := pubkey.Curve.Params()
    fmt.Println("P : ", curveParams.P)
    fmt.Println("N : ", curveParams.N)
    fmt.Println("B : ", curveParams.B)
    fmt.Printf("Gx, Gy : %v, %v\n", curveParams.Gx, curveParams.Gy)
    fmt.Println("BitSize : ", curveParams.BitSize)
}

func GenerateKey() (*PrivateKey, error) {
	curve := secp256k1.S256()

	priv, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("cannot generate key pair: %w", err)
	}

	return &PrivateKey{
		PublicKey: &PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: new(big.Int).SetBytes(priv),
	}, nil
}

func NewPublicKeyFromHex(s string) (*PublicKey, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("cannot decode hex string: %w", err)
	}

	return NewPublicKeyFromBytes(b)
}

func NewPublicKeyFromString(x, y string) (*PublicKey, error) {
	curve := secp256k1.S256()

    x_i, success := new(big.Int).SetString(x, 10)
    if success == false {
        panic("Failed to parse x value.")
    }

    y_i, success := new(big.Int).SetString(y, 10)
    if success == false {
        panic("Failed to parse y value.")
    }

	return &PublicKey{
        Curve: curve,
        X:     x_i,
        Y:     y_i,
    }, nil

}

func NewPublicKeyFromBytes(b []byte) (*PublicKey, error) {
	curve := secp256k1.S256()

	switch b[0] {
	case 0x02, 0x03:
		if len(b) != 33 {
			return nil, fmt.Errorf("cannot parse public key")
		}

		x := new(big.Int).SetBytes(b[1:])
		var ybit uint
		switch b[0] {
		case 0x02:
			ybit = 0
		case 0x03:
			ybit = 1
		}

		if x.Cmp(curve.Params().P) >= 0 {
			return nil, fmt.Errorf("cannot parse public key")
		}

		// y^2 = x^3 + b
		// y   = sqrt(x^3 + b)
		var y, x3b big.Int
		x3b.Mul(x, x)
		x3b.Mul(&x3b, x)
		x3b.Add(&x3b, curve.Params().B)
		x3b.Mod(&x3b, curve.Params().P)
		if z := y.ModSqrt(&x3b, curve.Params().P); z == nil {
			return nil, fmt.Errorf("cannot parse public key")
		}

		if y.Bit(0) != ybit {
			y.Sub(curve.Params().P, &y)
		}
		if y.Bit(0) != ybit {
			return nil, fmt.Errorf("incorrectly encoded X and Y bit")
		}

		return &PublicKey{
			Curve: curve,
			X:     x,
			Y:     &y,
		}, nil
	case 0x04:
		if len(b) != 65 {
			return nil, fmt.Errorf("cannot parse public key")
		}

		x := new(big.Int).SetBytes(b[1:33])
		y := new(big.Int).SetBytes(b[33:])

		if x.Cmp(curve.Params().P) >= 0 || y.Cmp(curve.Params().P) >= 0 {
			return nil, fmt.Errorf("cannot parse public key")
		}

		x3 := new(big.Int).Sqrt(x).Mul(x, x)
		if t := new(big.Int).Sqrt(y).Sub(y, x3.Add(x3, curve.Params().B)); t.IsInt64() && t.Int64() == 0 {
			return nil, fmt.Errorf("cannot parse public key")
		}

		return &PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		}, nil
	default:
		return nil, fmt.Errorf("cannot parse public key")
	}
}

func (k *PublicKey) Bytes(compressed bool) []byte {
	x := k.X.Bytes()
	if len(x) < 32 {
		for i := 0; i < 32-len(x); i++ {
			x = append([]byte{0}, x...)
		}
	}

	if compressed {
		// If odd
		if k.Y.Bit(0) != 0 {
			return bytes.Join([][]byte{{0x03}, x}, nil)
		}

		// If even
		return bytes.Join([][]byte{{0x02}, x}, nil)
	}

	y := k.Y.Bytes()
	if len(y) < 32 {
		for i := 0; i < 32-len(y); i++ {
			y = append([]byte{0}, y...)
		}
	}

	return bytes.Join([][]byte{{0x04}, x, y}, nil)
}

func (k *PublicKey) Hex(compressed bool) string {
	return hex.EncodeToString(k.Bytes(compressed))
}

func newPrivFromHex(s string) (ecdsa.PrivateKey, error) {
	k, err := hex.DecodeString(s)
	if err != nil {
		return ecdsa.PrivateKey{}, err
	}

	x, y := secp256k1.S256().ScalarBaseMult(k)

	return ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: secp256k1.S256(),
			X:     x,
			Y:     y,
		},
		D: new(big.Int).SetBytes(k),
	}, nil
}

// Given message hashes m1 and m2 with signatures (r, s1) and (r, s2), i.e
// repeated r values, this function recovers the private key. Note m1 and m2 are
// the hashes.
func RecoverSecretKeyFromRepeatNonce(r, s1, s2, m1, m2 *big.Int) (*PrivateKey, error) {
	curve := secp256k1.S256()
    curveParams := curve.Params()
    N := curveParams.N

   // Given identical r values, then:
   // s1 - s2 = k^(-1)(m+rD) - (k^-1)(m2 + rD)
   // Thus the nonce k is:
   // k = (m1 - m2)/(s1 - s2)
    s12_inv := big.NewInt(0).Sub(s1, s2)
    s12_inv.ModInverse(s12_inv, N)
    k := big.NewInt(0).Sub(m1, m2)
    k.Mul(k, s12_inv)

    priv, err := RecoverSecretKeyFromKnownNonce(r, s1, m1, k)
    return priv, err
}

// TODO: Later have command line input which just parses the mode and r, s, m,
// k, curve strings and just gives the output.
func RecoverSecretKeyFromKnownNonceStrings(r, s, m, k string) (*PrivateKey, error) {
    r_int, _ := new(big.Int).SetString(r, 10)
    s_int, _ := new(big.Int).SetString(s, 10)
    m_int, _ := new(big.Int).SetString(m, 10)
    k_int, _ := new(big.Int).SetString(k, 10)
    priv, err := RecoverSecretKeyFromKnownNonce(r_int, s_int, m_int, k_int)
    return priv, err
}

// Note here m is a hash, not the plaintext directly.
func RecoverSecretKeyFromKnownNonce(r, s, m, k *big.Int) (*PrivateKey, error) {
	curve := secp256k1.S256()
    curveParams := curve.Params()
    N := curveParams.N

    // Compute (r1_inv * ((k1 * s1) - m1)) % order
    r_inv := big.NewInt(0)
    r_inv.ModInverse(r, N)
    fmt.Println("r_inv: ", r_inv)

    priv := big.NewInt(0).Mul(k, s)
    priv.Sub(priv, m)
    priv.Mul(priv, r_inv)
    priv.Mod(priv, N)

    x, y := curve.ScalarBaseMult(priv.Bytes())

	return &PrivateKey{
		PublicKey: &PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: priv,
	}, nil
}
