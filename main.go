package main

import (
	"fmt"
	"math/big"
    "crypto/ecdsa"
    "crypto/rand"
)

// This is an example main function to e.g., recover private key from known
// nonce. Substitute with function calls from ecdsa.go as you wish.
// Run with: go run .
func main() {
    r, _ := new(big.Int).SetString("e34dc9682d84351326636b4286d5a9afe66a8e84763aa3ae00898b571c5df328", 16)
    s, _ := new(big.Int).SetString("6d49dfab0ae451bee756751ce92dbad2e9b57204fc1d9d724a841cc4c101005d", 16)
    m, _ := new(big.Int).SetString("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", 16)
    k, _ := new(big.Int).SetString("216c9dce67d3a7b60ad5117dd599e3f6", 16)

    result, _ := RecoverSecretKeyFromKnownNonce(r, s, m, k)

    fmt.Println("Private key:\n", result.D)
    fmt.Println("Public key data:")
    printPointData(result.PublicKey)

    fmt.Println()
    fmt.Println()
    a, b, c, d := recoverPublicKeysFromSignature(r, s, m)
    printPointData(a)
    fmt.Println()
    printPointData(b)
    fmt.Println()
    printPointData(c)
    fmt.Println()
    printPointData(d)

    fmt.Println()
    fmt.Println()
    fmt.Println()
    mm := m.Bytes()
    ecdsa_a := ecdsa.PublicKey{a.Curve, a.X, a.Y}
    fmt.Println(ecdsa_a)
    pub := ecdsa.PublicKey{result.PublicKey.Curve, result.PublicKey.X, result.PublicKey.Y}
    pub_mine := PublicKey{result.PublicKey.Curve, result.PublicKey.X, result.PublicKey.Y}
    printPointData(&pub_mine)
    fmt.Println("hello")
    res2 := ecdsa.Verify(&ecdsa_a, mm, r, s)
    fmt.Println(res2)

    result2 := ecdsa.PrivateKey{pub, result.D}
    q, z, err := ecdsa.Sign(rand.Reader, &result2, mm)
    fmt.Println(q, z, err)
    res := ecdsa.Verify(&result2.PublicKey, mm, r, s)
    fmt.Println(res)


}

