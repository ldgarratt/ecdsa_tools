package main

import (
    "testing"
    "math/big"
)

func TestRecoverSecretKeyFromKnownNonce(t *testing.T) {
    r, _ := new(big.Int).SetString("e34dc9682d84351326636b4286d5a9afe66a8e84763aa3ae00898b571c5df328", 16)
    s, _ := new(big.Int).SetString("6d49dfab0ae451bee756751ce92dbad2e9b57204fc1d9d724a841cc4c101005d", 16)
    m, _ := new(big.Int).SetString("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", 16)
    k, _ := new(big.Int).SetString("216c9dce67d3a7b60ad5117dd599e3f6", 16)

    result, _ := recoverSecretKeyFromKnownNonce(r, s, m, k)
    expected, _ := new(big.Int).SetString("5995bfb52d8d4bfbba7b98549cea1d55d901b9e3d050bdc42bb138be138441cf", 16)
    if result.D.Cmp(expected) != 0 {
        t.Errorf("Expecting %s, got: %s", expected.String(), result.D.String())
    }
}
