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

    result, _ := RecoverSecretKeyFromKnownNonce(r, s, m, k)
    expected, _ := new(big.Int).SetString("5995bfb52d8d4bfbba7b98549cea1d55d901b9e3d050bdc42bb138be138441cf", 16)
    if result.D.Cmp(expected) != 0 {
        t.Errorf("Expecting %s, got: %s", expected.String(), result.D.String())
    }


    r, _ = new(big.Int).SetString("dcb1b4f098a34a44f95337f04597dde635b0f5e3fa13d2e43663c7286dfd59e0", 16)
    s, _ = new(big.Int).SetString("6c44d8eee6fa34ba83214c477ad50aaebfada718d9498d99e8b20948c5882a1c", 16)
    k, _ = new(big.Int).SetString("7b3300ec97bf4199d9db91ace840d6b2", 16)

    result, _ = RecoverSecretKeyFromKnownNonce(r, s, m, k)
    expected, _ = new(big.Int).SetString("8bbfd8070a790b52685903e5072977cb7a175e264905566bf167cc572bc48403", 16)
    if result.D.Cmp(expected) != 0 {
        t.Errorf("Expecting %s, got: %s", expected.String(), result.D.String())
    }
}

func TestRecoverSecretKeyFromRepeatNonce(t *testing.T) {
    r, _ := new(big.Int).SetString("5d66e837a35ddc34be6fb126a3ec37153ff4767ff63cbfbbb32c04a795680491", 16)
    s1, _ := new(big.Int).SetString("1a53499a4aafb33d59ed9a4c5fcc92c5850dcb23d208de40a909357f6fa2c12c", 16)
    s2, _ := new(big.Int).SetString("d67006bc8b7375e236e11154d576eed0fc8539c3bba566f696e9a5340bb92bee", 16)
    m1, _ := new(big.Int).SetString("610e8f362f5276d8f52c2e84f517b73092924db8b01d56a9fea622ad436a7f4d", 16)
    m2, _ := new(big.Int).SetString("54daa3bae25f29331509c0e299cbe829e6191a8b8600c946ee61f30a7ff3b619", 16)

    result, _ := RecoverSecretKeyFromRepeatNonce(r, s1, s2, m1, m2)
    expected, _ := new(big.Int).SetString("128e06938ac462d9", 16)
    if result.D.Cmp(expected) != 0 {
        t.Errorf("Expecting %s, got: %s", expected.String(), result.D.String())
    }
}

