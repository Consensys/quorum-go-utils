package account

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	secp256k1 "github.com/consensys/goquorum-crypto-secp256k1"
	"golang.org/x/crypto/sha3"
)

const (
	keyLen = 32 // the expected length in bytes of a S256 secp256k1 private key
)

// GenerateKey generates a new random secp256k1 key
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
}

// NewKeyFromHexString creates a new PrivateKey from the provided hex string-representation.
// The hex key can be with/without the '0x' prefix.
// This function should not be used with direct user input as it performs minimal validation.
// Auto-generated input should be used (i.e. generated keys retrieved direct from Vault) or user-input from Quorum that should have been validated at the Quorum-level.
// Be careful if using direct user input as valid hex may not result in a valid ethereum private key.
func NewKeyFromHexString(key string) (*ecdsa.PrivateKey, error) {
	key = strings.TrimPrefix(key, "0x")
	byt, err := hex.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("invalid hex private key: %v", err)
	}
	return newKey(byt)
}

func newKey(byt []byte) (*ecdsa.PrivateKey, error) {
	if len(byt) != keyLen {
		return nil, fmt.Errorf("private key must have length %v bytes", keyLen)
	}
	var (
		curve = secp256k1.S256()
		key   = new(ecdsa.PrivateKey)
	)
	key.D = new(big.Int).SetBytes(byt)
	key.PublicKey.Curve = curve
	key.PublicKey.X, key.PublicKey.Y = curve.ScalarBaseMult(byt)

	return key, nil
}

// PrivateKeyToAddress derives the valid 20-byte Quorum address from the provided private key
func PrivateKeyToAddress(key *ecdsa.PrivateKey) (Address, error) {
	if key == nil || key.PublicKey.X == nil || key.PublicKey.Y == nil {
		return Address{}, errors.New("invalid key: unable to derive address")
	}
	pubBytes := elliptic.Marshal(secp256k1.S256(), key.PublicKey.X, key.PublicKey.Y)

	d := sha3.NewLegacyKeccak256()
	_, err := d.Write(pubBytes[1:])
	if err != nil {
		return Address{}, err
	}
	pubHash := d.Sum(nil)

	return NewAddress(pubHash[12:])
}

// PrivateKeyToBytes returns the bytes for the private component of the key, and if necessary, left-0 pads them to 32 bytes.
//
// As outlined in https://github.com/openethereum/openethereum/issues/2263, 256 bit secp256k1 can generate valid keys that are shorter than 32 bytes.
// To protect against potential issues with variable lengths, key bytes should be left-0 padded.
//
// common/math.PaddedBigBytes accomplishes this using bitwise operations for maximal performance.
// Given the additional HTTP overhead already introduced when using Vault, and to improve code-readability, standard slice functions have been used here.
func PrivateKeyToBytes(key *ecdsa.PrivateKey) ([]byte, error) {
	// TODO(cjh) if performance of crypto operations needs to be improved, consider revisiting this func (see godoc)
	if key == nil {
		return nil, errors.New("nil key")
	}
	byt := key.D.Bytes()

	switch {
	case len(byt) > keyLen:
		return nil, fmt.Errorf("key cannot be longer than %v bytes", keyLen)
	case len(byt) < keyLen:
		padded := make([]byte, keyLen)
		return append(padded[:len(padded)-len(byt)], byt...), nil
	default:
		return byt, nil
	}
}

// PrivateKeyToHexString encodes the provided key as a hex string
func PrivateKeyToHexString(key *ecdsa.PrivateKey) (string, error) {
	byt, err := PrivateKeyToBytes(key)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(byt), nil
}

// ZeroKey zeroes the underlying bytes of the key
func ZeroKey(key *ecdsa.PrivateKey) {
	b := key.D.Bits()
	for i := range b {
		b[i] = 0
	}
}

// Zero zeroes the bytes
func Zero(byt []byte) {
	for i := range byt {
		byt[i] = 0
	}
}

// Sign simply signs the data with the provided key using secp256k1.  It performs no pre/post-computation of the data - if this is required it should be performed by the caller.
func Sign(toSign []byte, key *ecdsa.PrivateKey) ([]byte, error) {
	keyByt, err := PrivateKeyToBytes(key)
	if err != nil {
		return nil, err
	}
	defer Zero(keyByt)

	return secp256k1.Sign(toSign, keyByt)
}
