package account

import (
	"encoding/hex"
	"fmt"
	"strings"
)

const addressLength = 20

// Address is the Quorum account address
type Address [addressLength]byte

// NewAddress creates a new Address from the provided bytes.  Minimal validation is performed.
func NewAddress(byt []byte) (Address, error) {
	if len(byt) != addressLength {
		return Address{}, fmt.Errorf("account address must have length %v bytes", addressLength)
	}
	var addr Address
	copy(addr[:], byt)

	return addr, nil
}

// NewAddressFromHexString creates a new Address from the provided hex string-representation.  The hexAddr can be with/without the '0x' prefix.
func NewAddressFromHexString(addr string) (Address, error) {
	addr = strings.TrimPrefix(addr, "0x")
	byt, err := hex.DecodeString(addr)
	if err != nil {
		return Address{}, fmt.Errorf("invalid hex address: %v", err)
	}
	return NewAddress(byt)
}

// ToBytes returns the underlying bytes of the Address
func (a Address) ToBytes() []byte {
	return a[:]
}

// ToHexString encodes the Address as a hex string without the '0x' prefix
func (a Address) ToHexString() string {
	return hex.EncodeToString(a[:])
}
