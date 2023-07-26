package ecdsa

import (
	"crypto/ecdsa"

	"github.com/gwsee/gosdk/common"
	"github.com/gwsee/gosdk/common/math"
	"github.com/gwsee/gosdk/utils/gocrypto/ecdsa/encrypt"
)

type Key struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
}

func (key *Key) GetAddress() string {
	ret := encrypt.PubkeyToAddress(key.PrivateKey.PublicKey)
	return ret.Hex()
}

func (key *Key) GetPrivKey() string {
	return common.Bytes2Hex(math.PaddedBigBytes(key.PrivateKey.D, 32))
}

func (key *Key) GetHexPubKey() string {
	return common.ToHex(encrypt.FromECDSAPub(key.PublicKey))
}
