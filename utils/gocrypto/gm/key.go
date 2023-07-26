package gm

import (
	"errors"
	"math/big"

	"github.com/gwsee/gosdk/common"
	"github.com/gwsee/gosdk/utils/gocrypto/ecdsa/encrypt/sha3"
	sm2 "github.com/gwsee/gosdk/utils/gocrypto/gm/guomi/sm2"
)

type Key struct {
	PrivateKey *sm2.PrivateKey
	PublicKey  *sm2.PublicKey
	RawPuk     []byte
}

func (key *Key) GetPrivateKey() *sm2.PrivateKey {
	return key.PrivateKey
}

func (key *Key) GetPublicKey() *sm2.PublicKey {
	return key.PublicKey
}

func (key *Key) GetHexPubKey() string {
	return common.ToHex(sm2.GetPubKeyFromPri(key.PrivateKey))
}

func (key *Key) GetRawPublicKey() []byte {
	return key.RawPuk
}

func (key *Key) GetAddress() string {
	pub := sm2.GetPubKeyFromPri(key.PrivateKey)
	return common.BytesToAddress(Keccak256(pub)[12:]).Hex()
}

func Keccak256(data ...[]byte) []byte {
	d := sha3.NewKeccak256()
	for _, b := range data {
		d.Write(b)
	}
	return d.Sum(nil)
}

// GetAddrFromPubX is used to generate address with part X in public key
func GetAddrFromPubX(pubStr string) (string, error) {
	if pubStr[0:2] == "0x" {
		pubStr = pubStr[2:]
	}

	pubY, err := UncompressedPubkey(pubStr)

	if err != nil {
		return "0x0", err
	}

	pubXBytes := common.Hex2Bytes(pubStr[2:])
	hyperchainMatchedHeader := append([]byte{4}, common.LeftPadBytes(pubXBytes, 32)...)
	rawPub := append(hyperchainMatchedHeader, common.LeftPadBytes(pubY, 32)...)
	return common.ToHex(Keccak256(rawPub)[12:]), nil
}

// UncompressedPubkey is used to uncompress public key
func UncompressedPubkey(pubStr string) ([]byte, error) {
	tmp := common.Hex2Bytes(pubStr)
	if tmp == nil {
		return nil, errors.New("input is not a hex")
	}
	if tmp[0]&0x02 != 2 {
		return nil, errors.New("private key is not compressed form")
	}
	flag := tmp[0] & 0x01
	curve := sm2.P256Sm2().Params()
	x := big.NewInt(0).SetBytes(tmp[1:])
	xx := big.NewInt(0)
	xx = xx.Mul(x, x).Mod(xx, curve.P)
	a := big.NewInt(3)
	a = a.Sub(curve.P, a).Mod(a, curve.P)

	xx.Add(xx, a).Mod(xx, curve.P)
	xx.Mul(xx, x).Mod(xx, curve.P)
	xx.Add(xx, curve.B).Mod(xx, curve.P)
	r := xx.ModSqrt(xx, curve.P)
	if r == nil {
		return nil, errors.New("unknown error")
	}
	if (byte(r.Bit(0))^flag)&0x01 == 1 {
		return a.Sub(curve.P, r).Mod(a, curve.P).Bytes(), nil
	} else {
		return r.Bytes(), nil
	}
}
