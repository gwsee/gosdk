package gm

import (
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"math/big"

	"github.com/gwsee/gosdk/common"
	"github.com/gwsee/gosdk/utils/ccrypto/ecdsa/encrypt/sha3"
	"github.com/gwsee/gosdk/utils/ccrypto/gm/guomi"
)

type Key struct {
	PrivateKey *guomi.PrivateKey
	PublicKey  *guomi.PublicKey
	RawPuk     []byte
}

func (key *Key) GetPrivateKey() *guomi.PrivateKey {
	return key.PrivateKey
}

func (key *Key) GetPublicKey() *guomi.PublicKey {
	return key.PublicKey
}

func (key *Key) GetHexPubKey() string {
	return common.ToHex(guomi.GetPubKeyFromPri(key.PrivateKey))
}

func (key *Key) GetRawPublicKey() []byte {
	return key.RawPuk
}

func (key *Key) GetAddress() string {
	pub := guomi.GetPubKeyFromPri(key.PrivateKey)
	return common.BytesToAddress(Keccak256(pub)[12:]).Hex()
}

func Keccak256(data ...[]byte) []byte {
	d := sha3.NewKeccak256()
	for _, b := range data {
		d.Write(b)
	}
	return d.Sum(nil)
}

func GetAddrFromPubX(pubStr string) (string, error) {
	pubY, err := guomi.UncompressedPubkeyOpenssl(pubStr)
	if err != nil {
		return "0x0", err
	}

	if pubStr[0:2] == "0x" {
		pubStr = pubStr[2:]
	}
	pubXBytes := common.Hex2Bytes(pubStr[2:])
	hyperchainMatchedHeader := append([]byte{4}, pubXBytes...)
	rawPub := append(hyperchainMatchedHeader, pubY...)
	return common.ToHex(Keccak256(rawPub)[12:]), nil
}

var one = new(big.Int).SetInt64(1)

func randFieldElement(c elliptic.Curve, rand io.Reader) (k *big.Int, err error) {
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}
	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

func GenerateKey() (*guomi.PrivateKey, error) {
	c := guomi.P256Sm2()
	k, err := randFieldElement(c, rand.Reader)
	if err != nil {
		return nil, err
	}
	priv := new(guomi.PrivateKey)
	priv.Key = k.Bytes()
	//priv.PublicKey.Curve = guomi.Curve(16)
	xBig, yBig := c.ScalarBaseMult(k.Bytes())

	priv.PublicKey.X, priv.PublicKey.Y = common.LeftPadBytes(xBig.Bytes(), 32), common.LeftPadBytes(yBig.Bytes(), 32)

	return priv, nil
}
