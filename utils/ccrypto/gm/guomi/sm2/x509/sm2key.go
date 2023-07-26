package x509

import (
	"crypto"
	"crypto/elliptic"
	"io"
	"math/big"

	"github.com/gwsee/gosdk/common"
	"github.com/gwsee/gosdk/utils/ccrypto/gm/guomi"
)

//PublicKey guomi public key
type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

//PrivateKey guomi private key
type PrivateKey struct {
	PublicKey
	D *big.Int
}

//Public Public() get public key from private key
func (priv *PrivateKey) Public() crypto.PublicKey {
	return &priv.PublicKey
}

//Sign Sign() Signing with sm2 algorithm, msg should be hashed
//underlying layer calls C implementation
func (priv *PrivateKey) Sign(_ io.Reader, msg []byte, _ crypto.SignerOpts) ([]byte, error) {
	key := &guomi.PrivateKey{
		PublicKey: guomi.PublicKey{
			Curve: 0,
			X:     common.BigToBytes(priv.X, 10),
			Y:     common.BigToBytes(priv.Y, 10),
		},
		Key: common.BigToBytes(priv.D, 10),
	}
	return key.Sign(msg)
}
