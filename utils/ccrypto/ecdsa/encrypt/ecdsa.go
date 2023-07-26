package encrypt

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
)

// ECDSASignature represents an ECDSA signature
type ECDSASignature struct {
	R, S *big.Int
}

// ECDSASignWithSha256 先对msg采用sha256摘要，再用ECDSA算法签名
func ECDSASignWithSha256(privKey *ecdsa.PrivateKey, msg []byte) ([]byte, error) {
	digest := make([]byte, 32)
	h := sha256.New()
	h.Write(msg)
	h.Sum(digest[:0])

	r, s, err := ecdsa.Sign(rand.Reader, privKey, digest)
	if err != nil {
		return nil, err
	}

	sig, err := asn1.Marshal(ECDSASignature{r, s})
	if err != nil {
		return nil, err
	}

	return sig, nil
}

// ReadCert 读取cert文件，编码为hex string
func ReadCert(certpath string) (string, error) {
	certpem, err := ioutil.ReadFile(certpath)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(certpem), nil
}

// ParsePriv 解析x509编码的密钥
func ParsePriv(privpath string) (*ecdsa.PrivateKey, error) {
	fileContent, err := ioutil.ReadFile(privpath)
	if err != nil {
		return nil, err
	}

	priv, _ := pem.Decode(fileContent)
	if priv == nil {
		return nil, fmt.Errorf("fail to decode pem file")
	}

	return x509.ParseECPrivateKey(priv.Bytes)
}
