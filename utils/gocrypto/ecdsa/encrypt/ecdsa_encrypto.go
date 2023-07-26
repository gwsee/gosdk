//gwsee License
//Copyright (C) 2016 The Hyperchain Authors.
package encrypt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"

	"github.com/gwsee/gosdk/common"
	"github.com/gwsee/gosdk/utils/gocrypto/ecdsa/encrypt/secp256k1"
	"github.com/gwsee/gosdk/utils/gocrypto/ecdsa/encrypt/sha3"
)

type EcdsaEncrypto struct {
	name string
	id   string
}

func NewEcdsaEncrypto(name string) *EcdsaEncrypto {
	ee := &EcdsaEncrypto{name: name}
	return ee
}

func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
}

func (ee *EcdsaEncrypto) Sign(hash []byte, prv interface{}) (sig []byte, err error) {
	privateKey := prv.(*ecdsa.PrivateKey)
	if len(hash) != 32 {
		return nil, fmt.Errorf("hash is required to be exactly 32 bytes (%d)", len(hash))
	}

	seckey := common.LeftPadBytes(privateKey.D.Bytes(), privateKey.Params().BitSize/8)
	defer zeroBytes(seckey)
	sig, err = secp256k1.Sign(hash, seckey)
	sig = append([]byte{0}, sig...)
	return
}

func Secp256k1Sign(msg []byte, seckey []byte) ([]byte, error) {

	//[]byte{0} is support for ecdsa version
	sig, err := secp256k1.Sign(msg, seckey)
	if err != nil {
		return nil, err
	}
	return append([]byte{0}, sig[0:]...), nil
}

//UnSign recovers Address from txhash and signature
func (ee *EcdsaEncrypto) UnSign(args ...interface{}) (common.Address, error) {
	if len(args) != 2 {
		err := errors.New("paramas invalid")
		return common.Address{}, err
	}
	hash := args[0].([]byte)
	sig := args[1].([]byte)
	pubBytes, err := secp256k1.RecoverPubkey(hash, sig)
	if err != nil {
		return common.Address{}, err
	}
	var addr common.Address
	copy(addr[:], Keccak256(pubBytes[1:])[12:])
	return addr, nil
}
func (ee *EcdsaEncrypto) GeneralKey() (interface{}, error) {
	key, err := GenerateKey()
	if err != nil {
		return nil, err
	}

	return key, nil
}

//load key by given port
//func (ee *EcdsaEncrypto)GetKey() (interface{},error) {
//	file := keystoredir+ee.port
//	return LoadECDSA(file)
//}

func (ee *EcdsaEncrypto) GenerateNodeKey(nodeID string, keyNodeDir string) error {
	ee.id = nodeID
	nodeDir := path.Join(keyNodeDir, "node")
	nodefile := path.Join(nodeDir, nodeID)

	_, err := os.Stat(nodefile)
	if err == nil || os.IsExist(err) { //privatefile exists
		return nil
	}
	key, err := GenerateKey()
	if err != nil {
		return err
	}
	err = os.MkdirAll(nodeDir, 0700)
	if err != nil {
		return err
	}
	if err = SaveECDSA(nodefile, key); err != nil {
		return err
	}
	return nil

}

//keyNodeDir 需要从配置文件中读取
func (ee *EcdsaEncrypto) GetNodeKey(keyNodeDir string) (interface{}, error) {
	nodefile := path.Join(keyNodeDir, "node", ee.id)
	return LoadECDSA(nodefile)

}

func (ee *EcdsaEncrypto) PrivKeyToAddress(prv interface{}) common.Address {
	p := prv.(ecdsa.PrivateKey)
	return PubkeyToAddress(p.PublicKey)
}

// LoadECDSA loads a secp256k1 private key from the given file.
// key data is expected to be hex-encoded.
func LoadECDSA(file string) (*ecdsa.PrivateKey, error) {
	buf := make([]byte, 64)
	fd, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	if _, err := io.ReadFull(fd, buf); err != nil {
		return nil, err
	}

	key, err := hex.DecodeString(string(buf))
	if err != nil {
		return nil, err
	}

	return ToECDSA(key), nil
}

// New methods using proper ecdsa keys from the stdlib
func ToECDSA(prv []byte) *ecdsa.PrivateKey {
	if len(prv) == 0 {
		return nil
	}

	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = secp256k1.S256()
	priv.D = common.BigD(prv)
	priv.PublicKey.X, priv.PublicKey.Y = secp256k1.S256().ScalarBaseMult(prv)
	return priv
}

func FromECDSA(prv *ecdsa.PrivateKey) []byte {
	if prv == nil {
		return nil
	}
	return prv.D.Bytes()
}

// SaveECDSA saves a secp256k1 private key to the given file with
// restrictive permissions. The key data is saved hex-encoded.
func SaveECDSA(file string, key *ecdsa.PrivateKey) error {
	k := hex.EncodeToString(FromECDSA(key))
	return ioutil.WriteFile(file, []byte(k), 0600)
}

func PubkeyToAddress(p ecdsa.PublicKey) common.Address {
	pubBytes := FromECDSAPub(&p)
	return common.BytesToAddress(Keccak256(pubBytes[1:])[12:])
}

func Keccak256(data ...[]byte) []byte {
	d := sha3.NewKeccak256()
	for _, b := range data {
		d.Write(b)
	}
	return d.Sum(nil)
}
func FromECDSAPub(pub *ecdsa.PublicKey) []byte {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil
	}
	return elliptic.Marshal(secp256k1.S256(), pub.X, pub.Y)
}
func zeroBytes(bytes []byte) {
	for i := range bytes {
		bytes[i] = 0
	}
}

//ParsePublicKey From JAVA SDK HexString
func GetPublickFromHex(pubStr string) (*ecdsa.PublicKey, error) {
	pubByte := common.Hex2Bytes(pubStr)
	if len(pubByte) != 65 {
		errStr := fmt.Sprintf("the Publickey Byte length must be 65!Your PublicKey length is %d !", len(pubByte))
		return nil, errors.New(errStr)
	}
	X := pubByte[1:33]
	Y := pubByte[33:65]

	x := common.Bytes2Big(X)
	y := common.Bytes2Big(Y)

	pubkey := new(ecdsa.PublicKey)
	pubkey.Curve = secp256k1.S256()
	pubkey.X = x
	pubkey.Y = y

	return pubkey, nil
}

//JAVA SDK TRANSPORT VERIFY SIGNTURE
func VerifyTransportSign(publicKey interface{}, msg, sign string) (bool, error) {

	pub := publicKey.(*(ecdsa.PublicKey))
	pubAddress := PubkeyToAddress(*pub)
	hashB := Keccak256([]byte(msg))
	signB := common.Hex2Bytes(sign)

	pubBytes, err := secp256k1.RecoverPubkey(hashB, signB)
	if err != nil {
		return false, err
	}
	recoveredPubkey := new(ecdsa.PublicKey)
	recoveredPubkey.Curve = secp256k1.S256()
	recoveredPubkey.X = common.Bytes2Big(pubBytes[1:33])
	recoveredPubkey.Y = common.Bytes2Big(pubBytes[33:65])
	addr := PubkeyToAddress(*recoveredPubkey)
	return pubAddress == addr, nil
}
