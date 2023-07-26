package gm

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"strings"

	"github.com/gwsee/gosdk/common"
	"github.com/gwsee/gosdk/utils/ccrypto/gm/guomi"
	"github.com/gwsee/gosdk/utils/ccrypto/gm/guomi/sm2"
	"github.com/gwsee/gosdk/utils/ccrypto/gm/guomi/sm2/x509"
)

var (
	prkFile string = "prk.pem"
	pukFile string = "puk.der"
)

func GenerateSignature(privateKey *guomi.PrivateKey, puk *guomi.PublicKey, rawPuk []byte, needHash string) (signature []byte, err error) {
	defer func() {
		if rerr := recover(); rerr != nil {
			fmt.Println(rerr) //这里的err其实就是panic传入的内容，bug
			err = errors.New("panic")
		}
	}()
	signature, err = privateKey.Sign(SighHashSM3(puk.X, puk.Y, needHash))
	if err != nil {
		return
	}
	signature = common.Hex2Bytes(common.Bytes2Hex([]byte{1}) + common.Bytes2Hex(guomi.GetPubKeyFromPri(privateKey)) + common.Bytes2Hex(signature))
	return
}

func SighHashSM3(pubX, pubY []byte, needHash string) []byte {
	/*
		from=0x000f1a7a08ccc48e5d30f80850cf1cf283aa3abd
		&to=0x80958818f0a025273111fba92ed14c3dd483caeb
		&value=0x08904e10904e1835
		&timestamp=0x14a31c7e4883b166
		&nonce=0x179a44e05e42f7
	*/
	h := guomi.New()
	ENTL1 := "00"
	h.Write(common.Hex2Bytes(ENTL1))
	ENTL2 := "80"
	h.Write(common.Hex2Bytes(ENTL2))
	userId := "31323334353637383132333435363738"
	h.Write(common.Hex2Bytes(userId))
	a := "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"
	h.Write(common.Hex2Bytes(a))
	b := "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"
	h.Write(common.Hex2Bytes(b))
	xG := "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"
	h.Write(common.Hex2Bytes(xG))
	yG := "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"
	h.Write(common.Hex2Bytes(yG))
	h.Write(pubX)
	h.Write(pubY)
	res := h.Sum(nil)
	h2 := guomi.New()

	//修改为sm3hash方法
	h2.Write(res)
	h2.Write([]byte(needHash))
	hashResult := h2.Sum(nil)
	return hashResult
}

func GetKeyPare(path string) (*Key, error) {
	privateKey, err := GetPrivateKey(path + "/" + prkFile)
	if err != nil {
		errStr := fmt.Sprintf("get account #%v's private key failed! error message:%v", path, err.Error())
		return nil, errors.New(errStr)
	}
	rawPuk, publicKey, err := GetPublicKey(path + "/" + pukFile)
	if err != nil {
		errStr := fmt.Sprintf("get account #%v's public key failed! error message:%v", path, err.Error())
		return nil, errors.New(errStr)
	}
	return &Key{
		privateKey,
		publicKey,
		rawPuk,
	}, nil
}

func GetPriFromHex(pri string) (*guomi.PrivateKey, error) {
	key, err := guomi.GetPriKeyFromHex(common.Hex2Bytes(pri))
	if err != nil {
		return nil, err
	}
	return key, nil
}

func GetPubFromPriv(pri *guomi.PrivateKey) []byte {
	pub := guomi.GetPubKeyFromPri(pri)
	return pub
}

func GetKeyPareFromHex(pri, pub string) (*Key, error) {
	prk, _ := GetPriFromHex(pri)
	rawPuk := GetPubFromPriv(prk)
	if res, err := isMatch(prk, pub); err != nil {
		return nil, err
	} else if !res {
		return nil, errors.New("public key " + pub + "is not matched with privatekey " + pri)
	}
	return &Key{
		prk,
		&prk.PublicKey,
		rawPuk,
	}, nil
}

func isMatch(prk *guomi.PrivateKey, pub string) (bool, error) {
	if len(pub) < 3 {
		return false, errors.New("Not matched public key format")
	}

	rawPub, err := prk.GetRaw()
	if err != nil {
		return false, err
	}
	if rawPub[2:] != pub && rawPub != pub {
		return false, fmt.Errorf("Not matched public key content\ncorrect is:\n%v\nbut get:\n%v", rawPub, pub)
	}
	switch pub[0:2] {
	case "0x":
		return isMatch(prk, pub[2:])
	case "02":
		bigy := common.BytesToBig(prk.PublicKey.Y)
		return new(big.Int).Mod(bigy, big.NewInt(2)).Int64() == 0, nil
	case "03":
		bigy := common.BytesToBig(prk.PublicKey.Y)
		return new(big.Int).Mod(bigy, big.NewInt(2)).Int64() == 1, nil
	case "04":
		return strings.Compare(common.ToHex(append(prk.PublicKey.X, prk.PublicKey.Y...))[2:], pub[2:]) == 0, nil
	default:
		return false, errors.New("Not matched public key format")
	}
}

func GetPrivateKey(path string) (*guomi.PrivateKey, error) {
	privateKey, err := generatePrivateKeyOfGuoMi(path) // "./utils/crypto/guomi/prk.pem")
	return privateKey, err
}
func GetPublicKey(path string) ([]byte, *guomi.PublicKey, error) {
	err, rawPuk := setPublicKeyOfTransaction(path) // "./utils/crypto/guomi/puk.der")
	var publicKey *guomi.PublicKey
	if err == nil {
		publicKey, err = generatePublicKeyOfGuoMi(rawPuk)
	}
	return rawPuk, publicKey, err
}

func generatePrivateKeyOfGuoMi(privateKeyPath string) (*guomi.PrivateKey, error) {
	//sm2p256v1 := guomi.Curve(1)
	prkDer, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode([]byte(prkDer))
	sm2Key, err := sm2.ParseSMPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key := sm2Key.(*x509.PrivateKey)
	return &guomi.PrivateKey{
		Key: key.D.Bytes(),
		PublicKey: guomi.PublicKey{
			Curve: guomi.Curve(1),
			X:     key.X.Bytes(),
			Y:     key.Y.Bytes(),
		},
	}, nil
	//prk, err := guomi.ParsePriKeyFromDER(sm2p256v1, block.Bytes)
	//if err != nil {
	//	return nil, err
	//}
	//return prk, nil
}

func generatePublicKeyOfGuoMi(rawPuk []byte) (*guomi.PublicKey, error) {
	//sm2p256v1 := guomi.Curve(1)
	puk, err := guomi.ParsePublicKeyByEncode(rawPuk)
	if err != nil {
		return nil, err
	}
	return puk, nil
}

func setPublicKeyOfTransaction(publicKeyPath string) (error, []byte) {
	pukDer, err := ioutil.ReadFile(publicKeyPath)
	pukInfo := struct {
		Raw       asn1.RawContent
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{}
	_, err = asn1.Unmarshal(pukDer, &pukInfo)
	if err != nil {
		return err, nil
	}
	raw := pukInfo.PublicKey.Bytes
	if err != nil {
		return err, nil
	}
	return nil, raw
}
