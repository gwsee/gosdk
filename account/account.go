package account

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/gwsee/gosdk/utils/gocrypto/crypto"
	"github.com/gwsee/gosdk/utils/gocrypto/gm/guomi/sm4"

	"github.com/gwsee/gosdk/common"
	"github.com/gwsee/gosdk/common/math"
	"github.com/gwsee/gosdk/utils/gocrypto/ecdsa"
	"github.com/gwsee/gosdk/utils/gocrypto/ecdsa/encrypt"
	"github.com/gwsee/gosdk/utils/gocrypto/gm"
	sm2 "github.com/gwsee/gosdk/utils/gocrypto/gm/guomi/sm2"
)

const (
	ECKDF2 = "0x01"
	ECDES  = "0x02"
	ECRAW  = "0x03"
	ECAES  = "0x04"
	EC3DES = "0x05"

	SMSM4  = "0x11"
	SMDES  = "0x12"
	SMRAW  = "0x13"
	SMAES  = "0x14"
	SM3DES = "0x15"

	V1 = "1.0"
	V2 = "2.0"
	V3 = "3.0"
	V4 = "4.0"
)

var logger = common.GetLogger("account")

type accountJSON struct {
	Address common.Address `json:"address"`
	// Algo 0x01 KDF2 0x02 DES(ECB) 0x03(plain) 0x04 DES(CBC)
	Algo string `json:"algo,omitempty"`
	//Encrypted           string `json:"encrypted,omitempty"`
	Version    string `json:"version,omitempty"`
	PublicKey  string `json:"publicKey,omitempty"`
	PrivateKey string `json:"privateKey,omitempty"`
	//PrivateKeyEncrypted bool   `json:"privateKeyEncrypted"`
}

// NewAccountJson generate account json by account type
func NewAccountJson(acType, password string) (string, error) {
	accountJson := new(accountJSON)
	var privateKey []byte

	if strings.HasPrefix(acType, "0x0") {
		key, err := encrypt.GenerateKey()
		if err != nil {
			return "", err
		}
		switch acType {
		case ECKDF2:
			return "", errors.New("not support KDF2 now")
		case ECDES:
			accountJson.Algo = ECDES
			privateKey, err = crypto.DesEncrypt(math.PaddedBigBytes(key.D, 32), []byte(password))
			if err != nil {
				return "", err
			}
		case ECRAW:
			accountJson.Algo = ECRAW
			privateKey = math.PaddedBigBytes(key.D, 32)
		case ECAES:
			accountJson.Algo = ECAES
			privateKey, err = crypto.AesEncrypt(math.PaddedBigBytes(key.D, 32), []byte(password))
			if err != nil {
				return "", err
			}
		case EC3DES:
			accountJson.Algo = EC3DES
			privateKey, err = crypto.TripleDesEnc(math.PaddedBigBytes(key.D, 32), []byte(password))
			if err != nil {
				return "", err
			}
		default:
			return "", errors.New("not support crypt type " + acType)
		}
		accountJson.Version = V4
		accountJson.Address = encrypt.PubkeyToAddress(key.PublicKey)
		accountJson.PublicKey = common.Bytes2Hex(encrypt.FromECDSAPub(&(key.PublicKey)))
		accountJson.PrivateKey = common.Bytes2Hex(privateKey)
	} else if strings.HasPrefix(acType, "0x1") {
		key, err := sm2.GenerateKey()
		if err != nil {
			return "", err
		}
		tempKey := common.LeftPadBytes(key.D.Bytes(), 32)
		var privateKey []byte
		switch acType {
		case SMSM4:
			accountJson.Algo = SMSM4
			privateKey, err = sm4.SM4Encrypt(tempKey, []byte(password))
			if err != nil {
				return "", err
			}
		case SMDES:
			accountJson.Algo = SMDES
			privateKey, err = crypto.DesEncrypt(tempKey, []byte(password))
			if err != nil {
				return "", err
			}
		case SMRAW:
			accountJson.Algo = SMRAW
			privateKey = tempKey
		case SMAES:
			accountJson.Algo = SMAES
			privateKey, err = crypto.AesEncrypt(tempKey, []byte(password))
			if err != nil {
				return "", err
			}
		case SM3DES:
			accountJson.Algo = SM3DES
			privateKey, err = crypto.TripleDesEnc(tempKey, []byte(password))
			if err != nil {
				return "", err
			}
		default:
			return "", errors.New("not support crypt type " + acType)
		}
		accountJson.Version = V4
		accountJson.PrivateKey = common.Bytes2Hex(privateKey)
		pubKey := sm2.GetPubKeyFromPri(key)
		accountJson.PublicKey = common.Bytes2Hex(pubKey)
		accountJson.Address = common.BytesToAddress(gm.Keccak256(pubKey[0:])[12:])
	}

	jsonBytes, err := json.Marshal(accountJson)
	if err != nil {
		return "", err
	}

	return string(jsonBytes), nil
}

// GenKeyFromAccountJson generate ecdsa.Key or gm.Key by account type
func GenKeyFromAccountJson(accountJson, password string) (key interface{}, err error) {
	defer func() {
		if r := recover(); r != nil {
			key = nil
			err = errors.New("decrypt private key failed")
		}
	}()

	accountJson, err = ParseAccountJson(accountJson, password)
	if err != nil {
		return nil, err
	}

	account := new(accountJSON)
	err = json.Unmarshal([]byte(accountJson), account)
	if err != nil {
		return nil, err
	}

	var priv []byte
	priv, err = decrptPriv(account.PrivateKey, account.Algo, password)
	if err != nil {
		return nil, err
	}

	if strings.HasPrefix(account.Algo, "0x0") {
		return NewAccountFromPriv(common.Bytes2Hex(priv))
	} else if strings.HasPrefix(account.Algo, "0x1") {
		return NewAccountSm2FromPriv(common.Bytes2Hex(priv))

	}
	return nil, errors.New("error account algo type")
}

func ParseAccountJson(accountJson, password string) (newAccountJson string, err error) {
	account := make(map[string]interface{})
	err = json.Unmarshal([]byte(accountJson), &account)
	var version string
	var address string
	var publicKey string
	var algo string
	var privateKey string
	var isEncrypted bool

	address = account["address"].(string)
	if account["encrypted"] == nil {
		privateKey = strings.ToLower(account["privateKey"].(string))
	} else {
		privateKey = strings.ToLower(account["encrypted"].(string))
	}

	if account["version"] == nil {
		version = V4
	} else {
		version = account["version"].(string)
		if version == V4 {
			return accountJson, nil
		}
	}

	if account["privateKeyEncrypted"] != nil {
		isEncrypted = account["privateKeyEncrypted"].(bool)
	}

	if account["algo"] == nil {
		if isEncrypted {
			algo = SMDES
		} else {
			algo = SMRAW
		}
	} else {
		algo = account["algo"].(string)
	}

	if account["publicKey"] != nil {
		publicKey = account["publicKey"].(string)
	} else if strings.HasPrefix(algo, "0x0") {
		var decryptedPriv []byte
		decryptedPriv, err = decrptPriv(privateKey, algo, password)
		if err != nil {
			return "", err
		}
		key, err := NewAccountFromPriv(common.Bytes2Hex(decryptedPriv))
		if err != nil {
			return "", errors.New("error private key")
		}
		publicKey = strings.ToLower(common.Bytes2Hex(encrypt.FromECDSAPub(key.PublicKey)))
	}

	newAccountJson = "{\"address\":\"" +
		common.DelHex(address) + "\",\"algo\":\"" +
		algo + "\",\"privateKey\":\"" +
		common.DelHex(privateKey) + "\",\"version\":\"" +
		version + "\",\"publicKey\":\"" +
		common.DelHex(publicKey) + "\"}"

	return newAccountJson, nil
}

func decrptPriv(encrypted, algo, password string) (priv []byte, err error) {
	if strings.HasPrefix(algo, "0x0") {
		switch algo {
		case ECKDF2:
			return nil, errors.New("not support KDF2 now")
		case ECDES:
			priv, err = crypto.DesDecrypt(common.Hex2Bytes(encrypted), []byte(password))
		case ECRAW:
			priv = common.Hex2Bytes(encrypted)
		case ECAES:
			priv, err = crypto.AesDecrypt(common.Hex2Bytes(encrypted), []byte(password))
		case EC3DES:
			priv, err = crypto.TripleDesDec(common.Hex2Bytes(encrypted), []byte(password))
		default:
			return nil, errors.New("not support crypt type " + algo)
		}
		if err != nil {
			return nil, err
		}

	} else if strings.HasPrefix(algo, "0x1") {
		switch algo {
		case SMSM4:
			priv, err = sm4.SM4Decrypt(common.Hex2Bytes(encrypted), []byte(password))
		case SMDES:
			priv, err = crypto.DesDecrypt(common.Hex2Bytes(encrypted), []byte(password))
		case SMRAW:
			priv = common.Hex2Bytes(encrypted)
		case SMAES:
			priv, err = crypto.AesDecrypt(common.Hex2Bytes(encrypted), []byte(password))
		case SM3DES:
			priv, err = crypto.TripleDesDec(common.Hex2Bytes(encrypted), []byte(password))
		default:
			return nil, errors.New("not support crypt type " + algo)
		}
		if err != nil {
			return nil, err
		}
	}

	return priv, nil
}

// NewAccount create account using ecdsa
// if password is empty, the encrypted field will be private key
func NewAccount(password string) (string, error) {
	if password != "" {
		return NewAccountJson(ECDES, password)
	} else {
		return NewAccountJson(ECRAW, password)
	}
}

// NewAccountFromPriv 从私钥字节数组得到ECDSA Key结构体
func NewAccountFromPriv(priv string) (*ecdsa.Key, error) {
	rawKey := encrypt.ToECDSA(common.Hex2Bytes(priv))
	if rawKey == nil {
		logger.Error("create account error")
		return nil, errors.New("create account error")
	}
	key := ecdsa.Key{
		PrivateKey: rawKey,
		PublicKey:  &rawKey.PublicKey,
	}

	return &key, nil
}

// NewAccountFromAccountJSON ECDSA Key结构体
func NewAccountFromAccountJSON(accountjson, password string) (key *ecdsa.Key, err error) {
	defer func() {
		if r := recover(); r != nil {
			key = nil
			err = errors.New("decrypt private key failed")
		}
	}()
	accountjson, err = ParseAccountJson(accountjson, password)
	if err != nil {
		return nil, err
	}

	account := new(accountJSON)
	err = json.Unmarshal([]byte(accountjson), account)
	if err != nil {
		return nil, err
	}

	var priv []byte

	if account.Version == "1.0" {
		priv, err = crypto.DesDecrypt(common.Hex2Bytes(account.PrivateKey), []byte(password))
		if err != nil {
			return nil, err
		}
	} else {
		// version 2.0 means not encrypted
		priv = common.Hex2Bytes(account.PrivateKey)
	}

	return NewAccountFromPriv(common.Bytes2Hex(priv))
}

// NewAccountSm2 生成国密
func NewAccountSm2(password string) (string, error) {
	if password != "" {
		return NewAccountJson(SMDES, password)
	} else {
		return NewAccountJson(SMRAW, password)
	}
}

// NewAccountSm2FromPriv 从私钥字符串生成国密结构体
func NewAccountSm2FromPriv(priv string) (*gm.Key, error) {
	if strings.HasPrefix(priv, "00") {
		priv = priv[2:]
	}
	prk, err := sm2.GetPriKeyFromHex(common.Hex2Bytes(priv))
	if err != nil {
		return nil, err
	}
	key := gm.Key{
		PrivateKey: prk,
		PublicKey:  &prk.PublicKey,
	}

	return &key, nil
}

// NewAccountSm2FromAccountJSON 从账户JSON转为国密结构体
// Deprecated
func NewAccountSm2FromAccountJSON(accountjson, password string) (key *gm.Key, err error) {
	defer func() {
		if r := recover(); r != nil {
			key = nil
			err = errors.New("decrypt private key failed")
		}
	}()

	accountjson, err = ParseAccountJson(accountjson, password)
	if err != nil {
		return nil, err
	}

	account := new(accountJSON)
	err = json.Unmarshal([]byte(accountjson), account)
	if err != nil {
		return nil, err
	}
	var priv []byte
	if account.Algo == SMDES {
		priv, err = crypto.DesDecrypt(common.Hex2Bytes(account.PrivateKey), []byte(password))
		if err != nil {
			return nil, err
		}
	} else {
		priv = common.Hex2Bytes(account.PrivateKey)
	}
	newkey, err := NewAccountSm2FromPriv(common.Bytes2Hex(priv))
	if err != nil {
		return nil, err
	}
	// FIXME: we need to judge address is right
	//if newkey.GetAddress() != account.Address.Hex() {
	//	return nil, errors.New("address is error")
	//}
	return newkey, nil
}
