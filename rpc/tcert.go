package rpc

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/gwsee/gosdk/common"
	"github.com/gwsee/gosdk/utils/gocrypto/ecdsa/encrypt"
	"github.com/gwsee/gosdk/utils/gocrypto/gm"
	sm2 "github.com/gwsee/gosdk/utils/gocrypto/gm/guomi/sm2"
	"github.com/terasum/viper"
)

// KeyPair privateKey(ecdsa.PrivateKey or guomi.PrivateKey) and publicKey string
type KeyPair struct {
	privKey interface{}
	pubKey  string
}

// newKeyPair create a new KeyPair(ecdsa or sm2)
func newKeyPair(privFilePath string) (*KeyPair, error) {
	keyPari, err := encrypt.ParsePriv(privFilePath)
	if err != nil {
		logger.Debug("the cert is not ecdsa, now try to parse by sm2")
		keyPari, err := gm.GetPrivateKey(privFilePath)
		if err != nil {
			logger.Error(err)
			return nil, err
		}
		pubKey := sm2.GetPubKeyFromPri(keyPari)
		return &KeyPair{
			privKey: keyPari,
			pubKey:  common.Bytes2Hex(pubKey),
		}, nil
	}
	return &KeyPair{
		privKey: keyPari,
		pubKey:  common.Bytes2Hex(encrypt.FromECDSAPub(&keyPari.PublicKey)),
	}, nil
}

// Sign sign the message by privateKey
func (key *KeyPair) Sign(msg []byte) ([]byte, error) {
	switch key.privKey.(type) {
	case *ecdsa.PrivateKey:
		data, err := encrypt.ECDSASignWithSha256(key.privKey.(*ecdsa.PrivateKey), msg)
		if err != nil {
			return nil, err
		}
		return data, nil
	case *sm2.PrivateKey:
		gmKey := key.privKey.(*sm2.PrivateKey)
		data, err := gmKey.Sign(rand.Reader, gm.SighHashSM3(gmKey.X, gmKey.Y, string(msg)), nil)
		if err != nil {
			return nil, err
		}
		return data, nil
	default:
		logger.Error("unsupported sign type")
		return nil, NewSystemError(errors.New("signature type error"))
	}
}

// TCert tcert message
type TCert string

// TCertManager manager tcert
type TCertManager struct {
	sdkCert        *KeyPair
	uniqueCert     *KeyPair
	ecert          string
	tcertPool      map[string]TCert
	sdkcertPath    string
	sdkcertPriPath string
	uniquePubPath  string
	uniquePrivPath string
	cfca           bool
}

// NewTCertManager create a new TCert manager
func NewTCertManager(vip *viper.Viper, confRootPath string) *TCertManager {
	if !vip.GetBool(common.PrivacySendTcert) {
		return nil
	}

	sdkcertPath := strings.Join([]string{confRootPath, vip.GetString(common.PrivacySDKcertPath)}, "/")
	logger.Debugf("[CONFIG]: sdkcertPath = %v", sdkcertPath)

	sdkcertPriPath := strings.Join([]string{confRootPath, vip.GetString(common.PrivacySDKcertPrivPath)}, "/")
	logger.Debugf("[CONFIG]: sdkcertPriPath = %v", sdkcertPriPath)

	uniquePubPath := strings.Join([]string{confRootPath, vip.GetString(common.PrivacyUniquePubPath)}, "/")
	logger.Debugf("[CONFIG]: uniquePubPath = %v", uniquePubPath)

	uniquePrivPath := strings.Join([]string{confRootPath, vip.GetString(common.PrivacyUniquePrivPath)}, "/")
	logger.Debugf("[CONFIG]: uniquePrivPath = %v", uniquePrivPath)

	cfca := vip.GetBool(common.PrivacyCfca)
	logger.Debugf("[CONFIG]: cfca = %v", cfca)

	var (
		sdkCert    *KeyPair
		uniqueCert *KeyPair
		err        error
	)

	sdkCert, err = newKeyPair(sdkcertPriPath)
	if err != nil {
		panic(fmt.Sprintf("read sdkcertPri from %s failed", sdkcertPriPath))
	}
	uniqueCert, err = newKeyPair(uniquePrivPath)
	if err != nil {
		panic(fmt.Sprintf("read uniquePriv from %s failed", uniquePrivPath))

	}
	ecert, err := ioutil.ReadFile(sdkcertPath)
	if err != nil {
		panic(fmt.Sprintf("read sdkcert from %s failed", sdkcertPath))

	}

	return &TCertManager{
		sdkcertPath:    sdkcertPath,
		sdkcertPriPath: sdkcertPriPath,
		uniquePubPath:  uniquePubPath,
		uniquePrivPath: uniquePrivPath,
		sdkCert:        sdkCert,
		uniqueCert:     uniqueCert,
		ecert:          common.Bytes2Hex(ecert),
		cfca:           cfca,
	}
}

// GetECert get ecert
func (tcm *TCertManager) GetECert() string {
	return tcm.ecert
}
