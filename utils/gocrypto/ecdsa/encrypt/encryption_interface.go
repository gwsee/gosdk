//gwsee License
//Copyright (C) 2016 The Hyperchain Authors.
package encrypt

import "github.com/gwsee/gosdk/common"

type KeyType interface {
	sign()
}

type Encryption interface {

	//sign byte
	Sign(hash []byte, prv interface{}) (sig []byte, err error)
	UnSign(args ...interface{}) (common.Address, error)
	//general private key
	GeneralKey() (interface{}, error)

	//generates pri-pub key of node and save it to file
	GenerateNodeKey(port string, keyNodeDir string) error

	GetNodeKey(keydir string) (interface{}, error)

	//GeneralKey(path string)(*ecdsa.PrivateKey,error)

	//GetKey()(interface{},error)

	PrivKeyToAddress(prv interface{}) common.Address
}
