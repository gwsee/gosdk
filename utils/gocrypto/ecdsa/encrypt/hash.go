//gwsee License
//Copyright (C) 2016 The Hyperchain Authors.
package encrypt

import (
	"encoding/json"

	"github.com/gwsee/gosdk/common"
	"github.com/gwsee/gosdk/utils/gocrypto/ecdsa/encrypt/sha3"
)

//Keccak256Hash is a kind of hash method which implements CommomHash interface
type Keccak256Hash struct {
	name string
}

func NewKeccak256Hash(name string) *Keccak256Hash {
	s256 := &Keccak256Hash{name: name}
	return s256
}

//Hash transfers object x into common.Hash with length 32
func (k256 *Keccak256Hash) Hash(x interface{}) (h common.Hash) {
	serialize_data, err := json.Marshal(x)
	common.ParseData(x)

	if err != nil {
		panic(err)
	}
	hw := sha3.NewKeccak256()
	hw.Write(serialize_data)
	hw.Sum(h[:0])

	return h
}

//ByteHash deals with params which has already been []byte
func (k256 *Keccak256Hash) ByteHash(data ...[]byte) (h common.Hash) {

	hw := sha3.NewKeccak256()
	for _, d := range data {
		hw.Write(d)
	}
	hw.Sum(h[:0])

	return h
}

// Keccak256HashE calculates and returns the Keccak256 hash of the input data,
// converting it to an internal Hash data structure.
func Keccak256HashE(data ...[]byte) (h common.Hash) {
	d := sha3.NewKeccak256()
	for _, b := range data {
		d.Write(b)
	}
	d.Sum(h[:0])
	return h
}
