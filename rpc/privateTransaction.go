package rpc

import (
	"encoding/json"
	"github.com/buger/jsonparser"
	"strconv"
	"strings"

	"github.com/gwsee/gosdk/common"
	"github.com/gwsee/gosdk/utils/gocrypto/ecdsa"
	"github.com/gwsee/gosdk/utils/gocrypto/ecdsa/encrypt/sha3"
)

// PrivateTransactionRawData is raw private transaction extra field
type PrivateTransactionRawData struct {
	Collection      []string `json:"collection"`
	PublicSignature string   `json:"publicSignature"`
	Payload         string   `json:"payload"`
}

// NewPrivateTransaction return a empty private transaction
func NewPrivateTransaction(from string, participants []string) *Transaction {
	return &Transaction{
		timestamp:    getCurTimeStamp(),
		nonce:        getRandNonce(),
		to:           "0x0",
		from:         chPrefix(from),
		simulate:     false,
		vmType:       string(EVM),
		participants: participants,
		isPrivateTx:  true,
	}
}

// GenSinPub is used to signature needString
func GenSinPub(key *ecdsa.Key, needHashString string) string {
	h := sha3.NewKeccak256()
	h.Write([]byte(needHashString))
	sig, err := genSignature(nil, key.GetPrivKey(), "ecdsa", needHashString)
	if err != nil {
		logger.Error("ecdsa signature error")
		return ""
	}
	return common.Bytes2Hex(sig)
}

// PreSign is used to constructor extra field in private transaction
func (t *Transaction) PreSign(key *ecdsa.Key) {
	sha3ToHex := func(value []byte) string {
		h := sha3.NewKeccak256()
		h.Write(value)
		return "0x" + common.Bytes2Hex(h.Sum([]byte{}))
	}

	rawPayload := t.payload

	// --- create sig_pub ---
	pubTxExtra := NewKVExtra()
	privateRawData := PrivateTransactionRawData{
		Payload:         sha3ToHex([]byte(t.payload)),
		Collection:      t.participants,
		PublicSignature: "",
	}

	t.hasExtra = true

	pubTxExtra.add(KVExtraPrivateKey, privateRawData)

	if t.kvExtra != nil {
		for k, v := range t.kvExtra.data {
			var stringifyResult string
			if strings.EqualFold(k, KVExtraVersionKey) {
				continue
			}
			if str, ok := v.(string); ok {
				stringifyResult = str
			} else {
				value, err := json.Marshal(v)
				if err != nil {
					logger.Error(err)
					return
				}
				stringifyResult = string(value)
			}
			valHash := sha3ToHex([]byte(stringifyResult))
			pubTxExtra.add(k, valHash)
		}
	} else {
		t.kvExtra = NewKVExtra()
	}

	t.extra = pubTxExtra.Stringify()
	t.payload = ""

	pubSig := GenSinPub(key, needHashString(t))

	// --- create sig_pri ---
	extraBytesRaw := []byte(t.extra)

	// in order to keep the order of keys, we should operate on t.extra

	// reset private data
	extraBytesRaw, err := jsonparser.Set(extraBytesRaw, []byte(strconv.Quote(rawPayload)), KVExtraPrivateKey, KVExtraPrivatePayloadKey)
	if err != nil {
		panic(err)
	}

	extraBytesRaw, err = jsonparser.Set(extraBytesRaw, []byte(strconv.Quote(pubSig)), KVExtraPrivateKey, KVExtraPrivatePubSigKey)
	if err != nil {
		panic(err)
	}

	// reset kvExtra data
	for k, v := range t.kvExtra.data {
		var stringifyResult string
		if strings.EqualFold(k, KVExtraVersionKey) {
			continue
		}
		if str, ok := v.(string); ok {
			stringifyResult = str
		} else {
			value, err := json.Marshal(v)
			if err != nil {
				logger.Error(err)
				return
			}
			stringifyResult = string(value)
		}
		extraBytesRaw, err = jsonparser.Set(extraBytesRaw, []byte(strconv.Quote(stringifyResult)), k)
		if err != nil {
			panic(err)
		}
	}

	t.extra = string(extraBytesRaw)
}
