package guomi

/*
#cgo CFLAGS : -I./include -I/usr/local/include -I/usr/include -I/include -I/lib/local/ssl/include -I/usr/local/opt/openssl/include
#cgo LDFLAGS: -lssl -lcrypto -ldl

#include <openssl/opensslconf.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include "./include/ossl_typ.h"
#include "./include/ecdsa.h"
#include "./include/ecdh.h"
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include "./crypto/sm2/obj_mac.h"
#include "./crypto/sm2/sm2.h"
#include "./crypto/sm3/sm3.h"
#include "./crypto/sm2/sm2.c"
#include "./crypto/sm2/kdf.h"

*/
import "C"

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"github.com/gwsee/gosdk/common"
	"math/big"
	"unsafe"
)

/**
sm2_sign_verify
*/

type Curve int16

type PublicKey struct {
	Curve
	X, Y []byte
}

type PrivateKey struct {
	PublicKey
	Key []byte
}

func NewPubKey(x, y []byte) *PublicKey {
	sm2p256v1 := Curve(C.NID_sm2p256v1)
	key := new(PublicKey)
	key.X = x
	key.Y = y
	key.Curve = sm2p256v1
	return key
}

func ParsePriKeyFromDER(curve Curve, der []byte) (*PrivateKey, error) {
	sm2p256v1 := Curve(103)
	curve = sm2p256v1
	prkInfo := struct {
		Version       int
		PrivateKey    []byte
		NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
		PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
	}{}
	_, err := asn1.Unmarshal(der, &prkInfo)
	if err != nil {
		return nil, err
	}
	raw := prkInfo.PrivateKey
	key := new(PrivateKey)

	key.Curve = curve
	key.Key = raw
	k := C.EC_KEY_new_group()
	defer C.EC_KEY_free(k)

	// private key
	priv_key := C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&key.Key[0])),
		C.int(len(key.Key)), nil)
	defer C.BN_free(priv_key)
	//---------------
	pub_key_x := C.BN_new()
	defer C.BN_free(pub_key_x)
	pub_key_y := C.BN_new()
	defer C.BN_free(pub_key_y)

	group := C.sm2_ec_group()
	pub_key := C.EC_POINT_new(group)
	defer C.EC_POINT_free(pub_key)

	// the actual step which does the conversion from private to public key
	if C.EC_POINT_mul(group, pub_key, priv_key, nil, nil, nil) == C.int(0) {
		return nil, errors.New("EC_POINT_mul error")
	}
	if C.EC_KEY_set_private_key(k, priv_key) == C.int(0) {
		return nil, errors.New("EC_KEY_set_private_key")
	}
	if C.EC_KEY_set_public_key(k, pub_key) == C.int(0) {
		return nil, errors.New("EC_KEY_set_public_key")
	}
	// get X and Y coords from pub_key
	if C.EC_POINT_get_affine_coordinates_GFp(group, pub_key, pub_key_x,
		pub_key_y, nil) == C.int(0) {
		return nil, errors.New("EC_POINT_get_affine_coordinates_GFp")
	}
	key.PublicKey.X = make([]byte, C.BN_num_bytes_not_a_macro(pub_key_x))
	key.PublicKey.Y = make([]byte, C.BN_num_bytes_not_a_macro(pub_key_y))
	C.BN_bn2bin(pub_key_x, (*C.uchar)(unsafe.Pointer(&key.PublicKey.X[0])))
	C.BN_bn2bin(pub_key_y, (*C.uchar)(unsafe.Pointer(&key.PublicKey.Y[0])))
	return key, nil
}

func ParsePublicKeyByDerEncode(curve Curve, der []byte) (*PublicKey, error) {
	//fmt.Println(der)
	sm2p256v1 := Curve(C.NID_sm2p256v1)
	curve = sm2p256v1
	pukInfo := struct {
		Raw       asn1.RawContent
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{}
	_, err := asn1.Unmarshal(der, &pukInfo)
	if err != nil {
		return nil, err
	}
	raw := pukInfo.PublicKey.Bytes
	if raw[0] != byte(0x04) || len(raw)%2 != 1 {
		return nil, errors.New("not uncompressed format")
	}
	raw = raw[1:]
	intLength := int(len(raw) / 2)
	key := new(PublicKey)
	key.Curve = curve
	key.X = make([]byte, intLength)
	key.Y = make([]byte, intLength)
	copy(key.X, raw[:intLength])
	copy(key.Y, raw[intLength:])
	return key, nil
}

func ParsePublicKeyByEncode(der []byte) (*PublicKey, error) {
	//sm2p256v1 := Curve(C.NID_sm2p256v1)
	//curve := sm2p256v1
	raw := der
	if raw[0] != byte(0x04) || len(raw)%2 != 1 {
		return nil, errors.New("public key not uncompressed format, please check your public key format.")
	}
	raw = raw[1:]
	intLength := int(len(raw) / 2)
	key := new(PublicKey)
	//key.Curve = curve
	key.X = make([]byte, intLength)
	key.Y = make([]byte, intLength)
	copy(key.X, raw[:intLength])
	copy(key.Y, raw[intLength:])
	return key, nil
}

func GetEC_KEY(curve Curve, pubkey *PublicKey, privkey *PrivateKey) (*C.EC_KEY, error) {
	// initialization
	sm2p256v1 := Curve(C.NID_sm2p256v1)
	curve = sm2p256v1
	key := C.EC_KEY_new_group()
	if key == nil {
		return nil, errors.New("EC_KEY_new_by_curve_name")
	}
	// convert bytes to BIGNUMs
	pub_key_x := C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&pubkey.X[0])),
		C.int(len(pubkey.X)), nil)
	defer C.BN_free(pub_key_x)
	pub_key_y := C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&pubkey.Y[0])),
		C.int(len(pubkey.Y)), nil)
	defer C.BN_free(pub_key_y)
	// also add private key if it exists
	if privkey != nil {
		priv_key := C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&privkey.Key[0])),
			C.int(len(privkey.Key)), nil)
		defer C.BN_free(priv_key)
		if C.EC_KEY_set_private_key(key, priv_key) == C.int(0) {
			return nil, errors.New("EC_KEY_set_private_key")
		}
	}
	group := C.EC_KEY_get0_group(key)
	pub_key := C.EC_POINT_new(group)
	defer C.EC_POINT_free(pub_key)
	// set coordinates to get pubkey and then set pubkey
	if C.EC_POINT_set_affine_coordinates_GFp(group, pub_key, pub_key_x,
		pub_key_y, nil) == C.int(0) {
		return nil, errors.New("EC_POINT_set_affine_coordinates_GFp")
	}
	if C.EC_KEY_set_public_key(key, pub_key) == C.int(0) {
		return nil, errors.New("EC_KEY_set_public_key")
	}
	// validate the key
	if C.EC_KEY_check_key(key) == C.int(0) {
		return nil, errors.New("EC_KEY_check_key")
	}
	return key, nil
}

func (key *PrivateKey) Sign(dgst []byte) ([]byte, error) {
	ec_key, err := GetEC_KEY(key.Curve, &key.PublicKey, key)
	defer C.EC_KEY_free(ec_key)
	if err != nil {
		return nil, err
	}
	//sig :=  (*C.uchar)(C.malloc(256))
	sigLen := C.uint(256)
	sig := make([]byte, 256)
	dst := make([]byte, len(dgst))
	copy(dst, dgst)
	pid := C.SM2_sign(C.NID_undef, (*C.uchar)(unsafe.Pointer(&dst[0])), C.SM3_DIGEST_LENGTH, (*C.uchar)(unsafe.Pointer(&sig[0])), &sigLen, ec_key)
	if pid == 1 {
		return sig[:sigLen], nil
	}
	return nil, errors.New("Signature failed")

}

func (key *PublicKey) VerifySignature(sig, dgst []byte) (bool, error) {
	ec_key, err := GetEC_KEY(key.Curve, key, nil)
	defer C.EC_KEY_free(ec_key)
	if err != nil {
		return false, err
	}
	bol := C.SM2_verify(C.NID_undef, (*C.uchar)(unsafe.Pointer(&dgst[0])), C.int(len(dgst)), (*C.uchar)(unsafe.Pointer(&sig[0])), C.int(len(sig)), ec_key)

	if bol == 1 {
		return true, nil
	}

	return false, errors.New("invaild signature!")
}

func (key *PublicKey) GetRaw() (string, error) {
	var hexX []byte
	bigy := common.BytesToBig(key.Y)
	if new(big.Int).Mod(bigy, big.NewInt(2)).Int64() == 1 {
		hexX = append([]byte{3}, key.X...)
	} else {
		hexX = append([]byte{2}, key.X...)
	}
	return common.ToHex(hexX), nil
}

func GetPriKeyFromHex(pri []byte) (*PrivateKey, error) {
	key := new(PrivateKey)
	key.Curve = Curve(1)
	key.Key = pri
	k := C.EC_KEY_new_group()
	defer C.EC_KEY_free(k)

	// private key
	priv_key := C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&key.Key[0])),
		C.int(len(key.Key)), nil)
	defer C.BN_free(priv_key)
	//---------------
	pub_key_x := C.BN_new()
	defer C.BN_free(pub_key_x)
	pub_key_y := C.BN_new()
	defer C.BN_free(pub_key_y)

	group := C.sm2_ec_group()
	pub_key := C.EC_POINT_new(group)
	defer C.EC_POINT_free(pub_key)

	// the actual step which does the conversion from private to public key
	if C.EC_POINT_mul(group, pub_key, priv_key, nil, nil, nil) == C.int(0) {
		return nil, errors.New("EC_POINT_mul error")
	}
	if C.EC_KEY_set_private_key(k, priv_key) == C.int(0) {
		return nil, errors.New("EC_KEY_set_private_key")
	}
	if C.EC_KEY_set_public_key(k, pub_key) == C.int(0) {
		return nil, errors.New("EC_KEY_set_public_key")
	}
	// get X and Y coords from pub_key
	if C.EC_POINT_get_affine_coordinates_GFp(group, pub_key, pub_key_x,
		pub_key_y, nil) == C.int(0) {
		return nil, errors.New("EC_POINT_get_affine_coordinates_GFp")
	}
	key.PublicKey.X = make([]byte, C.BN_num_bytes_not_a_macro(pub_key_x))
	key.PublicKey.Y = make([]byte, C.BN_num_bytes_not_a_macro(pub_key_y))
	C.BN_bn2bin(pub_key_x, (*C.uchar)(unsafe.Pointer(&key.PublicKey.X[0])))
	C.BN_bn2bin(pub_key_y, (*C.uchar)(unsafe.Pointer(&key.PublicKey.Y[0])))
	return key, nil
}

func GetPubKeyFromPri(pri *PrivateKey) []byte {
	return bytes.Join([][]byte{{4}, common.LeftPadBytes(pri.X, 32), common.LeftPadBytes(pri.Y, 32)}, nil)
}

//有问题弃用
func uncompressedPubkey(pub []byte) []byte {
	x := common.BytesToBig(pub[1:33])

	a := common.Bytes2Big(common.Hex2Bytes("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"))
	b := common.Bytes2Big(common.Hex2Bytes("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"))
	p := common.Bytes2Big(common.Hex2Bytes("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"))

	//x^3
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)

	//ax
	ax := new(big.Int).Mul(a, x)

	//x^3+ax+b
	x3.Add(x3, ax)
	x3.Add(x3, b)

	//sqrt y^2
	y := x3.ModSqrt(x3, p)

	if new(big.Int).Mod(y, big.NewInt(2)).Int64() == 0 {
		fmt.Println("y is odd")
	} else {
		fmt.Println("y is even")
	}
	fmt.Println("BigtoBytes:", y.Bytes())

	return BigToBytes(y, 256)
}

func UncompressedPubkeyOpenssl(pubStr string) ([]byte, error) {
	pub := common.FromHex(pubStr)

	hexPrefix := 0
	if pubStr[0:2] == "0x" {
		hexPrefix = 2
	}

	if len(pub) != 33 {
		return nil, fmt.Errorf("lenth of publick key is insufficient: want 66 but get %v", len(pubStr)-hexPrefix)
	}

	pubX := pub[1:]

	y1 := make([]byte, 32)
	y0 := make([]byte, 32)
	C.SM2_calcy_interface((*C.uchar)(unsafe.Pointer(&pubX[0])), (*C.uchar)(unsafe.Pointer(&y1[0])))
	C.SM2_calcy_interface_0((*C.uchar)(unsafe.Pointer(&pubX[0])), (*C.uchar)(unsafe.Pointer(&y0[0])))

	switch pub[0] {
	case 2:
		if new(big.Int).Mod(common.Bytes2Big(y1), big.NewInt(2)).Int64() == 0 {
			return y1, nil
		}
		if new(big.Int).Mod(common.Bytes2Big(y0), big.NewInt(2)).Int64() == 0 {
			return y0, nil
		}
	case 3:
		if new(big.Int).Mod(common.Bytes2Big(y1), big.NewInt(2)).Int64() == 1 {
			return y1, nil
		}
		if new(big.Int).Mod(common.Bytes2Big(y0), big.NewInt(2)).Int64() == 1 {
			return y0, nil
		}
	default:
		return nil, errors.New("Not matched public key format")
	}
	return nil, errors.New("Cannot Uncompressed Public key!")
}

func BigToBytes(num *big.Int, base int) []byte {
	ret := make([]byte, base/8)

	if len(num.Bytes()) > base/8 {
		return num.Bytes()
	}

	return append(ret[:len(ret)-len(num.Bytes())], num.Bytes()...)
}
