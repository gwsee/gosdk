package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"errors"
)

// DES encrypt
func DesEncrypt(data, key []byte) ([]byte, error) {
	if len(key) < 8 {
		key = ZeroPadding(key, 8)
	} else {
		key = key[0:8]
	}
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	data = PKCS5Padding(data, bs)
	if len(data)%bs != 0 {
		return nil, errors.New("need a multiple of the block size")
	}
	out := make([]byte, len(data))
	dst := out
	for len(data) > 0 {
		block.Encrypt(dst, data[:bs])
		data = data[bs:]
		dst = dst[bs:]
	}
	return out, nil
}

// DES decrypt
func DesDecrypt(data []byte, key []byte) ([]byte, error) {
	if len(key) < 8 {
		key = ZeroPadding(key, 8)
	} else {
		key = key[0:8]
	}
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	if len(data)%bs != 0 {
		return nil, errors.New("crypto/cipher: input not full blocks")
	}
	out := make([]byte, len(data))
	dst := out
	for len(data) > 0 {
		block.Decrypt(dst, data[:bs])
		data = data[bs:]
		dst = dst[bs:]
	}
	out = PKCS5UnPadding(out)
	return out, nil
}

// AES encrypt
func AesEncrypt(origData, key []byte) ([]byte, error) {
	key = aesPassPadding(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	origData = PKCS5Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

// AES decrypt
func AesDecrypt(crypted, key []byte) ([]byte, error) {
	key = aesPassPadding(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS5UnPadding(origData)
	return origData, nil
}

// 3DES encryption algorithm implements
func TripleDesEnc(src, key []byte) ([]byte, error) {
	key = tdesPassPadding(key)
	block, err := des.NewTripleDESCipher(key[:24])
	if err != nil {
		return nil, err
	}
	msg := PKCS5Padding(src, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, key[:block.BlockSize()])
	crypted := make([]byte, len(msg))
	blockMode.CryptBlocks(crypted, msg)
	return crypted, nil
}

// 3DES decryption algorithm implements
func TripleDesDec(src, key []byte) ([]byte, error) {
	key = tdesPassPadding(key)
	block, err := des.NewTripleDESCipher(key[:24])
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, key[:block.BlockSize()])
	origData := make([]byte, len(src))
	blockMode.CryptBlocks(origData, src)
	origData = PKCS5UnPadding(origData)
	return origData, nil
}

// PKCS5 or PKCS7
func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// PKCS5 or PKCS7
func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	// 去掉最后一个字节 unpadding 次
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func ZeroPadding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{48}, padding)
	return append(ciphertext, padtext...)
}

func ZeroUnPadding(origData []byte) []byte {
	return bytes.TrimRightFunc(origData, func(r rune) bool {
		return r == rune(0)
	})
}

// triple des password need 192 bits | 24 bytes
// append right byte of '@'
func tdesPassPadding(origData []byte) []byte {
	padByte := byte('@')
	passLen := len(origData)
	result := origData
	if passLen < 24 {
		result = RightPadding(origData, 24, padByte)
	} else if passLen > 24 {
		result = origData[:24]
	}
	return result
}

// AES password need 128/192/256 bits | 16/24/32 bytes
// append right byte of '@'
func aesPassPadding(origData []byte) []byte {
	padByte := byte('@')
	passLen := len(origData)
	result := origData
	if passLen < 32 {
		result = RightPadding(origData, 32, padByte)
	} else if passLen > 32 {
		result = origData[:32]
	}
	return result
}

// RightPadding pad byte to length
func RightPadding(origData []byte, length int, pad byte) []byte {
	padBytes := make([]byte, length-len(origData))
	for i := 0; i < len(padBytes); i++ {
		padBytes[i] = pad
	}
	return append(origData, padBytes...)
}
