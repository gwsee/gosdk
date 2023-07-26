package guomi

/*
#cgo CFLAGS : -I./include -I/usr/local/include -I/usr/include
#cgo LDFLAGS: -L/usr/local/lib -L/usr/lib -L/usr/lib -lssl -lcrypto
#include <stdlib.h>
#include "./include/sm3.h"
#include "./crypto/sm3/sm3.c"
#include "./crypto/err/err.h"
#include "./crypto/err/err.c"

*/
import "C"

import (
	"hash"
	"unsafe"
)

/**
sm3_hash
this context implements the hash.Hash interface
*/
type sm3ctx struct {
	ctx C.sm3_ctx_t
}

func New() hash.Hash {
	h := new(sm3ctx)
	C.sm3_init(&h.ctx)
	return h
}

func clone(src *sm3ctx) *sm3ctx {
	sm3 := new(sm3ctx)
	sm3.ctx = src.ctx
	return sm3
}

func (self *sm3ctx) Write(msg []byte) (n int, err error) {
	size := C.size_t(len(msg))
	val := (*C.uchar)(unsafe.Pointer(C.CString(string(msg))))
	defer C.free(unsafe.Pointer(val))
	C.sm3_update(&self.ctx, val, size)
	return len(msg), nil
}

func (self *sm3ctx) Sum(b []byte) []byte {
	buf := make([]C.uchar, self.Size())
	ctxTmp := clone(self)
	C.sm3_final(&ctxTmp.ctx, &buf[0])
	var result []byte
	if b != nil {
		result = make([]byte, 0)
	} else {
		result = b
	}
	for _, value := range buf {
		result = append(result, byte(value))
	}
	return result
}

func (self *sm3ctx) Reset() {
	C.sm3_init(&self.ctx)
}

func (self *sm3ctx) Size() int {
	return C.SM3_DIGEST_LENGTH
}

func (self *sm3ctx) BlockSize() int {
	return C.SM3_BLOCK_SIZE
}
