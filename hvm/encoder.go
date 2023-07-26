package hvm

import (
	"errors"
	"github.com/gwsee/gosdk/common"
)

// | class length(4B) | name length(2B) | class | class name | bin |
func GenPayload(beanAbi *BeanAbi, params ...interface{}) ([]byte, error) {
	classBytes := beanAbi.classBytes()

	if len(classBytes) > 0xffff {
		return nil, errors.New("the bean class is too large") // 64k
	}

	beanName := []byte(beanAbi.BeanName)
	isJson := true
	for _, str := range params {
		if _, ok := str.(string); !ok {
			isJson = false
			break
		}
	}
	var bin string
	var err error
	if isJson {
		bin, err = beanAbi.encodeJson(params...)

	} else {
		bin, err = beanAbi.encode(params...)
	}

	if err != nil {
		return nil, err
	}
	binBytes := []byte(bin)

	result := make([]byte, 0)
	classLenByte := common.IntToBytes4(len(classBytes))
	nameLenByte := common.IntToBytes2(len(beanName))
	result = append(result, classLenByte[:]...)
	result = append(result, nameLenByte[:]...)
	result = append(result, classBytes...)
	result = append(result, beanName...)
	result = append(result, binBytes...)

	return result, nil
}
