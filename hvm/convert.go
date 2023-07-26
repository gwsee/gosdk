package hvm

import (
	"reflect"
)

func Convert(fc interface{}) interface{} {

	t := reflect.TypeOf(fc)
	s := reflect.ValueOf(fc)
	var result []interface{}
	if reflect.TypeOf(fc).Kind() == reflect.Struct {
		result = make([]interface{}, t.NumField())
	} else {
		result = make([]interface{}, s.Len())
	}

	switch reflect.TypeOf(fc).Kind() {
	case reflect.Map:

		keys := s.MapKeys()
		for i, key := range keys {
			keyVal := key.String()
			ret := Convert(s.MapIndex(key).Interface())
			result[i] = []interface{}{keyVal, ret}
		}
	case reflect.Slice:

		for i := 0; i < s.Len(); i++ {
			ret := Convert(s.Index(i).Interface())
			result[i] = ret

		}
	case reflect.Array:

		for i := 0; i < s.Len(); i++ {
			ret := Convert(s.Index(i).Interface())
			result[i] = ret
		}
	case reflect.Struct:
		result = make([]interface{}, t.NumField())
		for i := 0; i < t.NumField(); i++ {
			value := s.Field(i).Interface()
			result[i] = Convert(value)
		}
	default:
		return reflect.ValueOf(fc).String()
	}
	return result
}
