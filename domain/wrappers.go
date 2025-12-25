package domain

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"
)

type AuthInputWrapper struct {
	orig any
}

func (w *AuthInputWrapper) Original() any {
	return w.orig
}

func (w *AuthInputWrapper) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, w.orig)
}

// PayloadType contains type of customized jwt token payload
// Payload can create PayloadWrapper of its type with method NewPayloadWrapper
type PayloadType struct {
	t reflect.Type
}

// NewPayloadType saves objects type to PayloadType
// obj should be struct, not pointer
func NewPayloadType(obj any) PayloadType {
	t := reflect.TypeOf(obj)
	if t.Kind() != reflect.Struct {
		panic("TypeWrapper only supports structs")
	}
	return PayloadType{t: t}
}

// PayloadWrapper contains customized user's payload structure and token expire time
// PayloadWrapper is used as jwt token payload and has custom Masrshal/Unmarshal json methods
type PayloadWrapper struct {
	// Orig is a pointer to Payload ( user's ) structure
	orig any
	// Expire at contains jwt token expire time
	ExpireAt time.Time `json:"exp"`
}

// New creates PayloadWrapper based on PayloadType's saved type
func (pt *PayloadType) New() PayloadWrapper {
	orig := reflect.New(pt.t).Interface()
	return PayloadWrapper{
		orig:     orig,
		ExpireAt: time.Time{},
	}
}

// Marshals original structure's fields by `json` struct tag, and if not exitst by Name ( only exported fields )
// it also adds ExpireAt field at key: "exp"
func (pw *PayloadWrapper) MarshalJSON() ([]byte, error) {
	m := make(map[string]any)

	v := reflect.ValueOf(pw.orig)
	t := reflect.TypeOf(pw.orig)
	if t.Kind() == reflect.Ptr {
		v = v.Elem()
		t = t.Elem()
	}

	for i := range t.NumField() {
		f := t.Field(i)
		if f.PkgPath != "" {
			continue
		}
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		if tag := f.Tag.Get("json"); tag != "" {
			m[tag] = v.Field(i).Interface()
		} else {
			m[f.Name] = v.Field(i).Interface()
		}
	}

	m["exp"] = pw.ExpireAt

	return json.Marshal(m)
}

// Unmarshals json to original structure by `json` struct tag, and if not exitst by Name ( only exported fields )
// it also retrieves ExpireAt field at key: "exp"
func (pw *PayloadWrapper) UnmarshalJSON(data []byte) error {
	raw := make(map[string]json.RawMessage)

	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	if pw.orig == nil {
		return errors.New("Orig is nil")
	}

	v := reflect.ValueOf(pw.orig)
	if v.Kind() != reflect.Ptr || v.Elem().Kind() != reflect.Struct {
		return errors.New("Orig must be pointer to struct")
	}

	v = v.Elem()
	t := v.Type()

	for i := range t.NumField() {
		f := t.Field(i)
		if f.PkgPath != "" {
			continue
		}
		name := f.Name
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		if tag := f.Tag.Get("json"); tag != "" {
			name = strings.Split(tag, ",")[0]
		}

		msg, ok := raw[name]

		if !ok {
			continue
		}

		if err := json.Unmarshal(msg, v.Field(i).Addr().Interface()); err != nil {
			return err
		}

	}

	rawExp, ok := raw["exp"]
	if !ok {
		return errors.New("no exp field when unmarshaling")
	}

	return json.Unmarshal(rawExp, &pw.ExpireAt)
}
