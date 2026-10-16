package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

func decodeProfileIdentityMode(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", nil
	}
	var mode string
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, &mode) != nil || (mode != "" && mode != "preserve") {
		return "", fmt.Errorf("identity_mode must be empty or preserve")
	}
	return mode, nil
}

func decodeDuplicateName(body io.Reader) (*string, error) {
	decoder := json.NewDecoder(body)
	var fields map[string]json.RawMessage
	if err := decoder.Decode(&fields); err != nil {
		if err == io.EOF {
			return nil, nil
		}
		return nil, fmt.Errorf("duplicate options must be an object")
	}
	if fields == nil {
		return nil, fmt.Errorf("duplicate options must be an object")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("duplicate options must contain one object")
	}
	for key := range fields {
		if key != "name" {
			return nil, fmt.Errorf("duplicate options only support name")
		}
	}
	raw, present := fields["name"]
	if !present {
		return nil, nil
	}
	var name string
	if json.Unmarshal(raw, &name) != nil || !utf8.ValidString(name) || strings.TrimSpace(name) == "" || utf8.RuneCountInString(name) > 120 || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return nil, fmt.Errorf("duplicate name must contain 1 to 120 printable characters")
	}
	return &name, nil
}
