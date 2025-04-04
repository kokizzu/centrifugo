package main

func generateResponseEncoder() {
	generateToFile(headerResponseEncoder, templateFuncResponseEncoder, "internal/apiproto/encode_response_gen.go", nil, nil)
}

var headerResponseEncoder = `// Code generated by internal/gen/api/main.go. DO NOT EDIT.

package apiproto

import "encoding/json"

// JSONResponseEncoder ...
type JSONResponseEncoder struct{}

func NewJSONResponseEncoder() *JSONResponseEncoder {
	return &JSONResponseEncoder{}
}
`

var templateFuncResponseEncoder = `
// Encode{{ .RequestCapitalized }} ...
func (e *JSONResponseEncoder) Encode{{ .RequestCapitalized }}(response *{{ .RequestCapitalized }}Response) ([]byte, error) {
	return json.Marshal(response)
}
`
