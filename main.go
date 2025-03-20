package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"unicode"

	"gopkg.in/yaml.v2"
	"github.com/golang-jwt/jwt/v5"
)

type secret map[string]interface{}

type items struct {
    Items   []secret `yaml:"items"`
}

type decodedSecret struct {
	Key   string
	Value interface{}
}

type decodedJwt struct {
	Header interface{}
	Payload interface{}
	Signature string
}

var version string

func main() {
	if len(os.Args) == 2 && os.Args[1] == "version" {
		_, _ = fmt.Fprintf(os.Stdout, "ksd version %s\n", version)
		return
	}
	info, err := os.Stdin.Stat()
	if err != nil {
		panic(err)
	}

	if (info.Mode()&os.ModeCharDevice) != 0 || info.Size() < 0 {
		_, _ = fmt.Fprintln(os.Stderr, "the command is intended to work with pipes.")
		_, _ = fmt.Fprintln(os.Stderr, "usage: kubectl get secret <secret-name> -o <yaml|json> |", os.Args[0])
		_, _ = fmt.Fprintln(os.Stderr, "usage:", os.Args[0], "< secret.<yaml|json>")
		os.Exit(1)
	}

	stdin := read(os.Stdin)
	output, err := parse(stdin)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "could not decode secret: %v\n", err)
		os.Exit(1)
	}
	_, _ = fmt.Fprint(os.Stdout, string(output))
}

func cast(data interface{}, isJSON bool) (secret, bool) {
	if isJSON {
		d, ok := data.(map[string]interface{})
		return d, ok
	}

	parsed, ok := data.(map[interface{}]interface{})
	if !ok {
		return nil, false
	}
	d := make(map[string]interface{}, len(parsed))
	for key, value := range parsed {
		d[key.(string)] = value
	}
	return d, true
}

func parse(in []byte) ([]byte, error) {
	isJSON := isJSONString(in)

	var it items
	if err := unmarshal(in, &it, isJSON); err == nil && len(it.Items) > 0 {
		for i := 0; i < len(it.Items); i++ {
			decodeItem(&it.Items[i], isJSON)
		}
		return marshal(it, isJSON)
	}

	var s secret
	if err := unmarshal(in, &s, isJSON); err != nil {
		return nil, err
	}
	decodeItem(&s, isJSON)
	return marshal(s, isJSON)
}

func decodeItem(item *secret, isJSON bool) bool {
	data, ok := cast((*item)["data"], isJSON)
	if !ok || len(data) == 0 {
		return false
	}
	(*item)["data"] = decode(data)
	return true
}

func read(rd io.Reader) []byte {
	var output []byte
	reader := bufio.NewReader(rd)
	for {
		input, err := reader.ReadByte()
		if err != nil && err == io.EOF {
			break
		}
		output = append(output, input)
	}
	return output
}

func unmarshal(in []byte, out interface{}, asJSON bool) error {
	if asJSON {
		return json.Unmarshal(in, out)
	}
	return yaml.Unmarshal(in, out)
}

func marshal(d interface{}, asJSON bool) ([]byte, error) {
	if asJSON {
		return json.MarshalIndent(d, "", "    ")
	}
	return yaml.Marshal(d)
}

func isAsciiPrintable(s string) bool {
    for _, r := range s {
        if r > unicode.MaxASCII || (!unicode.IsPrint(r) && !unicode.IsSpace(r)) {
            return false
        }
    }
    return true
}

func decodeSecret(key, secret string, secrets chan decodedSecret) {
	value := secret
	// avoid wrong encoded secrets
	if decoded, err := base64.StdEncoding.DecodeString(secret); err == nil && isAsciiPrintable(string(decoded)) {
		value = string(decoded)

		var claims jwt.MapClaims
		parser := jwt.NewParser()
		token, _, err := parser.ParseUnverified(value, &claims)
		if err == nil {
			valuej := decodedJwt{Header: token.Header, Payload: token.Claims, Signature: string(token.Signature)}
			secrets <- decodedSecret{Key: key, Value: valuej}
			return
		}
	} else {
	}
	secrets <- decodedSecret{Key: key, Value: value}
}

func decode(data map[string]interface{}) map[string]interface{} {
	length := len(data)
	secrets := make(chan decodedSecret, length)
	decoded := make(map[string]interface{}, length)
	for key, encoded := range data {
		go decodeSecret(key, encoded.(string), secrets)
	}
	for i := 0; i < length; i++ {
		secret := <-secrets
		decoded[secret.Key] = secret.Value
	}
	return decoded
}

func isJSONString(s []byte) bool {
	return json.Unmarshal(s, &json.RawMessage{}) == nil
}
