package cesr

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const ONECharPrefix44 = "ABCDEFGHIJOQZ"
const TWOCharPrefix88 = "BCDEFGI"

func Encode(bytes []byte, prefix string) string {
	// Calculate padding needed to align to a 3-byte boundary.
	padCount := (3 - (len(bytes) % 3)) % 3

	// Create a padded array and copy the input bytes with the padding.
	padded := make([]byte, padCount+len(bytes))
	copy(padded[padCount:], bytes)

	// Convert the padded array to a Base64 string, then make it URL-safe.
	b64url := base64.RawURLEncoding.EncodeToString(padded)

	// Compose the self-describing CESR primitive by combining the prefix
	// with the encoded bytes. Replace part of the left padding with the prefix.
	return prefix + b64url[len(prefix):]
}

func Decode(cesr string) ([]byte, error) {
	if len(cesr)%4 != 0 {
		return nil, errors.New("invalid CESR length")
	}

	if cesr[0] == '0' && strings.Contains(TWOCharPrefix88, string(cesr[1])) {
		return decodeWithLen(cesr, 88, 2)
	}

	if strings.Contains(ONECharPrefix44, string(cesr[0])) {
		return decodeWithLen(cesr, 44, 1)
	}

	return nil, errors.New("unsupported CESR prefix")
}

func decodeWithLen(cesr string, totalLen int, prefixLen int) ([]byte, error) {
	prefix := cesr[:prefixLen]
	if len(cesr) != totalLen {
		return nil, errors.New("expected length " + fmt.Sprint(totalLen) + " for prefix " + prefix + ", got " + fmt.Sprint(len(cesr)))
	}

	cesr = strings.Repeat("A", prefixLen) + cesr[prefixLen:]
	decodedBytes, err := decodeBase64Url(cesr)
	if err != nil {
		return nil, err
	}

	padCount := 1
	if totalLen == 88 {
		padCount = 2
	}

	return decodedBytes[padCount:], nil
}

func decodeBase64Url(str string) ([]byte, error) {
	base64Str := strings.ReplaceAll(str, "-", "+")
	base64Str = strings.ReplaceAll(base64Str, "_", "/")
	for len(base64Str)%4 != 0 {
		base64Str += "="
	}

	return base64.StdEncoding.DecodeString(base64Str)
}
