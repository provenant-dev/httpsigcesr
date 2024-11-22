package cesr

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to convert a hex string to a byte array
func hexToBytes(hexString string) []byte {
	bytes, err := hex.DecodeString(hexString)
	if err != nil {
		panic(err) // Hex string must be valid for tests
	}
	return bytes
}

func TestEncode(t *testing.T) {
	// Define test cases
	testCases := []struct {
		hex      string
		expected string
	}{
		{"01", "AAAB"},
		{"ff", "AAD_"},
		{"0102", "AAEC"},
		{"010203", "AQID"},
		{"01020304", "AAABAgME"},
		{"a6de92670a70d1731a580171ab44e6684ade40cd0e140ce2de5b6c80e8137a10", "AKbekmcKcNFzGlgBcatE5mhK3kDNDhQM4t5bbIDoE3oQ"},
	}

	// Run each test case
	for index, tc := range testCases {
		bytes := hexToBytes(tc.hex)
		result := Encode(bytes, "")

		if result != tc.expected {
			t.Errorf("Test case %d failed. Hex: %s, Expected: %s, Got: %s", index+1, tc.hex, tc.expected, result)
		}
	}
}

var TESTHex32 = "a6de92670a70d1731a580171ab44e6684ade40cd0e140ce2de5b6c80e8137a10"
var TESTBytes32 = hexToBytes(TESTHex32)
var TESTHex64 = "a6de92670a70d1731a580171ab44e6684ade40cd0e140ce2de5b6c80e8137a10a6de92670a70d1731a580171ab44e6684ade40cd0e140ce2de5b6c80e8137a10"
var TESTBytes64 = hexToBytes(TESTHex64)
var TESTCesr44 = "AKbekmcKcNFzGlgBcatE5mhK3kDNDhQM4t5bbIDoE3oQ"
var TESTCesr88 = Encode(TESTBytes64, "0D")

func TestDecodeBadPrefix(t *testing.T) {
	_, err := Decode("*" + TESTCesr44[:1])
	require.Error(t, err)
}

func TestDecodeShortButMultipleOf4(t *testing.T) {
	_, err := Decode(TESTCesr44[:len(TESTCesr44)-4])
	require.Error(t, err)
}

func TestDecodeNotMultipleOf4(t *testing.T) {
	_, err := Decode(TESTCesr44[:len(TESTCesr44)-1])
	require.Error(t, err)
}

func TestDecode44(t *testing.T) {
	for _, prefix := range strings.Split(ONECharPrefix44, "") {
		result, err := Decode(prefix + TESTCesr44[1:])
		require.NoError(t, err)
		assert.Equal(t, TESTBytes32, result)
	}
}

func TestDecode88(t *testing.T) {
	for _, char2 := range strings.Split(TWOCharPrefix88, "") {
		result, err := Decode("0" + char2 + TESTCesr88[2:])
		require.NoError(t, err)
		assert.Equal(t, TESTBytes64, result)
	}
}
