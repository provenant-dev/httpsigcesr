package signature

import (
	"net/http"
	"testing"
)

func TestSignatureInput(t *testing.T) {
	// Define test cases
	testCases := []struct {
		fields   []string
		public   string
		expected string
	}{
		{[]string{"@method", "@path", "origin-date", "signify-resource"}, "public", "(\"@method\" \"@path\" \"origin-date\" \"signify-resource\");created=1618884475;keyid=\"public\";alg=\"ed25519\""},
	}

	// Run each test case
	for index, tc := range testCases {
		sd := NewSignatureData(tc.fields, tc.public, nil)
		sd.created = 1618884475
		result := sd.SignatureInput()

		if result != tc.expected {
			t.Errorf("Test case %d failed. Expected: %s, Got: %s", index+1, tc.expected, result)
		}
	}
}

func Test_evaulateField(t *testing.T) {
	// Define test cases
	testCases := []struct {
		field    string
		expected string
	}{
		{"@method", "GET"},
		{"@path", "/"},
		{"origin-date", "2021-04-20T20:21:15Z"},
		{"signify-resource", "public"},
	}

	// Run each test case
	for index, tc := range testCases {
		sd := NewSignatureData([]string{"@method", "@path", "origin-date", "signify-resource"}, "public", nil)
		r, _ := http.NewRequest("GET", "/", nil)
		r.Header.Add("origin-date", "2021-04-20T20:21:15Z")
		result, err := sd.evaluateField(tc.field, r)

		if err != nil {
			t.Errorf("Test case %d failed. Expected: %s, Got: %s", index+1, tc.expected, result)
		}
	}
}
