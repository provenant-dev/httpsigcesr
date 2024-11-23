package httpclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"github.com/Wavecrest/httpsigcesr/digest"
	"github.com/Wavecrest/httpsigcesr/signature"
	"net/http"
)

var (
	signatureFields = []string{"@method", "@path", "origin-date", "signify-resource"}
)

type CserSignedClient struct {
	privateKey ed25519.PrivateKey
	publicKey  string
}

func NewCserSignedClient(publicKey string, privateKey ed25519.PrivateKey) *CserSignedClient {
	return &CserSignedClient{
		privateKey: privateKey,
		publicKey:  publicKey,
	}
}

func (csc *CserSignedClient) SendSignedRequest(c context.Context, method string, url string, body interface{}) (*http.Response, error) {
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader := bytes.NewReader(bodyBytes)
	req, err := http.NewRequestWithContext(c, method, url, bodyReader)
	if err != nil {
		return nil, err
	}
	err = digest.AddDigest(req, digest.DigestSha256, bodyBytes)
	if err != nil {
		return nil, err
	}
	if len(bodyBytes) >= 0 {
		req.Header.Add("Content-Type", "application/json")
	}

	req.Header.Add("signify-resource", csc.publicKey)

	signatureData := signature.NewSignatureData(signatureFields, csc.publicKey, csc.privateKey)
	err = signatureData.SignRequest(req)

	client := &http.Client{}
	return client.Do(req)
}
