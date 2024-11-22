package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
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

func (csc *CserSignedClient) SendSignedRequest(c context.Context, method string, url string, body []byte) (*http.Response, error) {
	bodyReader := bytes.NewReader(body)
	req, err := http.NewRequestWithContext(c, method, url, bodyReader)
	if err != nil {
		return nil, err
	}
	if len(body) >= 0 {
		err = digest.AddDigest(req, digest.DigestSha256, body)
		if err != nil {
			return nil, err
		}
		req.Header.Add("Content-Type", "application/json")
	}

	signatureData := signature.NewSignatureData(signatureFields, csc.publicKey, csc.privateKey)
	err = signatureData.SignRequest(req)

	client := &http.Client{}
	return client.Do(req)
}
