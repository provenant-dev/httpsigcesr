package httpclient

import (
	"context"
	"net/http"
)

type HttpClient interface {
	SendSignedRequest(c context.Context, method string, url string, body interface{}) (*http.Response, error)
}
