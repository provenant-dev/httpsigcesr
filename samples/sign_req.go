package main

import (
	"context"
	"encoding/pem"
	"fmt"
	"github.com/Wavecrest/httpsigcesr/httpclient"
	"os"
	"io"
	"net/http"
)

func readPemFile(fileName string) ([]byte, error) {
	// Step 1: Read the file contents
	pemData, err := os.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	// Step 2: Decode the PEM block
	block, _ := pem.Decode(pemData)
	if block == nil {
		fmt.Println("Failed to parse PEM block")
		os.Exit(1)
	}
	return block.Bytes, nil
}

type OriginRequest struct {
	Orig      string `json:"orig"`
	Dest      string `json:"dest"`
	Evd       string `json:"evd"`
	OrigID    string `json:"origid"`
	RequestID string `json:"request_id"`
}

func main() {
   
   // get args
      var fromId string
      var toId   string

   if len( os.Args ) == 3 {
      fromId = os.Args[1]
      toId   = os.Args[2]
   }

   if (len(toId) == 0) && (len(fromId) == 0) {
		toId   = "+17035550001"
		fromId = "+15715550000"
   }
   fmt.Println( "using from and to:", fromId, toId )


	//read PEM file from disk
	privKeyPath := os.Getenv("PRIVATE_KEY_PATH")
	if privKeyPath == "" {
		privKeyPath = "/etc/kamailio/privkey.pem" // Default path
	}
	privKey, err := readPemFile(privKeyPath)
	if err != nil {
		fmt.Println("Error reading PEM file")
		os.Exit(1)
	}
	pubKeyPath := os.Getenv("PUBLIC_KEY_PATH")
	if pubKeyPath == "" {
		pubKeyPath = "/etc/kamailio/pubkey.txt" // Default path
	}
	publicKeyBytes, err := os.ReadFile(pubKeyPath)
	if err != nil {
		fmt.Println("Error reading public key file")
		os.Exit(1)
	}
	publicKey := string(publicKeyBytes)

	
	var client httpclient.HttpClient = httpclient.NewCserSignedClient(publicKey, privKey)
	req := OriginRequest{
		Orig: fromId,
		Dest: toId,
      Evd: "EPRYuyESGZDBlsHvfPbTrYd0ZnW9d4ZGWm_rqRoHr-lE",
		OrigID: "e0ac7b44-1fc3-4794-8edd-34b83c018fe9",
    	RequestID: "70664125-c88d-49d6-b66f-0510c20fc3a6",
	}
	resp, err := client.SendSignedRequest(context.Background(), "POST", "https://origin.dev.provenant.net/v1/signer/voice/sign", req)
	// // resp, err := client.SendSignedRequest(context.Background(), "POST", "http://localhost:9083/v1/signer/voice/sign", req)

	// Log the response or error
	if err != nil {
		fmt.Printf("Error in signed request: %s\n", err)
		return
	}
	if resp != nil {
		logResponse(resp)
	}

}

// Helper function to log the response
func logResponse(resp *http.Response) {
	fmt.Println("------ HTTP Response ------")
	fmt.Printf("Status: %s\n", resp.Status)
	fmt.Println("Headers:")
	for name, values := range resp.Header {
		for _, value := range values {
			fmt.Printf("  %s: %s\n", name, value)
		}
	}

	// Read and log the response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %s\n", err)
	} else {
		fmt.Printf("Body:\n")
		fmt.Printf("%s\n", string(bodyBytes))
	}

	// Ensure the response body is closed
	resp.Body.Close()
	fmt.Println("---------------------------")
}
