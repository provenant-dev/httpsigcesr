package main

import (
	"context"
	"encoding/pem"
	"fmt"
	"github.com/Wavecrest/httpsigcesr/httpclient"
	"os"
	"io"
	"net/http"
   "encoding/json"
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
	Identity  string `json:"identity"`
	RequestID string `json:"request_id"`
}

func main() {

   var fromId     string
   var toId       string
   var identity   string
   var requestid  string
   var url        string

   toId   = "src-unk"
   fromId = "dest-unk"

   if len( os.Args ) == 6 {
      fromId    = os.Args[1]
      toId      = os.Args[2]
      identity  = os.Args[3]
      requestid = os.Args[4]
      url       = os.Args[5]
   } else {
      fmt.Println( "usage:" , os.Args[0], " from to identity requestId" );
      fmt.Println( "  sample urls: https://origin.dev.provenant.net/v1/verifier/voice/verify" )
      fmt.Println( "  sample urls: https://origin.stage.provenant.net/v1/verifier/voice/verify" )
      fmt.Println( "  optional env vars: PRIVATE_KEY_PATH and PUBLIC_KEY_PATH" );
      fmt.Println( "    if not set then path is ./" );
      return;
   }

   
   fmt.Println( "\n\nusing from and to and url :", fromId, toId, url , "\n identity:", identity, "\nrequestid:", requestid, "\n\n" )

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
		Identity: identity,
    	RequestID: requestid}

	//req := OriginRequest{
	//	Orig: "+17035550001",
	//	Dest: "15715550000",
	//	Identity: "eyJhbGciOiJFZERTQSIsInR5cCI6InBhc3Nwb3J0IiwicHB0IjoiVlZQIn0.eyJvcmlnIjp7InRuIjpbIjE3MDM1NTUwMDAxIl19LCJkZXN0Ijp7InRuIjpbIjE1NzE1NTUwMDAwIl19LCJldmQiOiJFTFVfSWp2SlAzNzhuUjRFVC1ieVViRFpxbFhJSkJrRThSSjdvMWVKSlJwUSIsImF0dGVzdCI6IkEiLCJvcmlnSWQiOiJlMGFjN2I0NC0xZmMzLTQ3OTQtOGVkZC0zNGI4M2MwMThmZTkiLCJhaWQiOiJFTXBIVHlkcmVSb1pzNTkwb01IM3R5TkNJMFFxVkZjdkVubHJwUVRtNWx2bSIsImlhdCI6MTczMzE3MzQ5NSwiZXhwIjoxNzMzMTczNTI1LCJqdGkiOiI3MDY2NDEyNS1jODhkLTQ5ZDYtYjY2Zi0wNTEwYzIwZmMzYTYifQ.I46QfjH5uvEZlOX9_0icSzqpnMDOzGGH190fyK2hjuIIvdcbdEAWbTADCEMG4z1aSbf4D4GWsP6UTje8ToXRAQ",
   // 	RequestID: "70664125-c88d-49d6-b66f-0510c20fc3a6"}
	
   resp, err := client.SendSignedRequest(context.Background(), "POST", url, req)

	// Log the response or error
	if err != nil {
		fmt.Printf("Error in signed request: %s\n", err)
		return
	}
	if resp != nil {
		dispResponse(resp)
	}

}

// Helper function to log the response
func dispResponse(resp *http.Response) {
	fmt.Println("------ HTTP Response ------")
	fmt.Printf("Status: %s\n", resp.Status)
	fmt.Println("Headers:")
	for name, values := range resp.Header {
		for _, value := range values {
			fmt.Printf("  %s: %s\n", name, value)
		}
	}

   type Result struct {
      Result      uint32   `json:"result"`
      Epl         string   `json:"epl"`
      Request_id  string   `json:"request_id"`
      Attestation string   `json:"attestaion"`
   }

   // sample response
   // {
   //    "result": 34111494,
   //    "epl": "Evidence validation: Passed, Signature validation: Not passed, avet status: Valid, arcd status: Missing, tn status: Valid, prox status: Missing, a2sig status: Valid, alloc status: Valid, ovet status: Missing",
   //    "request_id": "70664125-c88d-49d6-b66f-0510c20fc3a6"
   // }


	// Read and log the response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %s\n", err)
	} else {
		//fmt.Printf("Body:\n")
		//fmt.Printf("%s\n\n", string(bodyBytes))

      var res Result
      err := json.Unmarshal( []byte(bodyBytes), &res )
      if err != nil {
         fmt.Println( err )
      }

      //fmt.Printf( "by:   %d\n", res.Result )
      if isAttestation_A( res.Result ) {
            //fmt.Println( "A attestation" )
            res.Attestation = "A"
      } else 
      if isAttestation_B( res.Result ) {
            //fmt.Println( "B attestation" )
            res.Attestation = "B"
      } else {
            //fmt.Println( "C attestation" )
            res.Attestation = "C"
      }

      json, err := json.Marshal( res )
      if err == nil {
         fmt.Println( string(json) )
      } else {
         fmt.Println( "error parsing json" )
      }
	}

	// Ensure the response body is closed
	resp.Body.Close()
	fmt.Println("---------------------------")
}

func isAttestation_A( res_code uint32 ) bool {
   const mask uint32 = 34111488

   //fmt.Println("Attestation A" )
   //fmt.Printf( "mask:  %x %32b\n", mask    , mask     )
   //fmt.Printf( "code:  %x %32b\n", res_code, res_code )
   //fmt.Printf( "mask: %x %32b\n", ^mask   , ^mask    )

   //fmt.Printf( "res : %x  %32b\n", (res_code & mask)  ,(res_code & mask) )
   //fmt.Printf( "res : %x        %32b\n", (res_code & ^mask) ,(res_code & ^mask) )

   if (res_code &^ mask) == 0 {
      return true
   } else
   {
      return false
   }
}


func isAttestation_B( res_code uint32 ) bool {
   const mask uint32 = 34308100

   //fmt.Println("Attestation B" )
   //fmt.Printf( "mask:  %d %32b\n", mask    , mask     )
   //fmt.Printf( "code:  %d %32b\n", res_code, res_code )
   //fmt.Printf( "mask:%d %32b\n", ^mask   , ^mask    )

   //fmt.Printf( "res : %d  %32b\n", (res_code & mask)  ,(res_code & mask) )
   //fmt.Printf( "res : %d        %32b\n", (res_code & ^mask) ,(res_code & ^mask) )

   if (res_code & ^mask) == 0 {
      return true
   } else
   {
      return false
   }
}
