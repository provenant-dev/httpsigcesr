# Sample: Sign HTTP Request

These samples demonstrates how to use the `httpsigcesr` library to sign an HTTP request with a private key.

---

## Setup

* In the root folder of this project, execute `keygen.go` file to generate a ED25519 public/private key pair.
   ```bash
   go run keygen.go
   ```

* Navigate to the `samples` directory
	```bash
   cd samples
   ```

## Sample Usage

### Sign Request

* Send `sign` request with default key-pair files path(files are in root folder)
   ```bash
   go run sign_req.go
   ```
* If the key-pair is in a different location:
   ```bash
   export PRIVATE_KEY_PATH=/path/to/privkey.pem
   export PUBLIC_KEY_PATH=/path/to/pubkey.txt
   go run sign_req.go
   ```

### Verification Request

* Send `sign` request with default key-pair files path(files are in root folder)
   ```bash
   go run verify_req.go
   ```
* If the key-pair is in a different location:
   ```bash
   export PRIVATE_KEY_PATH=/path/to/privkey.pem
   export PUBLIC_KEY_PATH=/path/to/pubkey.txt
   go run sign_req.go
   ```
