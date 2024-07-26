# cryptgo

`cryptgo` is a simple go library for aes encryption and decryption using aes-gcm mode. aes-gcm is a secure, authenticated encryption mode that combines encryption and integrity checking, making it ideal for secure data storage and transmission.

## features

- aes-256 encryption and decryption
- aes-gcm mode for authenticated encryption
- easy-to-use api

## installation

you can download `cryptgo` by running the following command:

```sh
go get -u github.com/amandlaus/cryptgo
```

# example usage

here's a complete example showing how to encrypt and decrypt text:

```go
package main

import (
	"fmt"
	"log"

	"github.com/amandlaus/cryptgo"
)

func main() {
	cg, err := cryptgo.New(&cryptgo.Options{
		// Read these options from .env file.
		// They're placed directly in code here for demonstration purpose only.
		Key:        "76a91c59564bd56132304a9fd65913ac96012689f1ab39b9d04e941cda00f08f", // Example 32-byte hex key
		FixedNonce: "203095d2a50cdbd777b5d8d7",                                         // Example 12-byte fixed nonce for deterministic encryption

	})
	if err != nil {
		log.Fatalf("failed to create cryptgo instance: %v", err)
	}

	plaintext := "Hello, World!"

	// Encrypt the plaintext
	ciphertext, err := cg.EncryptAES(plaintext)
	if err != nil {
		log.Fatalf("encryption failed: %v", err)
	}
	fmt.Printf("ciphertext: %s\n", ciphertext)

	// Decrypt the ciphertext
	decryptedText, err := cg.DecryptAES(ciphertext)
	if err != nil {
		log.Fatalf("decryption failed: %v", err)
	}
	fmt.Printf("plaintext: %s\n", decryptedText)
}
```

# generating encryption parameters

to generate encryption parameters, consider using the following code:

**scripts/gen_encryption_params.go**

```go
package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
)

func main() {
	keylength := flag.int("keylen", 32, "length of the key in bytes")
	flag.parse()

	if *keylength <= 0 {
		fmt.println("key length must be a positive integer.")
		os.exit(1)
	}

	// generate key with specified length
	key := make([]byte, *keylength)
	_, err := rand.read(key)
	if err != nil {
		log.fatal(err)
	}

	fmt.println(hex.encodetostring(key))
}
```

## you may then run the following commands:

### for generating encryption key:

```sh
go run scripts/gen_encryption_params.go -length=32
```

### for generating fixed nonce:

```sh
go run scripts/gen_encryption_params.go -length=12
```

**note**: store encryption key and fixed nonce in .env file

# error handling

the methods will return the following cases

- **invalid key format**: when the provided key does not conform to the expected 32-byte hexadecimal format.
- **encryption or decryption failures**: if an error occurs during the encryption or decryption process, such as an incorrect ciphertext or decryption failure.
- **incorrect ciphertext length**: when the length of the ciphertext is shorter than the required nonce size or otherwise invalid for proper decryption.

# contributing

feel free to open issues or pull requests to improve the library. contributions are welcome!

please refer to the [contributing.md](contributing.md) file for more details on how to contribute.

## license

this library is released under the mit license. see the [license](license) file for more details.

## code of conduct

feel free to open issues or pull requests to improve the library. contributions are welcome!

please adhere to our [code of conduct](code_of_conduct.md) when contributing to the project.
