# cryptgo

`cryptgo` is a simple go library for aes encryption and decryption using aes-gcm mode. aes-gcm is a secure, authenticated encryption mode that combines encryption and integrity checking, making it ideal for secure data storage and transmission.

## Features

- aes-256 encryption and decryption
- aes-gcm mode for authenticated encryption
- Easy-to-use api

## Installation

you can download `cryptgo` by running the following command:

```sh
go get -u github.com/amandlaus/cryptgo
```

# Example Usage

Here's a complete example showing how to encrypt and decrypt text:

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

# Generating Encryption Parameters

To generate encryption parameters, consider using the following code:

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
	keylength := flag.int("length", 32, "length of the key in bytes")
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

## You May Then Run The Following Commands:

### For Generating Encryption Key:

```sh
go run scripts/gen_encryption_params.go -length=32
```

### For Generating Fixed Nonce:

```sh
go run scripts/gen_encryption_params.go -length=12
```

**NOTE**: Store encryption key and fixed nonce in .env file

# Error Handling

The methods will return the following cases

- **Invalid Key Format**: When the provided key does not conform to the expected 32-byte hexadecimal format.
- **Encryption or Decryption Failures**: If an error occurs during the encryption or decryption process, such as an incorrect ciphertext or decryption failure.
- **Incorrect Ciphertext Length**: When the length of the ciphertext is shorter than the required nonce size or otherwise invalid for proper decryption.

# Contributing

Feel free to open issues or pull requests to improve the library. contributions are welcome!

Please refer to the [contributing.md](contributing.md) file for more details on how to contribute.

## License

This library is released under the mit license. see the [license](license) file for more details.

## Code of Conduct

Feel free to open issues or pull requests to improve the library. contributions are welcome!

Please adhere to our [code of conduct](code_of_conduct.md) when contributing to the project.
