package main

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"os"

	tfhelib "github.com/ethereum/go-ethereum/tfhe"
)

const (
	SUPPORTED_CAPABILITIES = "staking"
	PRINT_DEBUG            = true
	MEMORY_LIMIT           = 32  // MiB
	CACHE_SIZE             = 100 // MiB
)

// This is just a demo to ensure we can compile a static go binary
func main() {
	file := os.Args[1]
	path := os.Args[2]

	if file == "version" {
		libtfheVersion, err := tfhelib.Version()
		if err != nil {
			panic(err)
		}
		fmt.Printf("Tfhe-rs version: %s\n", libtfheVersion)
		return
	}

	if file == "encrypt" {
		clientKeyFile, err := os.ReadFile(path)
		if err != nil {
			panic(err)
		}

		ok, err := tfhelib.LoadClientKey(clientKeyFile)
		if err != nil {
			fmt.Printf("Error from tfhe: %s", err)
			return
		}
		if !ok {
			fmt.Printf("Load key failed")
			return
		}

		fmt.Printf("Load key success")

		num := big.NewInt(10)

		res, err := tfhelib.FheEncrypt(*num, 0)
		if err != nil {
			fmt.Printf("Error from tfhe FheEncrypt: %s", err)
			return
		}
		bytes := res.Serialization

		fmt.Printf("Got ciphertext: %s", hex.EncodeToString(bytes))
		return
	}

	if file == "deserialize-sks" {
		serverKey := []byte("test")
		ok, err := tfhelib.LoadServerKey(serverKey)
		if err != nil {
			fmt.Printf("Error from tfhe: %s", err)
		}

		fmt.Printf("Tfhe-rs result: %t\n", ok)
		return

	}
}
