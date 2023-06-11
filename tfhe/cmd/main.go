//package main
//
//import (
//	"encoding/hex"
//	"fmt"
//	"math/big"
//	"os"
//
//	tfhelib "github.com/ethereum/go-ethereum/tfhe"
//)
//
//// This is just a demo to ensure we can compile a static go binary
//func main() {
//	file := os.Args[1]
//
//	if file == "version" {
//		libtfheVersion, err := tfhelib.Version()
//		if err != nil {
//			panic(err)
//		}
//		fmt.Printf("Tfhe-rs version: %s\n", libtfheVersion)
//		return
//	}
//
//	path := os.Args[2]
//
//	if file == "encrypt" {
//		clientKeyFile, err := os.ReadFile(path)
//		if err != nil {
//			panic(err)
//		}
//
//		ok, err := tfhelib.LoadClientKey(clientKeyFile)
//		if err != nil {
//			fmt.Printf("Error from tfhe: %s", err)
//			return
//		}
//		if !ok {
//			fmt.Printf("Load key failed")
//			return
//		}
//
//		fmt.Printf("Load key success")
//
//		num := big.NewInt(10)
//
//		res, err := tfhelib.NewCipherText(*num, 0)
//		if err != nil {
//			fmt.Printf("Error from tfhe NewCipherText: %s", err)
//			return
//		}
//		bytes := res.Serialization
//
//		fmt.Printf("Got ciphertext: %s", hex.EncodeToString(bytes))
//		return
//	}
//
//	if file == "deserialize-sks" {
//		serverKey := []byte("test")
//		ok, err := tfhelib.LoadServerKey(serverKey)
//		if err != nil {
//			fmt.Printf("Error from tfhe: %s", err)
//		}
//
//		fmt.Printf("Tfhe-rs result: %t\n", ok)
//		return
//
//	}
//
//	if file == "add" {
//		path := os.Args[2]
//		serverKeyFile, err := os.ReadFile(path)
//		if err != nil {
//			panic(err)
//		}
//
//		ok, err := tfhelib.LoadServerKey(serverKeyFile)
//		if err != nil {
//			fmt.Printf("Error from tfhe: %s", err)
//			return
//		}
//		if !ok {
//			fmt.Printf("Load key failed")
//			return
//		}
//
//		clientKey := os.Args[3]
//		clientKeyFile, err := os.ReadFile(clientKey)
//		if err != nil {
//			panic(err)
//		}
//
//		ok, err = tfhelib.LoadClientKey(clientKeyFile)
//		if err != nil {
//			fmt.Printf("Error from tfhe: %s", err)
//			return
//		}
//		if !ok {
//			fmt.Printf("Load key failed")
//			return
//		}
//
//		num := big.NewInt(10)
//
//		num1, err := tfhelib.NewCipherText(*num, 0)
//		if err != nil {
//			fmt.Printf("Error from tfhe NewCipherText: %s", err)
//			return
//		}
//		num2, err := tfhelib.NewCipherText(*num, 0)
//		if err != nil {
//			fmt.Printf("Error from tfhe NewCipherText: %s", err)
//			return
//		}
//
//		res, err := num1.Add(num2)
//		if err != nil {
//			fmt.Printf("Error while adding: %s", err)
//			return
//		}
//
//		fmt.Printf("Success! Got result %s", hex.EncodeToString(res.Serialization))
//	}
//}

package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	tfhelib "github.com/ethereum/go-ethereum/tfhe"
	"math/big"
	"os"
)

var (
	fileFlag = flag.String("file", "", "Indicate the operation: version, encrypt, deserialize-sks, add")
	sksPath  = flag.String("server-key", "", "Server key path")
	cksPath  = flag.String("client-key", "", "Client key path")
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	if len(os.Args) == 1 {
		flag.Usage()
		os.Exit(1)
	}

	var err error
	switch *fileFlag {
	case "version":
		err = Version()
	case "encrypt":
		err = Encrypt(*cksPath)
	case "deserialize-sks":
		err = Deserialize(*sksPath)
	case "add":
		err = Add(*sksPath, *cksPath)
	default:
		fmt.Println("Invalid file operation.")
		return
	}

	if err != nil {
		fmt.Printf("Error: %s\n", err)
	}
}

func Version() error {
	libtfheVersion, err := tfhelib.Version()
	if err != nil {
		return err
	}
	fmt.Printf("Tfhe-rs version: %s\n", libtfheVersion)
	return nil
}

func Encrypt(path string) error {
	clientKeyFile, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	ok, err := tfhelib.LoadClientKey(clientKeyFile)
	if err != nil {
		return fmt.Errorf("error from tfhe: %s", err)
	}
	if !ok {
		return fmt.Errorf("load key failed")
	}

	fmt.Printf("Load key success")

	num := big.NewInt(10)

	res, err := tfhelib.NewCipherText(*num, 0)
	if err != nil {
		return fmt.Errorf("error from tfhe NewCipherText: %s", err)
	}
	bytes := res.Serialization

	fmt.Printf("Got ciphertext: %s", hex.EncodeToString(bytes))
	return nil
}

func Deserialize(path string) error {
	serverKeyFile, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	ok, err := tfhelib.LoadServerKey(serverKeyFile)
	if err != nil {
		return fmt.Errorf("error from tfhe: %s", err)
	}

	fmt.Printf("Tfhe-rs result: %t\n", ok)
	return nil
}

func Add(skPath string, ckPath string) error {
	serverKeyFile, err := os.ReadFile(skPath)
	if err != nil {
		return err
	}

	ok, err := tfhelib.LoadServerKey(serverKeyFile)
	if err != nil {
		return fmt.Errorf("error from tfhe: %s", err)
	}
	if !ok {
		return fmt.Errorf("load key failed")
	}

	clientKeyFile, err := os.ReadFile(ckPath)
	if err != nil {
		return err
	}

	ok, err = tfhelib.LoadClientKey(clientKeyFile)
	if err != nil {
		return fmt.Errorf("error from tfhe: %s", err)
	}
	if !ok {
		return fmt.Errorf("load key failed")
	}

	num := big.NewInt(10)

	num1, err := tfhelib.NewCipherText(*num, 0)
	if err != nil {
		return fmt.Errorf("error from tfhe NewCipherText: %s", err)
	}
	num2, err := tfhelib.NewCipherText(*num, 0)
	if err != nil {
		return fmt.Errorf("error from tfhe NewCipherText: %s", err)
	}

	res, err := num1.Add(num2)
	if err != nil {
		return fmt.Errorf("error while adding: %s", err)
	}

	fmt.Printf("Success! Got result %s", hex.EncodeToString(res.Serialization))
	return nil
}
