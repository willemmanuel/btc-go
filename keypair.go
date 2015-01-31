// Every file in go is a part of some package. Since we want to create a program
// from this file we use 'package main'
package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"bufio"
	"os"
	"regexp"
	"strings"

	"github.com/btcsuite/btcec"
	"github.com/btcsuite/btcnet"
	"github.com/btcsuite/btcutil"
)

// generateKeyPair creates a key pair based on the eliptic curve
// secp256k1. The key pair returned by this function is two points
// on this curve. Bitcoin requires that the public and private keys
// used to generate signatures are generated using this curve.

func generateKeyPair() (*btcec.PublicKey, *btcec.PrivateKey) {

	// Generate a private key, use the curve secpc256k1 and kill the program on
	// any errors
	priv, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		// There was an error. Log it and bail out
		log.Fatal(err)
	}

	return priv.PubKey(), priv
}

// generateAddr computes the associated bitcon address from the provided
// public key. We compute ripemd160(sha256(b)) of the pubkey and then
// shimmy the hashed bytes into btcsuite's AddressPubKeyHash type
func generateAddr(pub *btcec.PublicKey) *btcutil.AddressPubKeyHash {

	net := &btcnet.MainNetParams

	// Serialize the public key into bytes and then run ripemd160(sha256(b)) on it
	b := btcutil.Hash160(pub.SerializeCompressed())

	// Convert the hashed public key into the btcsuite type so that the library
	// will handle the base58 encoding when we call addr.String()
	addr, err := btcutil.NewAddressPubKeyHash(b, net)
	if err != nil {
		log.Fatal(err)
	}

	return addr
}

func generateVanityAddress(pattern string) (*btcec.PublicKey, *btcec.PrivateKey) {
	pub, priv := generateKeyPair()
	r, err := regexp.Compile(pattern)
	if err != nil {
		return nil, nil
	}
	for {
		if r.MatchString(generateAddr(pub).String()) {
			break
		}
		pub, priv = generateKeyPair()
	}
	return pub, priv
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter pattern, or nothing for non-vanity address: ")
	text, _ := reader.ReadString('\n')
	pub, priv := generateKeyPair()
	text = strings.TrimSpace(text)
	if(len(text) != 0) {
		pub, priv = generateKeyPair()
		r, err := regexp.Compile(text)
		if err != nil {
			fmt.Print("Invalid regex, generating non-vanity address instead.")
		}
		fmt.Printf("Searching...\n")
		for {
			if r.MatchString(generateAddr(pub).String()) {
				break
			}
			pub, priv = generateKeyPair()
		}
	}
	// To use this address we must store our private key somewhere. Everything
	// else can be recovered from the private key.
	fmt.Printf("This is a private key in hex:\t[%s]\n",
		hex.EncodeToString(priv.Serialize()))

	fmt.Printf("This is a public key in hex:\t[%s]\n",
		hex.EncodeToString(pub.SerializeCompressed()))

	addr := generateAddr(pub)

	// Output the bitcoin address derived from the public key
	fmt.Printf("This is the associated Bitcoin address:\t[%s]\n", addr.String())
}
