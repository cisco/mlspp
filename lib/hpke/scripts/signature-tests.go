package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"fmt"

	"github.com/cloudflare/circl/sign/ed448"
)

var (
	messageSize = 128

	curves = map[string]elliptic.Curve{
		"P256_SHA256": elliptic.P256(),
		"P384_SHA384": elliptic.P384(),
		"P521_SHA512": elliptic.P521(),
	}

	hashes = map[string]crypto.Hash{
		"P256_SHA256": crypto.SHA256,
		"P384_SHA384": crypto.SHA384,
		"P521_SHA512": crypto.SHA512,
	}
)

func newMessage() []byte {
	msg := make([]byte, messageSize)
	_, err := rand.Read(msg)
	chk(err)
	return msg
}

func ecdsaTestCase(curveName string) {

	priv, err := ecdsa.GenerateKey(curves[curveName], rand.Reader)
	chk(err)

	pub := elliptic.Marshal(curves[curveName], priv.X, priv.Y)

	msg := newMessage()
	h := hashes[curveName].New()
	h.Write(msg)

	sig, err := priv.Sign(rand.Reader, h.Sum(nil), nil)
	chk(err)

	printTestCase(curveName, pub, msg, sig)
}

func ed25519TestCase() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	chk(err)

	msg := newMessage()
	sig := ed25519.Sign(priv, msg)
	printTestCase("Ed25519", pub, msg, sig)
}

func ed448TestCase() {
	pub, priv, err := ed448.GenerateKey(rand.Reader)
	chk(err)

	msg := newMessage()
	sig := ed448.Sign(priv, msg, "")
	printTestCase("Ed448", pub, msg, sig)
}

func printTestCase(sigID string, pubKeyData, message, signature []byte) {
	fmt.Printf("{\n")
	fmt.Printf("  Signature::ID::%s,\n", sigID)
	fmt.Printf("  from_hex(\"%x\"),\n", pubKeyData)
	fmt.Printf("  from_hex(\"%x\"),\n", message)
	fmt.Printf("  from_hex(\"%x\"),\n", signature)
	fmt.Printf("},\n")
}

func main() {
	for name := range curves {
		ecdsaTestCase(name)
	}

	ed25519TestCase()
	ed448TestCase()
}

func chk(err error) {
	if err != nil {
		panic(err)
	}
}
