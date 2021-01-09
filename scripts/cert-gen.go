package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"math/big"
	"time"
)

var (
	caTemplate = &x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	leafTemplate = &x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	is_rsa = true
)

func chk(err error) {
	if err != nil {
		panic(err)
	}
}

func newEd25519() ed25519.PrivateKey {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	chk(err)
	return priv
}

func newRsa() *rsa.PrivateKey {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	chk(err)
	return priv
}

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey)
	default:
		return nil
	}
}

func makeCert(template, parent *x509.Certificate, parentPriv interface{}, addSKI bool) (interface{}, *x509.Certificate, []byte) {
	backdate := time.Hour
	lifetime := 24 * time.Hour
	skiSize := 4 // bytes

	// Set expiry
	template.NotBefore = time.Now().Add(-backdate)
	template.NotAfter = template.NotBefore.Add(lifetime)

	// Set serial number
	serialNumberLimit := big.NewInt(0).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	chk(err)
	template.SerialNumber = serialNumber

	// Add random SKI if required
	template.SubjectKeyId = nil
	if addSKI {
		template.SubjectKeyId = make([]byte, skiSize)
		rand.Read(template.SubjectKeyId)
	}

	// Add Email SAN
	template.EmailAddresses = []string{"user@domain.com"}

	// Generate and parse the certificate
	var priv interface{}
	priv = parentPriv
	realParent := template
	if parent != nil {
		if is_rsa {
			priv = newRsa()
		} else {
			priv = newEd25519()
		}

		realParent = parent
	}

	certData, err := x509.CreateCertificate(rand.Reader, template, realParent, publicKey(priv), parentPriv)
	chk(err)

	// generate hex version for file storage
	//certHex := make([]byte, hex.EncodedLen(len(certData)))
	// hex.Encode(certHex, certData)

	cert, err := x509.ParseCertificate(certData)
	chk(err)

	return priv, cert, certData
}

func makeCertChain(rootPriv interface{}, depth int, addSKI bool) ([]byte, []byte, []*x509.Certificate, [][]byte) {
	chain := make([]*x509.Certificate, depth)
	chainRaw := make([][]byte, depth)

	_, rootCert, rootCertRaw := makeCert(caTemplate, nil, rootPriv, addSKI)

	currPriv := rootPriv
	cert := rootCert
	certRaw := rootCertRaw
	for i := depth - 1; i > 0; i-- {
		currPriv, cert, certRaw = makeCert(caTemplate, cert, currPriv, addSKI)
		chain[i] = cert
		chainRaw[i] = certRaw
	}

	currPriv, cert, certRaw = makeCert(leafTemplate, cert, currPriv, addSKI)
	chain[0] = cert
	chainRaw[0] = certRaw

	// todo (snandaku) : make it more generic
	var privBytes []byte
	if is_rsa {
		privBytes, _ = x509.MarshalPKCS8PrivateKey(currPriv)
	} else {
		privBytes = currPriv.(ed25519.PrivateKey)
	}
	return privBytes, rootCertRaw, chain, chainRaw
}

func main() {
	depth := 2
	var rootPriv interface{}

	if is_rsa {
		rootPriv = newRsa()
	} else {
		rootPriv = newEd25519()
	}
	rootPrivBytes, err := x509.MarshalPKCS8PrivateKey(rootPriv)
	chk(err)

	myPrivBytes, rootCertRaw, _, chainRaw := makeCertChain(rootPriv, depth, true)
	chk(err)

	fmt.Printf("{\n")
	fmt.Printf("  root_priv,\n")
	fmt.Printf("},\n")
	fmt.Printf("  from_hex(\"%x\"),\n", rootPrivBytes)
	fmt.Printf("  root_cert,\n")
	fmt.Printf("  from_hex(\"%x\"),\n", rootCertRaw)
	fmt.Printf("  leaf_priv,\n")
	fmt.Printf("  from_hex(\"%x\"),\n", myPrivBytes)
	fmt.Printf("  chain [ leaf and up ],\n")
	for _, c := range chainRaw {
		fmt.Printf("  from_hex(\"%x\"),\n", c)
	}
	fmt.Printf("},\n")

}