package main

import (
    "crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"flag"
	"math/big"
	"time"
	"os"
	"errors"
)

var (
    notBefore = time.Now().Add(-2 * 24 * time.Hour)
    notAfter  = time.Now().Add(99 * 365 * 24 * time.Hour)

	caTemplate = &x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		NotBefore: notBefore,
        NotAfter: notAfter,
	}

	leafTemplate = &x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		NotBefore: notBefore,
		NotAfter: notAfter,
	}

    sigAlgo = flag.String("sig-alg", "", "rsa, ecdsa-p256, ed25519")
)

const (
  keyTypeRSA        = "rsa"
  keyTypeECDSA_P256 =  "ecdsa-p256"
  keyTypeED25519    = "ed25519"
)

func chk(err error) {
	if err != nil {
		panic(err)
	}
}

func chkSignatureScheme(algo string) {
    switch algo {
      case keyTypeRSA:
      case keyTypeECDSA_P256:
      case keyTypeED25519:
        return
      default:
        chk(errors.New("unsupported signature scheme"))
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

func newEcdsaKey() *ecdsa.PrivateKey {
    priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    chk(err)
    return priv
}


// Go represents Ed25519 private keys in a non-standard form, with the public key appended.
// This function removes the appended public key, so that the private key is in the format
// required by RFC 8032.
func normalizeEd25519PrivateKey(priv ed25519.PrivateKey) []byte {
  return priv[:32]
}

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
    		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey)
	default:
		return nil
	}
}

func privateKey(algo string) interface{}{
    switch algo {
      case keyTypeRSA:
        return newRsa()
      case keyTypeECDSA_P256:
        return newEcdsaKey()
      case keyTypeED25519:
        return newEd25519()
    }
    return nil
}

func privateKeyToBytes(algo string, priv interface{}) []byte {
    var privBytes []byte
    var err error
    switch algo {
      case keyTypeRSA:
        privBytes, err = x509.MarshalPKCS8PrivateKey(priv)
        chk(err)
        return privBytes
      case keyTypeECDSA_P256:
        privECDSA := priv.(*ecdsa.PrivateKey)
        return privECDSA.D.Bytes()
      case keyTypeED25519:
        return normalizeEd25519PrivateKey(priv.(ed25519.PrivateKey))
      default:
        return nil
    }
}

func makeCert(template, parent *x509.Certificate, parentPriv interface{}, addSKI bool, depth int) (interface{}, *x509.Certificate, []byte) {
	skiSize := 4 // bytes

	// Set serial number
	serialNumberLimit := big.NewInt(0).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	chk(err)
	template.SerialNumber = serialNumber
    // set subject
    template.Subject =  pkix.Name {
                           	CommonName: "custom:12345",
                           	SerialNumber: "11-22-33",
                          }

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
		priv = privateKey(*sigAlgo)
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

	_, rootCert, rootCertRaw := makeCert(caTemplate, nil, rootPriv, addSKI, depth)

	currPriv := rootPriv
	cert := rootCert
	certRaw := rootCertRaw
	for i := depth - 1; i > 0; i-- {
		currPriv, cert, certRaw = makeCert(leafTemplate, cert, currPriv, addSKI, i)
		chain[i] = cert
		chainRaw[i] = certRaw
	}

	currPriv, cert, certRaw = makeCert(leafTemplate, cert, currPriv, addSKI, 0)
	chain[0] = cert
	chainRaw[0] = certRaw

	privBytes := privateKeyToBytes(*sigAlgo, currPriv)
	return privBytes, rootCertRaw, chain, chainRaw
}

func main() {
    flag.Parse()

    if *sigAlgo == "" {
      fmt.Printf("Missing signature algorithm. please try -h option for more information\n")
      os.Exit(1)
    }

    chkSignatureScheme(*sigAlgo)

    fmt.Printf("Signature Scheme: %s\n", *sigAlgo)

	depth := 2
	var rootPriv interface{}
	rootPriv = privateKey(*sigAlgo)

	rootPrivBytes := privateKeyToBytes(*sigAlgo, rootPriv)

	myPrivBytes, rootCertRaw, _, chainRaw := makeCertChain(rootPriv, depth, true)

	fmt.Printf("{\n")
	fmt.Printf("  root_priv,\n")
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
