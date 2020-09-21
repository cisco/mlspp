package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"time"
	"fmt"
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

func makeCert(template, parent *x509.Certificate, parentPriv crypto.Signer, addSKI bool) (crypto.Signer, *x509.Certificate, string) {
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

  // Add random SKI if requried
  template.SubjectKeyId = nil
  if addSKI {
    template.SubjectKeyId = make([]byte, skiSize)
    rand.Read(template.SubjectKeyId)
  }

  // Generate and parse the certificate
  priv := parentPriv
  realParent := template
  if parent != nil {
    priv = newEd25519()
    realParent = parent
  }

  certData, err := x509.CreateCertificate(rand.Reader, template, realParent, priv.Public(), parentPriv)
  chk(err)

  // generate hex version for file storage
  certHex := make([]byte, hex.EncodedLen(len(certData)))
  hex.Encode(certHex, certData)

  cert, err := x509.ParseCertificate(certData)
  chk(err)

  return priv, cert, string(certHex)
}


func makeCertChain(rootPriv crypto.Signer, depth int, addSKI bool) ([]byte, string, []*x509.Certificate,  []string) {
  chain := make([]*x509.Certificate, depth)
  chainHex  := make([]string, depth)

  _, rootCert, rootHex := makeCert(caTemplate, nil, rootPriv, addSKI)

  currPriv := rootPriv
  cert := rootCert
  certHex := rootHex
  for i := depth - 1; i > 0; i-- {
    currPriv, cert, certHex = makeCert(caTemplate, cert, currPriv, addSKI)
    chain[i] = cert
    chainHex[i] = certHex
  }

  currPriv, cert, certHex = makeCert(leafTemplate, cert, currPriv, addSKI)
  chain[0] = cert
  chainHex[0] = certHex

  return currPriv.(ed25519.PrivateKey), rootHex, chain, chainHex
}

func main() {
  depth := 2
  rootPriv := newEd25519()
  fmt.Printf("Root Priv Key %x\n", rootPriv)

  myPriv, rootCertHex, _, chainHex := makeCertChain(rootPriv, depth, false)
  fmt.Printf("\n Root Certificate %s\n", rootCertHex)
  fmt.Printf("\n MyPriv %x\n", myPriv)
  for _, c := range chainHex {
    fmt.Printf("\n\t --- Begin Certificate ---- \n")
    fmt.Printf("%s", c)
    fmt.Printf("\n\t --- End Certificate ---- \n")
  }
}
