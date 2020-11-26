package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
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

func makeCert(template, parent *x509.Certificate, parentPriv crypto.Signer, addSKI bool) (crypto.Signer, *x509.Certificate, []byte) {
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

  // Add Email SAN
  template.EmailAddresses = []string{"user@domain.com"}

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
  //certHex := make([]byte, hex.EncodedLen(len(certData)))
  // hex.Encode(certHex, certData)

  cert, err := x509.ParseCertificate(certData)
  chk(err)

  return priv, cert, certData
}

func makeCertChain(rootPriv crypto.Signer, depth int, addSKI bool) ([]byte, []byte, []*x509.Certificate, [][]byte) {
  chain := make([]*x509.Certificate, depth)
  chainRaw  := make([][]byte, depth)

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

  return currPriv.(ed25519.PrivateKey), rootCertRaw, chain, chainRaw
}

func main() {
  depth := 2
  rootPriv := newEd25519()
  myPriv, rootCertRaw, _, chainRaw := makeCertChain(rootPriv, depth, false)

  fmt.Printf("{\n")
  fmt.Printf("  root_priv,\n")
  fmt.Printf("  from_hex(\"%x\"),\n", rootPriv)
  fmt.Printf("  root_cert,\n")
  fmt.Printf("  from_hex(\"%x\"),\n", rootCertRaw)
  fmt.Printf("  leaf_priv,\n")
  fmt.Printf("  from_hex(\"%x\"),\n", myPriv)
  for _, c := range chainRaw {
    fmt.Printf("  from_hex(\"%x\"),\n", c)
  }
  fmt.Printf("},\n")
}
