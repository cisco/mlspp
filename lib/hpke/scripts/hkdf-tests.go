package main

import (
	"crypto"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/hkdf"
)

func fromHex(h string) []byte {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	return b
}

var (
	kdfName = map[crypto.Hash]string{
		crypto.SHA256: "KDF::ID::HKDF_SHA256",
		crypto.SHA384: "KDF::ID::HKDF_SHA384",
		crypto.SHA512: "KDF::ID::HKDF_SHA512",
	}
	kdfID = map[crypto.Hash][]byte{
		crypto.SHA256: []byte{0x00, 0x01},
		crypto.SHA384: []byte{0x00, 0x02},
		crypto.SHA512: []byte{0x00, 0x03},
	}
)

func labeledExtract(hash crypto.Hash, suiteID, salt, label, ikm []byte) []byte {
	labeledIKM := append([]byte("HPKE-v1"), suiteID...)
	labeledIKM = append(labeledIKM, label...)
	labeledIKM = append(labeledIKM, ikm...)
	return hkdf.Extract(hash.New, labeledIKM, salt)
}

func labeledExpand(hash crypto.Hash, suiteID, prk, label, info []byte, size int) []byte {
	labeledInfo := make([]byte, 2)
	binary.BigEndian.PutUint16(labeledInfo, uint16(size))
	labeledInfo = append(labeledInfo, []byte("HPKE-v1")...)
	labeledInfo = append(labeledInfo, suiteID...)
	labeledInfo = append(labeledInfo, label...)
	labeledInfo = append(labeledInfo, info...)

	out := make([]byte, size)
	h := hkdf.Expand(hash.New, prk, labeledInfo)
	h.Read(out)
	return out
}

func testCase(hash crypto.Hash) {
	suiteID := append([]byte("KDF"), kdfID[hash]...)

	// https://tools.ietf.org/html/rfc5869#appendix-A.1
	ikm := fromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt := fromHex("000102030405060708090a0b0c")
	info := fromHex("f0f1f2f3f4f5f6f7f8f9")
	expandSize := 42

	extracted := hkdf.Extract(hash.New, ikm, salt)

	expanded := make([]byte, expandSize)
	h := hkdf.Expand(hash.New, extracted, info)
	h.Read(expanded)

	label := []byte("test")
	labeledExtracted := labeledExtract(hash, suiteID, salt, []byte("test"), ikm)
	labeledExpanded := labeledExpand(hash, suiteID, labeledExtracted, label, info, expandSize)

	fmt.Printf("{\n")
	fmt.Printf("  %s,\n", kdfName[hash])
	fmt.Printf("  from_hex(\"%x\"),\n", suiteID)
	fmt.Printf("  from_hex(\"%x\"),\n", extracted)
	fmt.Printf("  from_hex(\"%x\"),\n", expanded)
	fmt.Printf("  from_hex(\"%x\"),\n", labeledExtracted)
	fmt.Printf("  from_hex(\"%x\"),\n", labeledExpanded)
	fmt.Printf("},\n")
}

func main() {
	testCase(crypto.SHA256)
	testCase(crypto.SHA384)
	testCase(crypto.SHA512)
}
