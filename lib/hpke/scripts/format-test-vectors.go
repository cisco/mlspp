package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

var (
	encryptionThreshold = 10
	header              = `#include "test_vectors.h"

std::vector<HPKETestVector> test_vectors{`
	footer = `};`
)

type EncryptionTestVector struct {
	Plaintext  string `json:"plaintext"`
	AAD        string `json:"aad"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type ExporterTestVector struct {
	Context string `json:"exporter_context"`
	Length  int    `json:"L"`
	Value   string `json:"exported_value"`
}

type HPKETestVector struct {
	// Parameters
	Mode   int    `json:"mode"`
	KEMID  int    `json:"kem_id"`
	KDFID  int    `json:"kdf_id"`
	AEADID int    `json:"aead_id"`
	Info   string `json:"info"`

	// Private keys
	IKMR  string `json:"ikmR"`
	IKMS  string `json:"ikmS"`
	IKME  string `json:"ikmE"`
	SKR   string `json:"skRm"`
	SKS   string `json:"skSm"`
	SKE   string `json:"skEm"`
	PSK   string `json:"psk"`
	PSKID string `json:"psk_id"`

	// Public keys
	PKR string `json:"pkRm"`
	PKS string `json:"pkSm"`
	PKE string `json:"pkEm"`

	// Key schedule inputs and computations
	Enc                string `json:"enc"`
	SharedSecret       string `json:"shared_secret"`
	KeyScheduleContext string `json:"key_schedule_context"`
	Secret             string `json:"secret"`
	Key                string `json:"key"`
	Nonce              string `json:"base_nonce"`
	ExporterSecret     string `json:"exporter_secret"`

	Encryptions []EncryptionTestVector `json:"encryptions"`
	Exports     []ExporterTestVector   `json:"exports"`
}

func writeHexLine(hex string, indent int) {
	pad := strings.Repeat(" ", indent)

	if len(hex) == 0 {
		fmt.Printf("%s{},\n", pad)
		return
	}

	fmt.Printf("%sfrom_hex(\"%s\"),\n", pad, hex)
}

func writeEncryption(enc EncryptionTestVector, indent int) {
	pad := strings.Repeat(" ", indent)
	fmt.Printf("%s{\n", pad)
	writeHexLine(enc.Plaintext, indent+2)
	writeHexLine(enc.AAD, indent+2)
	writeHexLine(enc.Nonce, indent+2)
	writeHexLine(enc.Ciphertext, indent+2)
	fmt.Printf("%s},\n", pad)
}

func writeExport(exp ExporterTestVector, indent int) {
	pad := strings.Repeat(" ", indent)
	fmt.Printf("%s{\n", pad)
	writeHexLine(exp.Context, indent+2)
	fmt.Printf("%s  %d,\n", pad, exp.Length)
	writeHexLine(exp.Value, indent+2)
	fmt.Printf("%s},\n", pad)
}

func writeTestVector(tv HPKETestVector, indent int) {
	pad := strings.Repeat(" ", indent)
	fmt.Printf("%s{\n", pad)
	fmt.Printf("%s  HPKE::Mode(%d),\n", pad, tv.Mode)
	fmt.Printf("%s  KEM::ID(%d),\n", pad, tv.KEMID)
	fmt.Printf("%s  KDF::ID(%d),\n", pad, tv.KDFID)
	fmt.Printf("%s  AEAD::ID(%d),\n", pad, tv.AEADID)
	writeHexLine(tv.Info, indent+2)

	writeHexLine(tv.IKMR, indent+2)
	writeHexLine(tv.IKMS, indent+2)
	writeHexLine(tv.IKME, indent+2)

	writeHexLine(tv.SKR, indent+2)
	writeHexLine(tv.SKS, indent+2)
	writeHexLine(tv.SKE, indent+2)

	writeHexLine(tv.PSK, indent+2)
	writeHexLine(tv.PSKID, indent+2)

	writeHexLine(tv.PKR, indent+2)
	writeHexLine(tv.PKS, indent+2)
	writeHexLine(tv.PKE, indent+2)

	writeHexLine(tv.Enc, indent+2)
	writeHexLine(tv.SharedSecret, indent+2)
	writeHexLine(tv.KeyScheduleContext, indent+2)
	writeHexLine(tv.Secret, indent+2)
	writeHexLine(tv.Key, indent+2)
	writeHexLine(tv.Nonce, indent+2)
	writeHexLine(tv.ExporterSecret, indent+2)

	fmt.Printf("%s  {\n", pad)
	for i, enc := range tv.Encryptions {
		writeEncryption(enc, indent+4)

		if i > encryptionThreshold {
			break
		}
	}
	fmt.Printf("%s  },\n", pad)

	fmt.Printf("%s  {\n", pad)
	for _, exp := range tv.Exports {
		writeExport(exp, indent+4)
	}
	fmt.Printf("%s  },\n", pad)

	fmt.Printf("%s},\n", pad)
}

func chk(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	tvJ, err := ioutil.ReadAll(os.Stdin)
	chk(err)

	tvs := []HPKETestVector{}
	err = json.Unmarshal(tvJ, &tvs)
	chk(err)

	fmt.Printf("%s\n", header)
	for _, tv := range tvs {
		writeTestVector(tv, 2)
	}
	fmt.Printf("%s\n", footer)
}
