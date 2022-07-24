package main

// This script reads the test vectors in JSON format and re-encodes them in TLS
// format readable by the `tls` library, to avoid having to have a JSON parser
// as a dependency of the tests.
//
// XXX(RLB) There is a fair bit of silliness with array header encoding because
// the varint encoding that is currently in the Go TLS Syntax library doesn't
// match the encoding used by MLS.  Given that the Go TLS Syntax library's
// version is non-standard, we should probably update that to match what MLS
// requires, at which point we can simplify this script.  However, this would be
// a breaking change for any users of the Go library, so just in case there are
// some (I don't expect there are), I held off making the change.

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/cisco/go-tls-syntax"
)

func varintEncode(val int) []byte {
	switch {
	case val <= 0x3f:
		return []byte{byte(val)}

	case val <= 0x3fff:
		return []byte{0x40 | byte(val>>8), byte(val)}

	case val <= 0x3fffffff:
		return []byte{0x80 | byte(val>>24), byte(val >> 16), byte(val >> 8), byte(val)}

	default:
		panic("Un-encodable varint value")
	}
}

func addVarintHeader(data []byte) []byte {
	header := varintEncode(len(data))
	return append(header, data...)
}

type ByteString struct {
	Data []byte `tls:"head=varint"`
}

func (b *ByteString) UnmarshalJSON(data []byte) error {
	hexString := ""
	err := json.Unmarshal(data, &hexString)
	if err != nil {
		return err
	}

	b.Data, err = hex.DecodeString(hexString)
	return err
}

func (b ByteString) MarhsalTLS() ([]byte, error) {
	return addVarintHeader(b.Data), nil
}

type EncryptionTestVector struct {
	Plaintext  ByteString `json:"plaintext"`
	AAD        ByteString `json:"aad"`
	Nonce      ByteString `json:"nonce"`
	Ciphertext ByteString `json:"ciphertext"`
}

type EncryptionTestVectors []EncryptionTestVector

func (etvs EncryptionTestVectors) MarshalTLS() ([]byte, error) {
	data := []byte{}
	for _, etv := range etvs {
		item, err := syntax.Marshal(etv)
		if err != nil {
			return nil, err
		}

		data = append(data, item...)
	}

	return addVarintHeader(data), nil
}

type ExporterTestVector struct {
	Context ByteString `json:"exporter_context"`
	Length  uint32     `json:"L"`
	Value   ByteString `json:"exported_value"`
}

type ExporterTestVectors []ExporterTestVector

func (etvs ExporterTestVectors) MarshalTLS() ([]byte, error) {
	data := []byte{}
	for _, etv := range etvs {
		item, err := syntax.Marshal(etv)
		if err != nil {
			return nil, err
		}

		data = append(data, item...)
	}

	return addVarintHeader(data), nil
}

type HPKETestVector struct {
	// Parameters
	Mode   uint8      `json:"mode"`
	KEMID  uint16     `json:"kem_id"`
	KDFID  uint16     `json:"kdf_id"`
	AEADID uint16     `json:"aead_id"`
	Info   ByteString `json:"info"`

	// Private keys
	IKMR  ByteString `json:"ikmR"`
	IKMS  ByteString `json:"ikmS"`
	IKME  ByteString `json:"ikmE"`
	SKR   ByteString `json:"skRm"`
	SKS   ByteString `json:"skSm"`
	SKE   ByteString `json:"skEm"`
	PSK   ByteString `json:"psk"`
	PSKID ByteString `json:"psk_id"`

	// Public keys
	PKR ByteString `json:"pkRm"`
	PKS ByteString `json:"pkSm"`
	PKE ByteString `json:"pkEm"`

	// Key schedule inputs and computations
	Enc                ByteString `json:"enc"`
	SharedSecret       ByteString `json:"shared_secret"`
	KeyScheduleContext ByteString `json:"key_schedule_context"`
	Secret             ByteString `json:"secret"`
	Key                ByteString `json:"key"`
	Nonce              ByteString `json:"base_nonce"`
	ExporterSecret     ByteString `json:"exporter_secret"`

	Encryptions EncryptionTestVectors `json:"encryptions"`
	Exports     ExporterTestVectors   `json:"exports"`
}

type HPKETestVectors []HPKETestVector

func (htvs HPKETestVectors) MarshalTLS() ([]byte, error) {
	data := []byte{}
	for _, htv := range htvs {
		item, err := syntax.Marshal(htv)
		if err != nil {
			return nil, err
		}

		data = append(data, item...)
	}

	return addVarintHeader(data), nil
}

var (
	encryptionThreshold = 10
	header              = `#include "test_vectors.h"
#include <array>

const std::array<uint8_t, %d> test_vector_data{
`
	footer = `};`
)

func main() {
	tvJSON, err := ioutil.ReadAll(os.Stdin)
	chk(err)

	tvs := []HPKETestVector{}
	err = json.Unmarshal(tvJSON, &tvs)
	chk(err)

	tvTLS, err := syntax.Marshal(HPKETestVectors(tvs))
	chk(err)

	fmt.Printf(header, len(tvTLS))

	width := 16
	start := 0
	for start < len(tvTLS) {
		end := start + width
		if end > len(tvTLS) {
			end = len(tvTLS)
		}

		fmt.Printf("  ")
		for i := start; i < end-1; i++ {
			fmt.Printf("0x%02x, ", tvTLS[i])
		}
		fmt.Printf("0x%02x,\n", tvTLS[end-1])

		start = end
	}

	fmt.Printf("%s\n", footer)
}

func chk(err error) {
	if err != nil {
		panic(err)
	}
}
