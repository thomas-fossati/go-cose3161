package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"os"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"

	_ "crypto/sha256"
)

// go-cose3161 <timestamptoken>

func main() {
	args := os.Args
	if len(args) != 2 {
		fmt.Println("go-cose3161 <timestamptoken-DER-file>")
		os.Exit(1)
	}

	tst, err := os.ReadFile(args[1])
	if err != nil {
		panic(err)
	}

	// create a signer
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	signer, err := cose.NewSigner(cose.AlgorithmES256, privateKey)
	if err != nil {
		panic(err)
	}

	// sign message
	headers := cose.Headers{
		Protected: cose.ProtectedHeader{
			cose.HeaderLabelAlgorithm: cose.AlgorithmES256,
			269:                       tst,
		},
		Unprotected: cose.UnprotectedHeader{
			cose.HeaderLabelKeyID: []byte("11"),
		},
	}
	sig, err := cose.Sign1(rand.Reader, signer, headers, []byte("This is the content."), nil)
	if err != nil {
		panic(err)
	}

	dm, _ := cbor.DiagOptions{
		ByteStringEmbeddedCBOR: true,
		ByteStringText:         true,
	}.DiagMode()
	diag, _ := dm.Diagnose(sig)
	fmt.Println(diag)
}
