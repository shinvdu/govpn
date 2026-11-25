package aont

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestDecodeParts(t *testing.T) {
	for n := 1; n < 200; n += 7 {
		r := new([RSize]byte)
		rand.Read(r[:])
		in := make([]byte, n)
		rand.Read(in)
		enc, err := Encode(r, in)
		if err != nil {
			t.Fatal(err)
		}
		out1, err := Decode(enc)
		if err != nil {
			t.Fatal(err)
		}
		out2, err := DecodeParts(enc[:RSize], enc[RSize:])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out1, in) || !bytes.Equal(out2, in) {
			t.Fatalf("mismatch n=%d", n)
		}
	}
}
