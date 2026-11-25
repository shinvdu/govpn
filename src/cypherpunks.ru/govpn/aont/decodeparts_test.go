package aont

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestDecodePartsRejectsShortParts(t *testing.T) {
	cases := [][2][]byte{
		{make([]byte, RSize), make([]byte, 0)},
		{make([]byte, HSize+RSize), make([]byte, 0)},
		{make([]byte, 0), make([]byte, RSize-1)},
		{make([]byte, 0), make([]byte, HSize+RSize-1)},
	}
	for i, c := range cases {
		if _, err := DecodeParts(c[0], c[1]); err == nil {
			t.Fatalf("case %d: short parts accepted", i)
		}
	}
	// first alone is large enough but the trailing part is not: must not
	// panic on second[:len(second)-RSize].
	if _, err := DecodeParts(make([]byte, HSize+RSize), make([]byte, 0)); err == nil {
		t.Fatal("missing RSize tail accepted")
	}
}

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
