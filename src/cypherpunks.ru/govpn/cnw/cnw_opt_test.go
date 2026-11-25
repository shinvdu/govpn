package cnw

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"testing"

	"golang.org/x/crypto/poly1305"
	"golang.org/x/crypto/salsa20"
)

// Reference implementation, kept to prove the optimized code produces
// byte-identical output to GoVPN 5.7.
func refChaff(authKey *[32]byte, noncePrfx, in []byte) []byte {
	out := make([]byte, len(in)*EnlargeFactor)
	keys := make([]byte, 8*64)
	nonce := make([]byte, 24)
	copy(nonce[:8], noncePrfx)
	tag := new([16]byte)
	macKey := new([32]byte)
	for n, b := range in {
		binary.BigEndian.PutUint64(nonce[16:], uint64(n))
		salsa20.XORKeyStream(keys, keys, nonce, authKey)
		for i := 0; i < 8; i++ {
			v := (b >> uint8(i)) & 1
			copy(macKey[:], keys[64*i:64*i+32])
			if v == 0 {
				poly1305.Sum(tag, []byte("1"), macKey)
			} else {
				poly1305.Sum(tag, []byte("0"), macKey)
			}
			copy(out[16*(n*16+i*2):], tag[:])
			copy(macKey[:], keys[64*i+32:64*i+64])
			if v == 1 {
				poly1305.Sum(tag, []byte("1"), macKey)
			} else {
				poly1305.Sum(tag, []byte("0"), macKey)
			}
			copy(out[16*(n*16+i*2+1):], tag[:])
		}
		zero(keys)
	}
	zero(macKey[:])
	return out
}

func refWinnow(authKey *[32]byte, noncePrfx, in []byte) ([]byte, error) {
	out := make([]byte, len(in)/EnlargeFactor)
	keys := make([]byte, 8*64)
	nonce := make([]byte, 24)
	copy(nonce[:8], noncePrfx)
	tag := new([16]byte)
	macKey := new([32]byte)
	for n := 0; n < len(out); n++ {
		binary.BigEndian.PutUint64(nonce[16:], uint64(n))
		salsa20.XORKeyStream(keys, keys, nonce, authKey)
		var v byte
		for i := 0; i < 8; i++ {
			copy(macKey[:], keys[64*i:64*i+32])
			poly1305.Sum(tag, []byte("1"), macKey)
			is01 := subtle.ConstantTimeCompare(
				tag[:], in[16*(n*16+i*2):16*(n*16+i*2+1)],
			) == 1
			poly1305.Sum(tag, []byte("0"), macKey)
			is00 := subtle.ConstantTimeCompare(
				tag[:], in[16*(n*16+i*2):16*(n*16+i*2+1)],
			) == 1
			copy(macKey[:], keys[64*i+32:64*i+64])
			poly1305.Sum(tag, []byte("1"), macKey)
			is11 := subtle.ConstantTimeCompare(
				tag[:], in[16*(n*16+i*2+1):16*(n*16+i*2+2)],
			) == 1
			poly1305.Sum(tag, []byte("0"), macKey)
			is10 := subtle.ConstantTimeCompare(
				tag[:], in[16*(n*16+i*2+1):16*(n*16+i*2+2)],
			) == 1
			if !((is01 && is10) || (is00 && is11)) {
				return nil, errInvalidAuth
			}
			if is11 {
				v |= 1 << uint8(i)
			}
		}
		out[n] = v
		zero(keys)
	}
	zero(macKey[:])
	return out, nil
}

var errInvalidAuth = &authError{}

type authError struct{}

func (*authError) Error() string { return "invalid authenticator received" }

func TestTags1EdgeKeys(t *testing.T) {
	var keys [][32]byte
	var zero, ones, rZero, sOnes [32]byte
	for i := range ones {
		ones[i] = 0xff
	}
	for i := range sOnes {
		if i >= 16 {
			sOnes[i] = 0xff
		}
	}
	keys = append(keys, zero, ones, rZero, sOnes)
	for i := range keys {
		key := keys[i]
		t0lo, t0hi, t1lo, t1hi := tags1(key[:])
		var p0, p1 [16]byte
		poly1305.Sum(&p0, []byte("0"), &key)
		poly1305.Sum(&p1, []byte("1"), &key)
		if binary.LittleEndian.Uint64(p0[0:8]) != t0lo ||
			binary.LittleEndian.Uint64(p0[8:16]) != t0hi {
			t.Fatalf("edge key %d: tag0 mismatch", i)
		}
		if binary.LittleEndian.Uint64(p1[0:8]) != t1lo ||
			binary.LittleEndian.Uint64(p1[8:16]) != t1hi {
			t.Fatalf("edge key %d: tag1 mismatch", i)
		}
	}
}

func TestTags1MatchesPoly1305(t *testing.T) {
	var key [32]byte
	for i := 0; i < 20000; i++ {
		if _, err := rand.Read(key[:]); err != nil {
			t.Fatal(err)
		}
		t0lo, t0hi, t1lo, t1hi := tags1(key[:])
		var p0, p1 [16]byte
		poly1305.Sum(&p0, []byte("0"), &key)
		poly1305.Sum(&p1, []byte("1"), &key)
		if binary.LittleEndian.Uint64(p0[0:8]) != t0lo ||
			binary.LittleEndian.Uint64(p0[8:16]) != t0hi {
			t.Fatalf("tag0 mismatch at iteration %d", i)
		}
		if binary.LittleEndian.Uint64(p1[0:8]) != t1lo ||
			binary.LittleEndian.Uint64(p1[8:16]) != t1hi {
			t.Fatalf("tag1 mismatch at iteration %d", i)
		}
	}
}

func TestChaffWinnowMatchReference(t *testing.T) {
	var key [32]byte
	var nonce [8]byte
	for i := 0; i < 200; i++ {
		if _, err := rand.Read(key[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := rand.Read(nonce[:]); err != nil {
			t.Fatal(err)
		}
		in := make([]byte, 1+i%64)
		if _, err := rand.Read(in); err != nil {
			t.Fatal(err)
		}
		want := refChaff(&key, nonce[:], in)
		got := Chaff(&key, nonce[:], in)
		if !bytes.Equal(got, want) {
			t.Fatalf("chaff mismatch for len %d at iteration %d", len(in), i)
		}
		decodedRef, err := refWinnow(&key, nonce[:], want)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := Winnow(&key, nonce[:], got)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(decodedRef, decoded) || !bytes.Equal(decoded, in) {
			t.Fatalf("winnow mismatch for len %d at iteration %d", len(in), i)
		}
	}
}

func TestWinnowRejectsCorruption(t *testing.T) {
	var key [32]byte
	var nonce [8]byte
	rand.Read(key[:])
	rand.Read(nonce[:])
	in := []byte("0123456789abcdef")
	enc := Chaff(&key, nonce[:], in)
	enc[17] ^= 0x80
	if _, err := Winnow(&key, nonce[:], enc); err == nil {
		t.Fatal("corrupted input was accepted")
	}
}

func BenchmarkRefChaff(b *testing.B) {
	var key [32]byte
	nonce := make([]byte, 8)
	data := make([]byte, 16)
	rand.Read(key[:])
	rand.Read(nonce)
	rand.Read(data)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		refChaff(&key, nonce, data)
	}
}

func BenchmarkRefWinnow(b *testing.B) {
	var key [32]byte
	nonce := make([]byte, 8)
	data := make([]byte, 16)
	rand.Read(key[:])
	rand.Read(nonce)
	rand.Read(data)
	chaffed := refChaff(&key, nonce, data)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		refWinnow(&key, nonce, chaffed)
	}
}
