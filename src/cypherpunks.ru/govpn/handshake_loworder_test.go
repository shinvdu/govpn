package govpn

import (
	"testing"

	"github.com/agl/ed25519/extra25519"
)

func TestDHKeyGenRejectsLowOrder(t *testing.T) {
	var priv [32]byte
	for i := range priv {
		priv[i] = byte(i*7 + 1)
	}
	uOne := [32]byte{1}
	for _, pub := range [][32]byte{{}, uOne} {
		if _, err := dhKeyGen(&priv, &pub); err == nil {
			t.Fatalf("accepted low-order u-coordinate %x", pub)
		}
	}

	validPriv, validRepr := dhKeypairGen()
	var validPub [32]byte
	extra25519.RepresentativeToPublicKey(&validPub, validRepr)
	if _, err := dhKeyGen(validPriv, &validPub); err != nil {
		t.Fatalf("rejected valid DH point: %v", err)
	}
}
