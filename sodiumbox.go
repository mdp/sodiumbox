package sodiumbox

import (
	"crypto/rand"
	"errors"

	"github.com/dchest/blake2b"

	"golang.org/x/crypto/nacl/box"
)

func extractKey(slice []byte) *[32]byte {
	a := new([32]byte)
	copy(a[:], slice[0:32])
	return a
}

func boxSealNonce(ephemeralPk, publicKey *[32]byte) (*[24]byte, error) {
	nonce := new([24]byte)
	hashConfig := &blake2b.Config{Size: 24}
	hashFn, err := blake2b.New(hashConfig)
	if err != nil {
		return nil, errors.New("Failed to create blake2b hash function")
	}
	hashFn.Write(ephemeralPk[0:32])
	hashFn.Write(publicKey[0:32])
	nonceSum := hashFn.Sum(nil)
	copy(nonce[:], nonceSum[0:24])
	return nonce, nil
}

// Seal - crypto_box_seal's the message
// compatible with libsodium
func Seal(msg []byte, publicKey *[32]byte) (*[]byte, error) {
	// ephemeral_pk || box(m, recipient_pk, ephemeral_sk, nonce=blake2b(ephemeral_pk || recipient_pk))
	ephemeralPk, ephemeralSk, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, errors.New("Failed to create ephemeral key pair")
	}
	nonce, err := boxSealNonce(ephemeralPk, publicKey)
	if err != nil {
		return nil, errors.New("Failed to build nonce")
	}
	boxed := box.Seal(nil, msg, nonce, publicKey, ephemeralSk)
	output := make([]byte, len(boxed)+32)
	copy(output[0:32], ephemeralPk[0:32])
	copy(output[32:], boxed[:])
	return &output, nil
}

// SealOpen = crypto_box_seal_open
func SealOpen(enc []byte, publicKey, secretKey *[32]byte) (*[]byte, error) {
	// ephemeral_pk || box(m, recipient_pk, ephemeral_sk, nonce=blake2b(ephemeral_pk || recipient_pk))
	ephemeralPk := extractKey(enc)
	nonce, err := boxSealNonce(ephemeralPk, publicKey)
	if err != nil {
		return nil, errors.New("Failed to build nonce")
	}
	boxed := make([]byte, len(enc)-32)
	copy(boxed, enc[32:])
	result, ok := box.Open(nil, boxed, nonce, ephemeralPk, secretKey)
	if !ok {
		return nil, errors.New("Failed to decrypt")
	}
	return &result, err
}
