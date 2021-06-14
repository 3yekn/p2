package encryption

import (
	"crypto/rand"
	"crypto/sha512"

	"github.com/dfuse-io/logging"
	"go.uber.org/zap"
)

var zlog *zap.Logger

func init() {
	logging.Register("github.com/dappdever/p2/encryption", &zlog)
}

// Define salt size
const saltSize = 32

// Generate bytes randomly and securely using the
// Cryptographically secure pseudorandom number generator (CSPRNG)
// in the crypto.rand package
func GenerateRandomSalt() []byte {
	var salt = make([]byte, saltSize)
	_, err := rand.Read(salt[:])
	if err != nil {
		zlog.Fatal("cannot generate random salt")
	}
	return salt
}

// Combine payload and salt then hash them using the SHA-512
// hashing algorithm and then return the hashed payload
// as a base64 encoded string
func HashWithSalt(payload string, salt []byte) []byte {
	// Convert payload string to byte slice
	var payloadBytes = []byte(payload)
	// Append salt to payload
	payloadBytes = append(payloadBytes, salt...)
	return Sha512(payloadBytes)
}

func Sha256(payload []byte) []byte {
	h := sha512.New()
	h.Write(payload)
	return h.Sum(nil)
}

func Sha512(payload []byte) []byte {
	h := sha512.New()
	h.Write(payload)
	return h.Sum(nil)
}
