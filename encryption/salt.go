package encryption

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
)

// Define salt size
const saltSize = 32

// Generate 16 bytes randomly and securely using the
// Cryptographically secure pseudorandom number generator (CSPRNG)
// in the crypto.rand package
func GenerateRandomSalt() []byte {
	var salt = make([]byte, saltSize)

	_, err := rand.Read(salt[:])

	if err != nil {
		panic(err)
	}

	return salt
}

// func HashStringWithSalt(payload string, salt string) string {
// 	var payloadBytes = []byte(payload)
// 	var saltBytes = []byte(salt)
// 	// Append salt to payload
// 	payloadBytes = append(payloadBytes, saltBytes...)
// 	return hash(payloadBytes)
// }

func HashString(payload string) string {
	// Convert payload string to byte slice
	var payloadBytes = []byte(payload)

	// Create sha-512 hasher
	var sha512Hasher = sha512.New()

	// Write payload bytes to the hasher
	sha512Hasher.Write(payloadBytes)

	// Get the SHA-512 hashed payload
	var hashedpayloadBytes = sha512Hasher.Sum(nil)

	// Convert the hashed payload to a base64 encoded string
	var base64EncodedpayloadHash = base64.URLEncoding.EncodeToString(hashedpayloadBytes)

	return base64EncodedpayloadHash
}

func Sha256(payload []byte) []byte {
	h := sha256.New()
	h.Write(payload)
	return h.Sum(nil)
}

func hash(payloadBytes []byte) []byte {

	// Create sha-512 hasher
	var sha512Hasher = sha512.New()

	// Write payload bytes to the hasher
	sha512Hasher.Write(payloadBytes)

	// Get the SHA-512 hashed payload
	var hashedpayloadBytes = sha512Hasher.Sum(nil)
	return hashedpayloadBytes

	// // Convert the hashed payload to a base64 encoded string
	// var base64EncodedpayloadHash = base64.URLEncoding.EncodeToString(hashedpayloadBytes)

	// return base64EncodedpayloadHash
}

// func hashObj(payload interface{}) string {
// 	payloadBytes := new(bytes.Buffer)
// 	json.NewEncoder(payloadBytes).Encode(payload)
// 	return hash(payloadBytes.Bytes())
// }

// Combine payload and salt then hash them using the SHA-512
// hashing algorithm and then return the hashed payload
// as a base64 encoded string
func HashWithSalt(payload string, salt []byte) []byte {
	// Convert payload string to byte slice
	var payloadBytes = []byte(payload)

	// Append salt to payload
	payloadBytes = append(payloadBytes, salt...)

	return hash(payloadBytes)
}
