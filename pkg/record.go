package pkg

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/dappdever/p2/encryption"
	"golang.org/x/crypto/bcrypt"
)

type Record struct {
	Customer            Customer `json:"customer"`
	Sha256              string   `json:"sha256"`
	Sha512              string   `json:"sha512"`
	BCrypt1             string   `json:"bcrypt1"`
	BCrypt2             string   `json:"bcrypt2"`
	Salt                string   `json:"salt"`
	SaltedHash          string   `json:"salted_hash"`
	AESKey              string   `json:"aes_key"`
	RSAKeyName          string   `json:"rsa_key_name"`
	AESEncryptedPayload string   `json:"aes_encrypted_payload"`
	RSAEncryptedKey     string   `json:"rsa_encrypted_key"`
}

func NewRecord(c Customer, keyName string) (Record, error) {

	r := Record{}
	r.Customer = c
	customerS, err := json.Marshal(c)
	if err != nil {
		return Record{}, fmt.Errorf("cannot marshal string: %v", err)
	}
	fmt.Println("--")
	fmt.Println(string(customerS))
	fmt.Println("--")
	// zlog.Info("string with no-whitespace", zap.String("customer-string", string(customerS)))

	r.Sha256 = hex.EncodeToString(encryption.Sha256(customerS))
	r.Sha512 = hex.EncodeToString(encryption.Sha512(customerS))

	bcrypt1, err := bcrypt.GenerateFromPassword(customerS, bcrypt.DefaultCost)
	if err != nil {
		return Record{}, fmt.Errorf("cannot generate bcrypt: %v", err)
	}
	r.BCrypt1 = hex.EncodeToString(bcrypt1)

	bcrypt2, err := bcrypt.GenerateFromPassword(customerS, bcrypt.DefaultCost)
	if err != nil {
		return Record{}, fmt.Errorf("cannot generate bcrypt: %v", err)
	}
	r.BCrypt2 = hex.EncodeToString(bcrypt2)

	salt := encryption.GenerateRandomSalt()
	r.Salt = hex.EncodeToString(encryption.GenerateRandomSalt())
	r.SaltedHash = hex.EncodeToString(encryption.HashWithSalt(string(customerS), salt))

	aesKey := encryption.NewAesEncryptionKey()
	r.AESKey = hex.EncodeToString(aesKey[:])
	r.RSAKeyName = keyName

	aesEncrypted, _ := encryption.AesEncrypt(customerS, aesKey)
	r.AESEncryptedPayload = hex.EncodeToString(aesEncrypted)

	encryptedAesKey, err := encryption.RsaEncrypt(keyName, aesKey[:])
	if err != nil {
		return Record{}, fmt.Errorf("cannot marshal string: %v", err)
	}

	r.RSAEncryptedKey = hex.EncodeToString(encryptedAesKey)
	return r, nil
}
