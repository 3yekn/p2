package pkg

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/dappdever/p2/encryption"
)

type RecordMap struct {
	PayloadMap map[string]string `json:"payload"`
	Hash       []byte            `json:"hash"`
}

type Record struct {
	Customer            Customer `json:"customer"`
	Hash                string   `json:"hash"`
	Salt                string   `json:"salt"`
	SaltedHash          string   `json:"salted_hash"`
	AESKey              string   `json:"aes_key"`
	RSAKeyName          string   `json:"rsa_key_name"`
	AESEncryptedPayload string   `json:"aes_encrypted_payload"`
	RSAEncryptedKey     string   `json:"rsa_encrypted_key"`
}

func NewRecordMap(c Customer, keyName string) (RecordMap, error) {
	r := RecordMap{}
	r.PayloadMap = make(map[string]string)

	customerS, err := json.Marshal(c)
	if err != nil {
		return RecordMap{}, fmt.Errorf("cannot marshal string: %v", err)
	}

	payloadBytes := new(bytes.Buffer)
	json.NewEncoder(payloadBytes).Encode(customerS)

	r.PayloadMap["plaintext"] = string(customerS) // payloadBytes.String()

	h := sha256.New()
	h.Write(customerS)
	// fmt.Printf("Hash: %x", h.Sum(nil))
	r.Hash = h.Sum(nil)

	r.PayloadMap["hash"] = hex.EncodeToString(h.Sum(nil))

	// encryption.Sha256(customerS)

	salt := encryption.GenerateRandomSalt()
	r.PayloadMap["salt"] = hex.EncodeToString(salt)

	// r.PayloadMap["salted_hash"] = string(encryption.HashWithSalt(string(customerS), salt))
	// r.PayloadMap["rsa_key_name"] = keyName

	// aesKey := encryption.NewAesEncryptionKey()
	// r.PayloadMap["aes_key"] = string(aesKey[:])

	// aesEncrypted, _ := encryption.AesEncrypt(customerS, aesKey)
	// r.PayloadMap["aes_encrypted_payload"] = string(aesEncrypted)

	// encryptedAesKey, err := encryption.RsaEncrypt(keyName, aesKey[:])
	// if err != nil {
	// 	return RecordMap{}, fmt.Errorf("cannot marshal string: %v", err)
	// }
	// r.PayloadMap["encrypted_aes_key"] = string(encryptedAesKey)
	return r, nil
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

	r.Hash = hex.EncodeToString(encryption.Sha256(customerS))

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
