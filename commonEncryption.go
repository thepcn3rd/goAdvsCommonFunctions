package common

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
)

// EncryptString encrypts a string using AES-256 encryption with a random IV.
func EncryptString(key []byte, plaintext string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	//fmt.Println(iv)
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(plaintext))

	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// DecryptString decrypts a string using AES-256 encryption.
func DecryptString(key []byte, ciphertext string) (string, error) {
	data, err := base64.URLEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(data) < aes.BlockSize {
		return "", errors.New("Ciphertext too short")
	}
	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(data, data)

	return string(data), nil
}

// EncryptString encrypts a string using AES-256-GCM which provides both confidentiality and authenticity.
func EncryptStringGCM(key []byte, plaintext string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of repeat
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	ciphertext := aesgcm.Seal(nil, nonce, []byte(plaintext), nil)

	// Prepend the nonce to the ciphertext
	encryptedMsg := make([]byte, len(nonce)+len(ciphertext))
	copy(encryptedMsg[:12], nonce)
	copy(encryptedMsg[12:], ciphertext)

	return base64.URLEncoding.EncodeToString(encryptedMsg), nil
}

// DecryptString decrypts a string using AES-256-GCM.
func DecryptStringGCM(key []byte, ciphertext string) (string, error) {
	data, err := base64.URLEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(data) < 12 {
		return "", errors.New("ciphertext too short")
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := data[:12]
	ciphertextBytes := data[12:]

	plaintext, err := aesgcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func PullKey(keyURL string, userAgentString string, xAbility string) string {
	url := keyURL
	req, err := http.NewRequest("POST", url, nil)
	CheckError("Unable to pull key from URL...", err, true)
	req.Header.Set("User-Agent", userAgentString)
	req.Header.Set("X-Content-Type-Abilities", xAbility)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	CheckError("Unable to get response...", err, true)
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	respBodyString := string(respBody)
	//fmt.Println(string(respBody))
	return respBodyString
}

func generateSalt(f string) (string, error) {
	asciiChars := "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	saltLength := 256

	if !cf.FileExists("/" + f) {
		// Generate random bytes
		bytes := make([]byte, saltLength)
		_, err := rand.Read(bytes)
		if err != nil {
			log.Printf("Error generating random bytes: %v\n", err)
			return "", err
		}

		// Convert bytes to ASCII characters
		salt := make([]byte, saltLength)
		for i := range salt {
			salt[i] = asciiChars[int(bytes[i])%len(asciiChars)]
		}

		// Write to .salt file
		err = os.WriteFile(f, salt, 0600)
		if err != nil {
			log.Printf("Error writing file: %v\n", err)
			return "", err
		}

		return string(salt), nil
	} else {
		// Read the existing .salt file
		salt, err := os.ReadFile(f)
		if err != nil {
			log.Printf("Error reading file: %v\n", err)
			return "", err
		}
		return string(salt), nil
	}
}
