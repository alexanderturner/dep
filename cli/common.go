package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
)

func promptYesNo(msg string) (result bool) {
	fmt.Print(msg)
	fmt.Print(" (yes/no): ")
	for {
		var answer string
		fmt.Scanln(&answer)
		switch answer {
		case "y", "yes":
			return true
		case "n", "no":
			return false
		default:
			fmt.Print("Please type 'yes' or 'no': ")
		}
	}
}

func promptReplaceRemote(remote string) (bool, error) {
	remotes, err := gitRemoteNames()
	if err != nil {
		return false, err
	}
	for _, r := range remotes {
		if r == remote {
			fmt.Println("There is already a git remote called", remote)
			if !promptYesNo("Are you sure you want to replace it?") {
				log.Println("The remote was not created. Please declare the desired local git remote name with --remote flag.")
				return false, nil
			}
		}
	}
	return true, nil
}

// encrypt string to base64 crypto using AES
func encrypt(text string) string {
	// key := []byte(keyText)
	key := []byte("5OAksWdoynxMJsRnB8AWvPFqW2v0Kg1g")
	plaintext := []byte(text)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	// convert to base64
	return base64.URLEncoding.EncodeToString(ciphertext)
}

// decrypt from base64 to decrypted string
func decrypt(cryptoText string) string {
	key := []byte("5OAksWdoynxMJsRnB8AWvPFqW2v0Kg1g")
	ciphertext, _ := base64.URLEncoding.DecodeString(cryptoText)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)

	return fmt.Sprintf("%s", ciphertext)
}
