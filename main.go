package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"qq3/handler"
	"qq3/paillier"
)

func main() {
	// Generate a 128-bit private key.
	privKey, _ := paillier.GenerateKey(rand.Reader, 128)

	// Encrypt the number "15".
	m15 := new(big.Int).SetInt64(15)
	c15, _ := paillier.Encrypt(&privKey.PublicKey, m15.Bytes())
	plainEncrypted15 := new(big.Int).SetBytes(c15)
	fmt.Println("Encrypted15:", plainEncrypted15)
	c15ByEncrypted := plainEncrypted15.Bytes()
	// Decrypt the number "15".

	d, _ := paillier.Decrypt(privKey, c15ByEncrypted)
	plainText := new(big.Int).SetBytes(d)
	fmt.Println("Decryption Result of 15: ", plainText.String()) // 15

	// Encrypt the number "20".
	m20 := new(big.Int).SetInt64(20)
	c20, _ := paillier.Encrypt(&privKey.PublicKey, m20.Bytes())
	plainEncrypted20 := new(big.Int).SetBytes(c20)
	fmt.Println("Encrypted20:", plainEncrypted20.String())

	// Add the encrypted integers 15 and 20 together.
	plusM15M20 := paillier.AddCipher(&privKey.PublicKey, c15, c20)
	decryptedAddition, _ := paillier.Decrypt(privKey, plusM15M20)
	fmt.Println("Result of 15+20(")
	fmt.Println(new(big.Int).SetBytes(plusM15M20).String())
	fmt.Println(")after decryption: ",
		new(big.Int).SetBytes(decryptedAddition).String())

	http.HandleFunc("/generate", handler.GenerateHandler)
	http.HandleFunc("/encrypt", handler.EncryptHandle)
	http.HandleFunc("/decrypt", handler.DecryptHandle)
	http.HandleFunc("/add", handler.AddHandle)
	err := http.ListenAndServe(":8082", nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
