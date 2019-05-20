package handler

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"qq3/paillier"
)

func GenerateHandler(w http.ResponseWriter, r *http.Request) {
	key, _ := paillier.GenerateKey(rand.Reader, 128)
	type stringfyPrivKey struct {
		N         string
		G         string
		NSquared  string
		P         string
		Pp        string
		Pminusone string
		Q         string
		Qq        string
		Qminusone string
		Pinvq     string
		Hp        string
		Hq        string
		Pq        string
	}
	privKey := stringfyPrivKey{
		key.N.String(),
		key.G.String(),
		key.NSquared.String(),
		key.P.String(),
		key.Pp.String(),
		key.Pminusone.String(),
		key.Q.String(),
		key.Qq.String(),
		key.Qminusone.String(),
		key.Pinvq.String(),
		key.Hp.String(),
		key.Hq.String(),
		key.Pq.String(),
	}
	response, _ := json.Marshal(privKey)
	_, _ = w.Write(response)
}

func EncryptHandle(w http.ResponseWriter, r *http.Request) {
	var input struct {
		N        string `json:"N"`
		G        string `json:"G"`
		NSquared string `json:"NSquared"`
		M        string `json:"M"`
	}
	body, _ := ioutil.ReadAll(r.Body)
	_ = json.Unmarshal(body, &input)
	N, _ := new(big.Int).SetString(input.N, 10)
	G, _ := new(big.Int).SetString(input.G, 10)
	NSquared, _ := new(big.Int).SetString(input.NSquared, 10)
	pubKey := paillier.PublicKey{
		N:        N,
		G:        G,
		NSquared: NSquared,
	}
	mInputMessage, _ := new(big.Int).SetString(input.M, 10)
	encryptedData, _ := paillier.Encrypt(&pubKey, mInputMessage.Bytes())
	response, _ := json.Marshal(encryptedData)
	_, _ = w.Write(response)
}

func DecryptHandle(w http.ResponseWriter, r *http.Request) {
	var input struct {
		N         string `json:"N"`
		G         string `json:"G"`
		NSquared  string `json:"NSquared"`
		P         string `json:"P"`
		Pp        string `json:"Pp"`
		Pminusone string `json:"Pminusone"`
		Q         string `json:"Q"`
		Qq        string `json:"Qq"`
		Qminusone string `json:"Qminusone"`
		Pinvq     string `json:"Pinvq"`
		Hp        string `json:"Hp"`
		Hq        string `json:"Hq"`
		Pq        string `json:"Pq"`
		M         []byte `json:"M"`
	}
	body, _ := ioutil.ReadAll(r.Body)
	_ = json.Unmarshal(body, &input)
	N, _ := new(big.Int).SetString(input.N, 10)
	G, _ := new(big.Int).SetString(input.G, 10)
	NSquared, _ := new(big.Int).SetString(input.NSquared, 10)
	P, _ := new(big.Int).SetString(input.P, 10)
	Pp, _ := new(big.Int).SetString(input.Pp, 10)
	Pminusone, _ := new(big.Int).SetString(input.Pminusone, 10)
	Q, _ := new(big.Int).SetString(input.Q, 10)
	Qq, _ := new(big.Int).SetString(input.Qq, 10)
	Qminusone, _ := new(big.Int).SetString(input.Qminusone, 10)
	Pinvq, _ := new(big.Int).SetString(input.Pinvq, 10)
	Hp, _ := new(big.Int).SetString(input.Hp, 10)
	Hq, _ := new(big.Int).SetString(input.Hq, 10)
	Pq, _ := new(big.Int).SetString(input.Pq, 10)
	pubKey := paillier.PublicKey{
		N:        N,
		NSquared: NSquared,
		G:        G,
	}
	privKey := paillier.PrivateKey{
		PublicKey: pubKey,
		P:         P,
		Pp:        Pp,
		Pminusone: Pminusone,
		Q:         Q,
		Qq:        Qq,
		Qminusone: Qminusone,
		Pinvq:     Pinvq,
		Hp:        Hp,
		Hq:        Hq,
		Pq:        Pq,
	}
	decryptedData, err := paillier.Decrypt(&privKey, input.M)
	if err != nil {
		fmt.Println(err.Error())
	}
	var decrypted struct {
		M *big.Int `json:"M"`
	}
	decrypted.M = new(big.Int).SetBytes(decryptedData)
	response, err := json.Marshal(decrypted.M)
	if err != nil {
		fmt.Println(err)
	}
	_, _ = w.Write(response)
}

func AddHandle(w http.ResponseWriter, r *http.Request) {
	var input struct {
		N        string `json:"N"`
		G        string `json:"G"`
		NSquared string `json:"NSquared"`
		Message1 []byte `json:"Message1"`
		Message2 []byte `json:"Message2"`
	}
	body, _ := ioutil.ReadAll(r.Body)
	_ = json.Unmarshal(body, &input)
	N, _ := new(big.Int).SetString(input.N, 10)
	G, _ := new(big.Int).SetString(input.G, 10)
	NSquared, _ := new(big.Int).SetString(input.NSquared, 10)
	pubKey := paillier.PublicKey{
		N:        N,
		G:        G,
		NSquared: NSquared,
	}
	ans := paillier.AddCipher(&pubKey, input.Message1, input.Message2)
	response, _ := json.Marshal(ans)
	_, _ = w.Write(response)
}
