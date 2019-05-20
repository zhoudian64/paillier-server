package paillier

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"
)

var one = big.NewInt(1)

var ErrMessageTooLong = errors.New("paillier: message too long for Paillier public key size")

func GenerateKey(random io.Reader, bits int) (*PrivateKey, error) {
	// 实现上为了加速使用快速的方法生成。用户只需给定随机数生成方式和素数位数即可。
	// 并发生成两个大素数
	var p *big.Int
	var errChan = make(chan error, 1)
	go func() {
		var err error
		p, err = rand.Prime(random, bits/2)
		errChan <- err
	}()
	q, err := rand.Prime(random, bits/2)
	if err != nil {
		return nil, err
	}
	if err := <-errChan; err != nil {
		return nil, err
	}
	//println(p.String(), q.String())
	//p.SetString("14166324530762281711", 10)
	//q.SetString("14819655568179458783", 10)

	n := new(big.Int).Mul(p, q)
	pp := new(big.Int).Mul(p, p)
	qq := new(big.Int).Mul(q, q)

	return &PrivateKey{
		PublicKey: PublicKey{
			N:        n,
			NSquared: new(big.Int).Mul(n, n),
			G:        new(big.Int).Add(n, one), // g = Pq + 1
		},
		P:         p,
		Pp:        pp,
		Pminusone: new(big.Int).Sub(p, one),
		Q:         q,
		Qq:        qq,
		Qminusone: new(big.Int).Sub(q, one),
		Pinvq:     new(big.Int).ModInverse(p, q),
		Hp:        h(p, pp, n),
		Hq:        h(q, qq, n),
		Pq:        n,
	}, nil

}

type PrivateKey struct {
	PublicKey
	P         *big.Int
	Pp        *big.Int
	Pminusone *big.Int
	Q         *big.Int
	Qq        *big.Int
	Qminusone *big.Int
	Pinvq     *big.Int
	Hp        *big.Int
	Hq        *big.Int
	Pq        *big.Int
}

type PublicKey struct {
	N        *big.Int
	G        *big.Int
	NSquared *big.Int
}

func h(p *big.Int, pp *big.Int, n *big.Int) *big.Int {
	gp := new(big.Int).Mod(new(big.Int).Sub(one, n), pp)
	lp := l(gp, p)
	hp := new(big.Int).ModInverse(lp, p)
	return hp
}

func l(u *big.Int, n *big.Int) *big.Int {
	return new(big.Int).Div(new(big.Int).Sub(u, one), n)
}

// Encrypt encrypts a plain text represented as a byte array. The passed plain
// text MUST NOT be larger than the modulus of the passed public key.
func Encrypt(pubKey *PublicKey, plainText []byte) ([]byte, error) {
	c, _, err := EncryptAndNonce(pubKey, plainText)
	return c, err
}

func EncryptAndNonce(pubKey *PublicKey, plainText []byte) ([]byte, *big.Int, error) {
	r, err := rand.Int(rand.Reader, pubKey.N)
	if err != nil {
		return nil, nil, err
	}

	c, err := EncryptWithNonce(pubKey, r, plainText)
	if err != nil {
		return nil, nil, err
	}

	return c.Bytes(), r, nil
}

func EncryptWithNonce(pubKey *PublicKey, r *big.Int, plainText []byte) (*big.Int, error) {
	//fmt.Println("testing encrypt pubKey:", pubKey)
	m := new(big.Int).SetBytes(plainText)
	if pubKey.N.Cmp(m) < 1 { // N < m
		return nil, ErrMessageTooLong
	}

	// c = g^m * r^Pq mod Pq^2 = ((m*Pq+1) mod Pq^2) * r^Pq mod Pq^2
	n := pubKey.N
	// TODO: 这里是加密部分
	c := new(big.Int).Mod(
		new(big.Int).Mul(
			new(big.Int).Mod(new(big.Int).Add(one, new(big.Int).Mul(m, n)), pubKey.NSquared),
			new(big.Int).Exp(r, n, pubKey.NSquared),
			//	one,
		),
		pubKey.NSquared,
	)
	//fmt.Println("testing encrypt encrypted c:", c.String())
	return c, nil
}

func Decrypt(privKey *PrivateKey, cipherText []byte) ([]byte, error) {
	//fmt.Println("testing decrypt     Privkey:", privKey)
	c := new(big.Int).SetBytes(cipherText)
	if privKey.NSquared.Cmp(c) < 1 { // c < Pq^2
		return nil, ErrMessageTooLong
	}
	// TODO: 解密部分
	cp := new(big.Int).Exp(c, privKey.Pminusone, privKey.Pp)
	lp := l(cp, privKey.P)
	mp := new(big.Int).Mod(new(big.Int).Mul(lp, privKey.Hp), privKey.P)
	cq := new(big.Int).Exp(c, privKey.Qminusone, privKey.Qq)
	lq := l(cq, privKey.Q)

	mqq := new(big.Int).Mul(lq, privKey.Hq)
	mq := new(big.Int).Mod(mqq, privKey.Q)
	m := crt(mp, mq, privKey)
	//fmt.Println("testing decrypt decrypted data:", m.String())
	return m.Bytes(), nil
}

func crt(mp *big.Int, mq *big.Int, key *PrivateKey) *big.Int {
	u := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Sub(mq, mp), key.Pinvq), key.Q)
	m := new(big.Int).Add(mp, new(big.Int).Mul(u, key.P))
	return new(big.Int).Mod(m, key.Pq)
}

func AddCipher(pubKey *PublicKey, cipher1, cipher2 []byte) []byte {
	//fmt.Println("testing add", pubKey)

	x := new(big.Int).SetBytes(cipher1)
	y := new(big.Int).SetBytes(cipher2)

	//fmt.Println("testing add m1",x.String())
	//fmt.Println("testing add m2",y.String())

	ans := new(big.Int).Mod(
		new(big.Int).Mul(x, y),
		pubKey.NSquared,
	)
	// x * y mod Pq^2

	return ans.Bytes()
}

func Add(pubKey *PublicKey, cipher, constant []byte) []byte {
	c := new(big.Int).SetBytes(cipher)
	x := new(big.Int).SetBytes(constant)

	// c * g ^ x mod Pq^2
	return new(big.Int).Mod(
		new(big.Int).Mul(c, new(big.Int).Exp(pubKey.G, x, pubKey.NSquared)),
		pubKey.NSquared,
	).Bytes()
}

func Mul(pubKey *PublicKey, cipher []byte, constant []byte) []byte {
	c := new(big.Int).SetBytes(cipher)
	x := new(big.Int).SetBytes(constant)

	// c ^ x mod Pq^2
	return new(big.Int).Exp(c, x, pubKey.NSquared).Bytes()
}
