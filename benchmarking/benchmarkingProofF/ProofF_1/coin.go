package main

import (
	"math/big"

	bls12377_fp "github.com/consensys/gnark-crypto/ecc/bls12-377/fp"
	mimc_bw6_761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/mimc"
)

type Coin struct {
	// Value of the coin
	V [48]byte
	// Public key of the owner
	Pk [48]byte
	// Secret key of the owner
	Sk [48]byte
	// Coin ID
	Rho [48]byte
	// Randomness used to generate the commitment
	R [48]byte
	// Signature of the coin
	Signature Signature
}

// Take a random Rho and R and set the coin's values and the coin' owner's public key
func (coin *Coin) CreateCoinToMint(pk [48]byte, v big.Int) *Coin {

	coin.V = new(bls12377_fp.Element).SetBigInt(&v).Bytes()
	coin.Pk = pk

	var rho_fp bls12377_fp.Element
	rho_fp.SetRandom()
	rho_bytes := rho_fp.Bytes()
	copy(coin.Rho[:], rho_bytes[:])

	var r_fp bls12377_fp.Element
	r_fp.SetRandom()
	r_bytes := r_fp.Bytes()
	copy(coin.R[:], r_bytes[:])

	return coin
}

// TODO: add the deterministic formula for rho
func (coin *Coin) CreateCoinToPour(pk [48]byte, v big.Int) *Coin {
	coin.V = new(bls12377_fp.Element).SetBigInt(&v).Bytes()
	coin.Pk = pk

	var rho_fp bls12377_fp.Element
	rho_fp.SetRandom()
	rho_bytes := rho_fp.Bytes()
	copy(coin.Rho[:], rho_bytes[:])

	var r_fp bls12377_fp.Element
	r_fp.SetRandom()
	r_bytes := r_fp.Bytes()
	copy(coin.R[:], r_bytes[:])

	return coin
}

func (c *Coin) CommitCoin() [48]byte {
	if c.R == [48]byte{} {
		// Chose a random R if not chosen already
		var r_fp bls12377_fp.Element
		r_fp.SetRandom()
		r_bytes := r_fp.Bytes()
		copy(c.R[:], r_bytes[:])
	}
	mimc := mimc_bw6_761.NewMiMC()
	_, err := mimc.Write(c.V[:])
	if err != nil {
		panic(err)
	}
	_, err = mimc.Write(c.Pk[:])
	if err != nil {
		panic(err)
	}
	_, err = mimc.Write(c.Rho[:])
	if err != nil {
		panic(err)
	}
	_, err = mimc.Write(c.R[:])
	if err != nil {
		panic(err)
	}
	var res_buf []byte
	res_buf = mimc.Sum(res_buf)
	return [48]byte(res_buf)
}


///////////////////////////////////////

package ps_threshold

// Implementation of Pointcheval-Sanders signature scheme (https://eprint.iacr.org/2015/525.pdf)
// for BLS12-377 curve (https://eprint.iacr.org/2018/962)

import (
	"encoding/hex"
	"fmt"
	"math/big"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-377"
	scalar_field "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	scalar_field_poly "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/polynomial"
)

type PublicKey struct {
	G_tilde curve.G2Affine
	X_tilde curve.G2Affine
	Y_tilde curve.G2Affine
}

type ThresholdSecretKey struct {
	X     scalar_field.Element
	Y     scalar_field.Element
	Index scalar_field.Element
}

type PartialSignature struct {
	Sigma_1 curve.G1Affine
	Sigma_2 curve.G1Affine
	Index   scalar_field.Element
}

type Signature struct {
	Sigma_1 curve.G1Affine
	Sigma_2 curve.G1Affine
}

type PSMessage struct{ Scalar scalar_field.Element }

// //////////////////////////////////////////////////////
// Serialization
// //////////////////////////////////////////////////////
func (msg *PSMessage) Bytes() []byte {
	res := msg.Scalar.Bytes()
	return res[:]
}

func (msg *PSMessage) SetBytes(b []byte) {
	msg.Scalar.SetBigInt(new(big.Int).SetBytes(b))
}

func (msg *PSMessage) ToScalar() scalar_field.Element {
	return msg.Scalar
}

func (msg *PSMessage) FromScalar(s scalar_field.Element) {
	msg.Scalar = s
}

func (msg *PSMessage) ToString() string {
	msg_fr := msg.ToScalar()
	msg_byte := msg_fr.Marshal()

	return hex.EncodeToString(msg_byte)
}

func (msg *PSMessage) FromString(s string) {
	msg_byte, _ := hex.DecodeString(s)
	msg_fr := new(scalar_field.Element)
	msg_fr.Unmarshal(msg_byte)
	msg.FromScalar(*msg_fr)
}

func (sk *ThresholdSecretKey) ToVector() scalar_field.Vector {
	return []scalar_field.Element{sk.X, sk.Y, sk.Index}
}

func (sk *ThresholdSecretKey) FromVector(slice []scalar_field.Element) {
	sk.X = slice[0]
	sk.Y = slice[1]
	sk.Index = slice[2]
}

func (sk *ThresholdSecretKey) ToString() string {
	v := sk.ToVector()
	b, _ := v.MarshalBinary()
	return hex.EncodeToString(b)
}

func (sk *ThresholdSecretKey) FromString(s string) {
	b, _ := hex.DecodeString(s)
	v := new(scalar_field.Vector)
	v.UnmarshalBinary(b)
	sk.FromVector(*v)
}

func (pk *PublicKey) ToString() string {
	x_string := pk.X_tilde.Marshal()
	y_string := pk.Y_tilde.Marshal()
	g_string := pk.G_tilde.Marshal()
	return hex.EncodeToString(x_string) + hex.EncodeToString(y_string) + hex.EncodeToString(g_string)
}

func (pk *PublicKey) FromString(s string) {
	x_string, _ := hex.DecodeString(s[:len(s)/3])
	y_string, _ := hex.DecodeString(s[len(s)/3 : 2*len(s)/3])
	g_string, _ := hex.DecodeString(s[2*len(s)/3:])
	pk.X_tilde.Unmarshal(x_string)
	pk.Y_tilde.Unmarshal(y_string)
	pk.G_tilde.Unmarshal(g_string)
}

func (sig *PartialSignature) ToString() string {
	s1 := sig.Sigma_1.Marshal()
	s2 := sig.Sigma_2.Marshal()
	i := sig.Index.Marshal()
	return hex.EncodeToString(s1) + hex.EncodeToString(s2) + hex.EncodeToString(i)
}

func (sig *PartialSignature) FromString(s string) error {
	s1, _ := hex.DecodeString(s[:4*curve.SizeOfG1AffineCompressed])
	s2, _ := hex.DecodeString(s[4*curve.SizeOfG1AffineCompressed : 2*4*curve.SizeOfG1AffineCompressed])
	i, _ := hex.DecodeString(s[2*4*curve.SizeOfG1AffineCompressed:])
	err := sig.Sigma_1.Unmarshal(s1)
	if err != nil {
		return err
	}
	err = sig.Sigma_2.Unmarshal(s2)
	if err != nil {
		return err
	}
	sig.Index.Unmarshal(i)
	return nil
}

func (sig *PartialSignature) Bytes() []byte {
	s1 := sig.Sigma_1.Marshal()
	s2 := sig.Sigma_2.Marshal()
	i := sig.Index.Marshal()
	return append(append(s1, s2...), i...)
}

func (sig *PartialSignature) SetBytes(b []byte) error {
	if len(b) != 2*curve.SizeOfG1AffineUncompressed+32 {
		return fmt.Errorf("invalid length")
	}
	err := sig.Sigma_1.Unmarshal(b[:curve.SizeOfG1AffineUncompressed])
	if err != nil {
		return err
	}
	err = sig.Sigma_2.Unmarshal(b[curve.SizeOfG1AffineUncompressed : 2*curve.SizeOfG1AffineUncompressed])
	if err != nil {
		return err
	}
	sig.Index.Unmarshal(b[2*curve.SizeOfG1AffineUncompressed:])
	return nil
}

func (sig *Signature) ToString() string {
	s1 := sig.Sigma_1.Marshal()
	s2 := sig.Sigma_2.Marshal()
	return hex.EncodeToString(s1) + hex.EncodeToString(s2)
}

func (sig *Signature) FromString(s string) {
	s1, _ := hex.DecodeString(s[:len(s)/2])
	s2, _ := hex.DecodeString(s[len(s)/2:])
	sig.Sigma_1.Unmarshal(s1)
	sig.Sigma_2.Unmarshal(s2)
}

////////////////////////////////////////////////////////
// PS Threshold Signature Scheme
////////////////////////////////////////////////////////

func randomPolynomial(degree int) scalar_field_poly.Polynomial {
	coefficients := make([]scalar_field.Element, degree+1)
	for i := 0; i <= degree; i++ {
		coefficients[i].SetRandom()
	}
	return coefficients
}

func NewThresholdSecretKeys(t int, n int) []ThresholdSecretKey {
	v := randomPolynomial(t - 1)
	w := randomPolynomial(t - 1)
	// n+1 keys because the first key is the aggregated key
	keys := make([]ThresholdSecretKey, n+1)
	for i := 0; i <= n; i++ {
		var scalar scalar_field.Element
		scalar.SetUint64(uint64(i))
		key := new(ThresholdSecretKey)
		key.X = v.Eval(&scalar)
		key.Y = w.Eval(&scalar)
		key.Index = scalar
		keys[i] = *key
	}
	return keys
}

func ThresholdPublicKeys(privateKeys []ThresholdSecretKey) []PublicKey {
	pks := make([]PublicKey, len(privateKeys))
	g_tilde, _ := new(scalar_field.Element).SetRandom()
	G_tilde := *new(curve.G2Affine).ScalarMultiplicationBase(g_tilde.BigInt(new(big.Int)))
	for i := 0; i < len(privateKeys); i++ {
		pk := new(PublicKey)
		pk.X_tilde = *new(curve.G2Affine).ScalarMultiplication(&G_tilde, privateKeys[i].X.BigInt(new(big.Int)))
		pk.Y_tilde = *new(curve.G2Affine).ScalarMultiplication(&G_tilde, privateKeys[i].Y.BigInt(new(big.Int)))
		pk.G_tilde = G_tilde
		pks[i] = *pk
	}
	return pks
}

func (sk *ThresholdSecretKey) ThresholdSign(msg PSMessage) PartialSignature {

	// TODO: replace with hash to curve

	msg_byte := msg.Scalar.Bytes()
	h, _ := curve.HashToG1(msg_byte[:], []byte("ACT implementation"))

	if h.IsInfinity() {
		fmt.Println("h is at infinity")
		panic("h is at infinity")
	}

	// Compute the signature
	var s scalar_field.Element
	s.Set(&sk.Y)
	s.Mul(&s, &msg.Scalar)
	s.Add(&s, &sk.X)

	var sigma_2 curve.G1Affine
	sigma_2.ScalarMultiplication(&h, s.BigInt(new(big.Int)))

	var partialSignature PartialSignature
	partialSignature.Sigma_1 = h
	partialSignature.Sigma_2 = sigma_2
	partialSignature.Index = sk.Index

	return partialSignature
}

// Aggregate signatures
// sigma = (sigma_1, sigma_2)
//
//	= Sum(i)(l_i * sigma_i)
//
// with l_i = [Product(j!=i)(1<j<t) (0-j)] + [Product(j!=i)(1<j<t) (i-j)]^-1
//
// Returns sigma, the aggregated signature
func ThresholdAggregateSignatures(sigs []PartialSignature) Signature {
	h := sigs[0].Sigma_1
	// Makes sure that h is the same for all signatures
	for i := 0; i < len(sigs); i++ {
		if !sigs[i].Sigma_1.Equal(&h) {
			panic("h is not the same for all signatures")
		}
	}

	index_list := make([]scalar_field.Element, len(sigs))
	for i := 0; i < len(sigs); i++ {
		index_list[i] = sigs[i].Index
	}

	// Sigma_2
	var sigma_2 curve.G1Affine

	// Sigma = Sum(i)(l_i * sigma_i )
	for i := 0; i < len(sigs); i++ {
		// Compute Lagrange coefficient
		// l1 = Product(j!=i)(1<j<t) (0-j)
		// l2' = Product(j!=i)(1<j<t) (i-j)
		// l2 = l2'^-1
		// l_i = l1 + l2

		l1 := scalar_field.One()
		for j := 0; j < len(sigs); j++ {
			if i != j {
				var zero_scalar, j_scalar, sub scalar_field.Element
				zero_scalar.SetZero()
				j_scalar = index_list[j]
				sub.Sub(&zero_scalar, &j_scalar)
				l1.Mul(&l1, &sub)
			}
		}

		l2 := scalar_field.One()
		for j := 0; j < len(sigs); j++ {
			if i != j {
				var i_scalar, j_scalar, sub scalar_field.Element
				i_scalar = index_list[i]
				j_scalar = index_list[j]
				sub.Sub(&i_scalar, &j_scalar)
				l2.Mul(&l2, &sub)
			}
		}
		l2.Inverse(&l2)
		var l_i scalar_field.Element
		l_i.Mul(&l1, &l2)

		// l_i * sigma_i
		var product curve.G1Affine
		sigma_i := sigs[i].Sigma_2
		product.ScalarMultiplication(&sigma_i, l_i.BigInt(new(big.Int)))
		// Sum with sigma_2
		if i == 0 {
			sigma_2 = product
		} else {
			sigma_2.Add(&sigma_2, &product)
		}
	}

	return Signature{h, sigma_2}
}

func (sk *ThresholdSecretKey) Sign(msg *PSMessage) [2]curve.G1Affine {
	// Get a random point on the curve
	r, _ := new(scalar_field.Element).SetRandom()
	h := new(curve.G1Affine).ScalarMultiplicationBase(r.BigInt(new(big.Int)))
	if h.IsInfinity() {
		fmt.Println("h is at infinity")
		panic("h is at infinity")
	}

	// Compute the signature
	s := new(scalar_field.Element)
	s.Set(&sk.Y)
	s.Mul(s, &msg.Scalar)
	s.Add(s, &sk.X)

	sigma_1 := h
	sigma_2 := new(curve.G1Affine).ScalarMultiplication(h, s.BigInt(new(big.Int)))

	sigma := [2]curve.G1Affine{*sigma_1, *sigma_2}

	return sigma
}

func (pk *PublicKey) Verify(msg *scalar_field.Element, sigma_1 *curve.G1Affine, sigma_2 *curve.G1Affine) bool {
	// e(sigma_1, X_tilde * Y_tilde^msg) == e(sigma_2, G_tilde)
	// X_tilde * Y_tilde^msg
	lhs_2 := new(curve.G2Affine).ScalarMultiplication(&pk.Y_tilde, msg.BigInt(new(big.Int)))
	lhs_2.Add(&pk.X_tilde, lhs_2)

	lhs, _ := curve.Pair([]curve.G1Affine{*sigma_1}, []curve.G2Affine{*lhs_2})
	rhs, _ := curve.Pair([]curve.G1Affine{*sigma_2}, []curve.G2Affine{pk.G_tilde})

	if lhs.Equal(&rhs) {
		return true
	} else {
		return false
	}

}

