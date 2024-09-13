package main

import (
	"crypto/rand"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	sw_bls12377 "github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/hash/mimc"
)

// Define a functio that generates well defined notes to test the circuit
func (circuit *RegisterCircuit) GenerateNotes(api frontend.API) NoteFull {
	//generate random bid T
	max := int64((1 << 63) - 1)
	T_0, _ := rand.Int(rand.Reader, big.NewInt(max))
	T_1, _ := rand.Int(rand.Reader, big.NewInt(max))
	var T [2]frontend.Variable = [2]frontend.Variable{T_0, T_1}

	//Generate sk
	r, _ := rand.Int(rand.Reader, big.NewInt(max))
	var Sk frontend.Variable = r

	//Compute Pk as hash of Sk
	Pk_mimc, _ := mimc.NewMiMC(api)
	Pk_mimc.Write(Sk)
	var Pk frontend.Variable = Pk_mimc.Sum()

	//Generate random Rho
	var Rho, _ = rand.Int(rand.Reader, big.NewInt(max))

	//Generate random R
	var R, _ = rand.Int(rand.Reader, big.NewInt(max))

	//Compute Cm as hash of T, R, Rho, Pk
	Cm_mimc, _ := mimc.NewMiMC(api)
	Cm_mimc.Write(T[0])
	Cm_mimc.Write(T[1])
	Cm_mimc.Write(R)
	Cm_mimc.Write(Rho)
	Cm_mimc.Write(Pk)
	var Cm frontend.Variable = Cm_mimc.Sum()

	return NoteFull{T, Pk, Sk, Rho, R, Cm}
}

type Note struct {
	//bid type
	T [2]frontend.Variable
	/*
		// Value of the coin
		V frontend.Variable
	*/
	// Public key of the owner
	Pk frontend.Variable

	/*
		// Secret key of the owner
		Sk frontend.Variable
	*/

	// Coin ID
	Rho frontend.Variable
	// Randomness used to generate the commitment
	R frontend.Variable
	// commitment of the coin
	Cm frontend.Variable
}

type NoteFull struct {
	//bid type
	T [2]frontend.Variable
	/*
		// Value of the coin
		V frontend.Variable
	*/
	// Public key of the owner
	Pk frontend.Variable

	// Secret key of the owner
	Sk frontend.Variable

	// Coin ID
	Rho frontend.Variable
	// Randomness used to generate the commitment
	R frontend.Variable
	// commitment of the coin
	Cm frontend.Variable
}

/*
// Take a random Rho and R and set the coin's values and the coin' owner's public key
func (coin *Note) CreateCoinToMint(pk [48]byte, v big.Int) *Note {

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
func (coin *Note) CreateCoinToPour(pk [48]byte, v big.Int) *Note {
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

func (c *Note) CommitCoin() [48]byte {
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
	_, err = mimc.Write(c.T[:])
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
*/

// variable names must start with a capital letter
type RegisterCircuit struct {
	//public inputs
	Cm_in                frontend.Variable    `gnark:",public"`
	Sk_in_xor_h_g_r_b    frontend.Variable    `gnark:",public"`
	Pk_out_xor_h_h_g_r_b frontend.Variable    `gnark:",public"`
	B_xor_h_h_h_g_r_b    frontend.Variable    `gnark:",public"`
	G_r                  sw_bls12377.G1Affine `gnark:",public"`
	G                    sw_bls12377.G1Affine `gnark:",public"`
	G_b                  sw_bls12377.G1Affine `gnark:",public"`

	//secret inputs
	N_in   Note
	Sk_in  frontend.Variable
	B_i    frontend.Variable
	G_r_b  sw_bls12377.G1Affine
	Pk_out frontend.Variable
	R      frontend.Variable
}

func (circuit *RegisterCircuit) Define(api frontend.API) error {

	var G = circuit.G
	//var G_ = circuit.G

	//1) C == (sk_in||pk_out||b) XOR (H(g_r_b)||H(H(g_r_b))||H(H(H(g_r_b))))

	//	H(g_r_b)
	H_g_r_b_mimc, _ := mimc.NewMiMC(api)
	H_g_r_b_mimc.Write(circuit.G_r_b.X)
	H_g_r_b_mimc.Write(circuit.G_r_b.Y)
	H_g_r_b := H_g_r_b_mimc.Sum()
	//	sk_in + H(g_r_b)
	Sk_in_xor_h_g_r_b := api.Add(circuit.Sk_in, H_g_r_b)
	api.AssertIsEqual(circuit.Sk_in_xor_h_g_r_b, Sk_in_xor_h_g_r_b)

	//	H(H(g_r_b))
	H_H_g_r_b_mimc, _ := mimc.NewMiMC(api)
	H_H_g_r_b_mimc.Write(H_g_r_b)
	h_h_g_r_b := H_H_g_r_b_mimc.Sum()
	//	pk_out XOR H(H(g_r_b))
	Pk_out_xor_h_h_g_r_b := api.Add(circuit.Pk_out, h_h_g_r_b)
	api.AssertIsEqual(circuit.Pk_out_xor_h_h_g_r_b, Pk_out_xor_h_h_g_r_b)

	//	H(H(H(g_r_b)))
	H_h_H_g_r_b_mimc, _ := mimc.NewMiMC(api)
	H_h_H_g_r_b_mimc.Write(h_h_g_r_b)
	H_H_H_g_r_b := H_h_H_g_r_b_mimc.Sum()
	//	b XOR H(H(H(g_r_b)))
	B_xor_h_h_h_g_r_b := api.Add(circuit.B_i, H_H_H_g_r_b)
	api.AssertIsEqual(circuit.B_xor_h_h_h_g_r_b, B_xor_h_h_h_g_r_b)

	//2) Cm_in == H(n_in.T, n_in.r, n_in.rho, n_in.Pk_in)
	Cm_in_min, _ := mimc.NewMiMC(api)
	Cm_in_min.Write(circuit.N_in.T[0])
	Cm_in_min.Write(circuit.N_in.T[1])
	Cm_in_min.Write(circuit.N_in.R)
	Cm_in_min.Write(circuit.N_in.Rho)
	Cm_in_min.Write(circuit.N_in.Pk)
	Cm_in := Cm_in_min.Sum()
	api.AssertIsEqual(circuit.Cm_in, Cm_in)

	//3) Pk_in == KeyGen(sk_in)
	Keygen_mimc, _ := mimc.NewMiMC(api)
	Keygen_mimc.Write(circuit.Sk_in)
	Pk_in := Keygen_mimc.Sum()
	api.AssertIsEqual(Pk_in, Keygen_mimc.Sum())

	//4) g_r == g^r
	var G_r = G.ScalarMul(api, G, circuit.R)
	api.AssertIsEqual(circuit.G_r.X, G_r.X)
	api.AssertIsEqual(circuit.G_r.Y, G_r.Y)

	//5) g_r_b == (g^b)^r
	G_r_b := circuit.G_b.ScalarMul(api, circuit.G_r, circuit.B_i)
	api.AssertIsEqual(circuit.G_r_b.X, G_r_b.X)
	api.AssertIsEqual(circuit.G_r_b.Y, G_r_b.Y)

	return nil

}

func main() {

	// compiles our circuit into a R1CS
	var circuit RegisterCircuit
	ccs, _ := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuit)

	// groth16 zkSNARK: Setup
	pk, vk, _ := groth16.Setup(ccs)
	var assignment RegisterCircuit

	//instance
	largeNumberStr2 := "97923138803228348321746045345131010467419377585473546576536403543095977357941379250157548391941453488266640124397"
	var bigIntNum2 big.Int
	bigIntNum2.SetString(largeNumberStr2, 10)
	var bigIntNum222 big.Int
	bigIntNum222.SetString(largeNumberStr2, 10)
	var bigIntNum223 big.Int
	bigIntNum223.SetString(largeNumberStr2, 10)

	largeNumberStr4 := "11866087567316108826895898840685431850595636147905001650355651391234320097047013321767472745863954087875397300508"
	var bigIntSkInXorHgrb big.Int
	bigIntSkInXorHgrb.SetString(largeNumberStr4, 10)

	//64799271645723455587876499287562231540108438073082782985683754858995228406599595152750907772028996088406963826775
	largeNumberStr5 := "129086677779431183240338057063818579994867288594568185708738638516757312717394247785418915059839433582160028125204"
	var bigIntPkOutXorHhgrb big.Int
	bigIntPkOutXorHhgrb.SetString(largeNumberStr5, 10)

	//247509191813070087604734131214916718544311164182026467345219683618650808332632407663507021366803513306546881526838
	largeNumberStr6 := "213777535342478826145619068287963541242730937567968724663073561852994147153634965161118668197218269549611256582440"
	var bigIntBxorHhhgrb big.Int
	bigIntBxorHhhgrb.SetString(largeNumberStr6, 10)
	assignment.Cm_in = frontend.Variable(bigIntNum2) //must be a number
	//203831271320381165583041774959570685434527305452115148233766083541991165947649203865415810075842964692419489031191
	assignment.Sk_in_xor_h_g_r_b = frontend.Variable(bigIntSkInXorHgrb)
	//assignment.Sk_in_xor_h_g_r_b = "203831271320381165583041774959570685434527305452115148233766083541991165947649203865415810075842964692419489031191"
	assignment.Pk_out_xor_h_h_g_r_b = frontend.Variable(bigIntPkOutXorHhgrb)
	assignment.B_xor_h_h_h_g_r_b = frontend.Variable(bigIntBxorHhhgrb)

	//40662129628873754736267876961679128669015529184351166531013321069758590089940590012970860239887658088459176147630
	largeNumberStr7 := "73237548591774980833465580103554296749417201406906935744081098138926652262613516658881763621469869314471598191994"
	var bigIntG_rX big.Int
	bigIntG_rX.SetString(largeNumberStr7, 10)

	//137574152425504189518083675552703433516071891763966884687761945592893336683595648192456388869618608994129453303591
	largeNumberStr8 := "12642988365915207449647990934289134368272554859334139889392369540662308531361619961017827567629066782011209976050"
	var bigIntG_rY big.Int
	bigIntG_rY.SetString(largeNumberStr8, 10)

	assignment.G_r = sw_bls12377.G1Affine{
		X: frontend.Variable(bigIntG_rX),
		Y: frontend.Variable(bigIntG_rY),
	}

	// 142653276895993031000006916266724128765221908004256063457362569275298456307915314952948497516099307719409858077584
	largeNumberStr10 := "142653276895993031000006916266724128765221908004256063457362569275298456307915314952948497516099307719409858077584"
	var bigIntNum4 big.Int
	bigIntNum4.SetString(largeNumberStr10, 10)

	//124869013296681382405525099997381943745958348199556996371954051753620340892927007930177100403663166477748695189485
	largeNumberStr11 := "124869013296681382405525099997381943745958348199556996371954051753620340892927007930177100403663166477748695189485"
	var bigIntNum5 big.Int
	bigIntNum5.SetString(largeNumberStr11, 10)

	assignment.G = sw_bls12377.G1Affine{
		X: frontend.Variable(bigIntNum4),
		Y: frontend.Variable(bigIntNum5),
	}

	//40662129628873754736267876961679128669015529184351166531013321069758590089940590012970860239887658088459176147630
	largeNumberStr12 := "40662129628873754736267876961679128669015529184351166531013321069758590089940590012970860239887658088459176147630"
	var bigIntG_bX big.Int
	bigIntG_bX.SetString(largeNumberStr12, 10)

	//137574152425504189518083675552703433516071891763966884687761945592893336683595648192456388869618608994129453303591
	largeNumberStr13 := "137574152425504189518083675552703433516071891763966884687761945592893336683595648192456388869618608994129453303591"
	var bigIntG_bY big.Int
	bigIntG_bY.SetString(largeNumberStr13, 10)

	assignment.G_b = sw_bls12377.G1Affine{
		X: frontend.Variable(bigIntG_bX),
		Y: frontend.Variable(bigIntG_bY),
	}

	// witness
	// Define the large number as a string
	largeNumberStr := "174318904806996777007223082677032033895598712436283838807748418363400238353280886561229810549989102368367181823304"
	var bigIntNum big.Int
	bigIntNum.SetString(largeNumberStr, 10)

	assignment.N_in = Note{
		T: [2]frontend.Variable{frontend.Variable(5267903284545154886), frontend.Variable(3427758880465230113)},
		//save as bigint
		Pk:  frontend.Variable(bigIntNum),
		Rho: frontend.Variable(1706047376502066796),
		R:   frontend.Variable(4312748660626696319),
		Cm:  frontend.Variable(bigIntNum222),
	}
	assignment.Sk_in = 3472352472855481322
	assignment.B_i = frontend.Variable(3206047376502166799)
	//40662129628873754736267876961679128669015529184351166531013321069758590089940590012970860239887658088459176147630
	largeNumberStr14 := "32607835244060611683605331688857170339502887804705168719185209092573100622180459949786476022808182126212885141918"
	var bigIntG_r_bX big.Int
	bigIntG_r_bX.SetString(largeNumberStr14, 10)

	//137574152425504189518083675552703433516071891763966884687761945592893336683595648192456388869618608994129453303591
	largeNumberStr15 := "219325212115656834382152939655638415953925251595620183154982460959254577375655557107453618578376790183089342057620"
	var bigIntG_r_bY big.Int
	bigIntG_r_bY.SetString(largeNumberStr15, 10)
	assignment.G_r_b = sw_bls12377.G1Affine{
		X: frontend.Variable(bigIntG_r_bX),
		Y: frontend.Variable(bigIntG_r_bY),
	}
	largeNumberStr3 := "16923138503228348321746045345131010467419377185473546576536403543095977357941379250157548391941453488266640124397"
	var bigIntNumPkOut big.Int
	bigIntNum223.SetString(largeNumberStr3, 10)
	assignment.Pk_out = frontend.Variable(bigIntNumPkOut)
	assignment.R = frontend.Variable(4506047376502066776)

	witness, _ := frontend.NewWitness(&assignment, ecc.BW6_761.ScalarField()) //BW6_761
	publicWitness, _ := witness.Public()

	// groth16: Prove & Verify
	proof, _ := groth16.Prove(ccs, pk, witness)
	//fmt.Println("Proof:", proof)
	groth16.Verify(proof, vk, publicWitness)
}
