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
	Rt                        frontend.Variable      `gnark:",public"`
	Cm_list                   [256]frontend.Variable `gnark:",public"`
	Sn_old_list               frontend.Variable      `gnark:",public"`
	Cm_new_list               frontend.Variable      `gnark:",public"`
	Sk_in_xor_h_g_r_b_list    frontend.Variable      `gnark:",public"`
	Pk_out_xor_h_h_g_r_b_list frontend.Variable      `gnark:",public"`
	B_xor_h_h_h_g_r_b_list    frontend.Variable      `gnark:",public"`
	G_r_list                  sw_bls12377.G1Affine   `gnark:",public"`
	G                         sw_bls12377.G1Affine   `gnark:",public"`
	G_b_list                  sw_bls12377.G1Affine   `gnark:",public"`

	//secret inputs
	Path_list   [8]frontend.Variable
	N_old_list  NoteFull
	N_new_list  NoteFull
	Sk_old_list frontend.Variable
	//r_j_list    frontend.Variable
	B_i_list   frontend.Variable
	G_r_b_list sw_bls12377.G1Affine
	//Pk_j_list frontend.Variable
	R_list       frontend.Variable
	R_j_new_list frontend.Variable
	//r_j_list_transfert frontend.Variable
}

func (circuit *RegisterCircuit) Define(api frontend.API) error {

	var l = 8
	var h = 3

	var G []sw_bls12377.G1Affine
	for i := 0; i < l; i++ {
		G = append(G, circuit.G)
	}

	////////
	// Start of Transfert subroutine
	////////

	//Compute sn_old

	for j := 0; j < l; j++ {
		Keygen_mimc, _ := mimc.NewMiMC(api)
		Keygen_mimc.Write(circuit.Sk_old_list)
		Keygen_mimc.Write(circuit.N_old_list.Rho)
		Sn_in_computed := Keygen_mimc.Sum()
		api.AssertIsEqual(circuit.Sn_old_list, Sn_in_computed)
	}

	//Compute Rho_new_list
	var Rho_new_list []frontend.Variable
	for j := 0; j < l; j++ {
		//Compute Rho_new
		Rho_new_mimc, _ := mimc.NewMiMC(api)
		for i := 0; i < l; i++ {
			Rho_new_mimc.Write(circuit.Sn_old_list)
		}
		Rho_new := Rho_new_mimc.Sum()
		Rho_new_list = append(Rho_new_list, Rho_new)
		api.Println(4441111441)
		api.Println(Rho_new)
		api.Println(circuit.N_new_list.Rho)
		api.Println(4441111441)
		api.AssertIsEqual(circuit.N_new_list.Rho, Rho_new)
	}

	//compute cm_new_list
	var Cm_new_list []frontend.Variable
	for j := 0; j < l; j++ {
		Cm_new_mimc, _ := mimc.NewMiMC(api)
		Cm_new_mimc.Write(circuit.N_new_list.T[0])
		Cm_new_mimc.Write(circuit.N_new_list.T[1])
		Cm_new_mimc.Write(circuit.R_j_new_list)
		Cm_new_mimc.Write(circuit.N_new_list.Rho)
		Cm_new_mimc.Write(circuit.N_new_list.Pk)
		Cm_new := Cm_new_mimc.Sum()
		Cm_new_list = append(Cm_new_list, Cm_new)
		api.AssertIsEqual(circuit.Cm_new_list, Cm_new)
	}

	//encrypt
	var Sk_in_computed []frontend.Variable
	var H_g_r_b frontend.Variable

	for i := 0; i < l; i++ {
		//	H(g_r_b)
		H_g_r_b_mimc, _ := mimc.NewMiMC(api)
		H_g_r_b_mimc.Write(circuit.G_r_b_list.X)
		H_g_r_b_mimc.Write(circuit.G_r_b_list.Y)
		H_g_r_b = H_g_r_b_mimc.Sum()
		//	sk_in + H(g_r_b)
		Sk_in_computed = append(Sk_in_computed, api.Sub(circuit.Sk_in_xor_h_g_r_b_list, H_g_r_b))
		api.AssertIsEqual(circuit.N_old_list.Sk, Sk_in_computed[i])
	}

	var Pk_out_computed []frontend.Variable
	var h_h_g_r_b frontend.Variable
	//	H(H(g_r_b))
	for v := 0; v < l; v++ {
		H_H_g_r_b_mimc, _ := mimc.NewMiMC(api)
		H_H_g_r_b_mimc.Write(H_g_r_b)
		h_h_g_r_b = H_H_g_r_b_mimc.Sum()
		//	pk_out XOR H(H(g_r_b))
		Pk_out_computed = append(Pk_out_computed, api.Sub(circuit.Pk_out_xor_h_h_g_r_b_list, h_h_g_r_b))
		api.AssertIsEqual(circuit.N_new_list.Pk, Pk_out_computed[v])
	}

	var B_computed []frontend.Variable
	for i := 0; i < l; i++ {
		//	H(H(H(g_r_b)))
		H_h_H_g_r_b_mimc, _ := mimc.NewMiMC(api)
		H_h_H_g_r_b_mimc.Write(h_h_g_r_b)
		H_H_H_g_r_b := H_h_H_g_r_b_mimc.Sum()
		//	b XOR H(H(H(g_r_b)))
		B_computed = append(B_computed, api.Sub(circuit.B_xor_h_h_h_g_r_b_list, H_H_H_g_r_b))
		api.AssertIsEqual(circuit.B_i_list, B_computed[i])
	}

	////////
	// End of Transfert subroutine
	////////

	////////
	// check if balance is preserved
	////////

	var left_sum frontend.Variable = frontend.Variable(0)
	for i := 0; i < l; i++ {
		left_sum = api.Add(left_sum, circuit.N_old_list.T[1])
	}

	var right_sum frontend.Variable = frontend.Variable(0)
	for i := 0; i < l; i++ {
		right_sum = api.Add(right_sum, circuit.N_new_list.T[1])
	}

	api.AssertIsEqual(left_sum, right_sum)

	////////
	// Check merkle proof (dummy path and root, only for benchmarking)
	////////

	for i := 0; i < l; i++ {
		mimc, _ := mimc.NewMiMC(api)
		for k := 0; k < h; k++ {
			left := api.Select(circuit.Path_list[i], circuit.Cm_list[2*h+1], circuit.Cm_list[2*h+2])
			right := api.Select(circuit.Path_list[i], circuit.Cm_list[2*h+2], circuit.Cm_list[2*h+1])
			mimc.Write(left)
			mimc.Write(right)
		}
		root := mimc.Sum()
		api.Println(4441111441)
		api.Println(root)
		api.Println(4441111441)
		api.AssertIsEqual(circuit.Rt, root)
	}

	////////
	// ensure Pk == KeyGen(sk)
	////////
	for i := 0; i < l; i++ {
		Keygen_mimc, _ := mimc.NewMiMC(api)
		Keygen_mimc.Write(circuit.Sk_old_list)
		Pk_in := Keygen_mimc.Sum()
		api.AssertIsEqual(circuit.N_old_list.Pk, Pk_in)
	}

	////////
	// ensure g_r == g^r
	////////

	//4)
	for i := 0; i < l; i++ {
		var G_r = G[i].ScalarMul(api, G[i], circuit.R_list)
		api.AssertIsEqual(circuit.G_r_list.X, G_r.X)
		api.AssertIsEqual(circuit.G_r_list.Y, G_r.Y)
	}

	////////
	// ensure g_r_b == (g^b)^r
	////////

	var G_b_list []sw_bls12377.G1Affine
	for i := 0; i < l; i++ {
		G_b_list = append(G_b_list, circuit.G_b_list)
	}

	//5) g_r_b == (g^b)^r
	for i := 0; i < l; i++ {
		G_r_b := G_b_list[i].ScalarMul(api, circuit.G_r_list, circuit.B_i_list)
		api.AssertIsEqual(circuit.G_r_b_list.X, G_r_b.X)
		api.AssertIsEqual(circuit.G_r_b_list.Y, G_r_b.Y)
	}

	return nil

}

func main() {

	//l := 5

	// compiles our circuit into a R1CS
	var circuit RegisterCircuit
	ccs, _ := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuit)

	// groth16 zkSNARK: Setup
	pk, vk, _ := groth16.Setup(ccs)
	var assignment RegisterCircuit

	//instance
	largeNumberStr09 := "72371257857203462926422275947487913781763386057862350479926612614873311592710988561652969962873132670481372852598"
	largeNumberStr2 := "113659196871612072543459970138388673998289533012026854082664823224600205847961680581286110096985633740750331734254"
	var bigIntNum2 big.Int
	bigIntNum2.SetString(largeNumberStr2, 10)
	var bigIntNum02 big.Int
	bigIntNum02.SetString(largeNumberStr2, 10)
	var bigIntNum09 big.Int
	bigIntNum09.SetString(largeNumberStr09, 10)
	var bigIntNum222 big.Int
	bigIntNum222.SetString(largeNumberStr2, 10)
	var bigIntNum223 big.Int
	bigIntNum223.SetString(largeNumberStr2, 10)

	largeNumberStr4 := "11866087567316108826895898840685431850595636147905001650355651391234320097047013321767472745863954087875397300508"
	var bigIntSkInXorHgrb big.Int
	bigIntSkInXorHgrb.SetString(largeNumberStr4, 10)

	//64799271645723455587876499287562231540108438073082782985683754858995228406599595152750907772028996088406963826775
	largeNumberStr5 := "44741156573458866236908406045957080354072488275937363976602794213437082722334311571679837470255175826086888490331"
	var bigIntPkOutXorHhgrb big.Int
	bigIntPkOutXorHhgrb.SetString(largeNumberStr5, 10)

	//247509191813070087604734131214916718544311164182026467345219683618650808332632407663507021366803513306546881526838
	largeNumberStr6 := "213777535342478826145619068287963541242730937567968724663073561852994147153634965161118668197218269549611256582440"
	var bigIntBxorHhhgrb big.Int
	bigIntBxorHhhgrb.SetString(largeNumberStr6, 10)
	assignment.Sn_old_list = frontend.Variable(bigIntNum02) //must be a number

	///////////
	// merkle tree verification
	///////////
	// dummy path and root (only for benchmarking)

	largeNumber := "36565350314434984676939566407959663774564372951806997595707794717614144179949634879639811089129601330391627854341"
	var bigIntN big.Int
	bigIntN.SetString(largeNumber, 10)

	var Cm_list_ [256]frontend.Variable = [256]frontend.Variable{}

	for i := 0; i < 256; i++ {
		Cm_list_[i] = frontend.Variable(bigIntN)
	}

	assignment.Cm_list = Cm_list_ //must be a number

	largeNumberRt := "49861458376678319477398468105169118761312075858657298692763533898205470074867179152027137271468949544703282610343"
	var bigIntRt big.Int
	bigIntRt.SetString(largeNumberRt, 10)
	assignment.Rt = frontend.Variable(bigIntRt)

	var Path_list_ [8]frontend.Variable = [8]frontend.Variable{}

	for i := 0; i < 8; i++ {
		Path_list_[i] = frontend.Variable(0)
	}

	assignment.Path_list = Path_list_

	///////////
	// transfert
	///////////

	assignment.Cm_new_list = frontend.Variable(bigIntNum09)
	assignment.R_j_new_list = frontend.Variable(4506047376502066776)
	//203831271320381165583041774959570685434527305452115148233766083541991165947649203865415810075842964692419489031191
	assignment.Sk_in_xor_h_g_r_b_list = frontend.Variable(bigIntSkInXorHgrb)
	//assignment.Sk_in_xor_h_g_r_b = "203831271320381165583041774959570685434527305452115148233766083541991165947649203865415810075842964692419489031191"
	assignment.Pk_out_xor_h_h_g_r_b_list = frontend.Variable(bigIntPkOutXorHhgrb)
	assignment.B_xor_h_h_h_g_r_b_list = frontend.Variable(bigIntBxorHhhgrb)

	//40662129628873754736267876961679128669015529184351166531013321069758590089940590012970860239887658088459176147630
	largeNumberStr7 := "73237548591774980833465580103554296749417201406906935744081098138926652262613516658881763621469869314471598191994"
	var bigIntG_rX big.Int
	bigIntG_rX.SetString(largeNumberStr7, 10)

	//137574152425504189518083675552703433516071891763966884687761945592893336683595648192456388869618608994129453303591
	largeNumberStr8 := "12642988365915207449647990934289134368272554859334139889392369540662308531361619961017827567629066782011209976050"
	var bigIntG_rY big.Int
	bigIntG_rY.SetString(largeNumberStr8, 10)

	assignment.G_r_list = sw_bls12377.G1Affine{
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

	assignment.G_b_list = sw_bls12377.G1Affine{
		X: frontend.Variable(bigIntG_bX),
		Y: frontend.Variable(bigIntG_bY),
	}

	// witness
	// Define the large number as a string
	largeNumberStr := "174318904806996777007223082677032033895598712436283838807748418363400238353280886561229810549989102368367181823304"
	var bigIntNum big.Int
	var bigIntNumGreat big.Int
	bigIntNum.SetString(largeNumberStr, 10)
	bigIntNumGreat.SetString(largeNumberStr, 10)

	Nbrstr := "20636640896979731940793627139413627245289804848019706900722220506017852242246254423043713318302642404351571488834"
	var bigIntNbr big.Int
	bigIntNbr.SetString(Nbrstr, 10)

	assignment.N_old_list = NoteFull{
		T: [2]frontend.Variable{frontend.Variable(5267903284545154886), frontend.Variable(3427758880465230113)},
		//save as bigint
		Pk:  frontend.Variable(bigIntNum),
		Sk:  frontend.Variable(3472352472855481322),
		Rho: frontend.Variable(1706047376502066796),
		R:   frontend.Variable(4312748660626696319),
		Cm:  frontend.Variable(bigIntNum222),
	}

	assignment.N_new_list = NoteFull{
		T: [2]frontend.Variable{frontend.Variable(5267903284545154886), frontend.Variable(3427758880465230113)},
		//save as bigint
		Pk:  frontend.Variable(bigIntNumGreat),
		Sk:  frontend.Variable(3472352472855481322), //1706047376502066796
		Rho: frontend.Variable(bigIntNbr),
		R:   frontend.Variable(4312748660626696319),
		Cm:  frontend.Variable(bigIntNum222),
	}

	assignment.Sk_old_list = 3472352472855481322
	assignment.B_i_list = frontend.Variable(3206047376502166799)
	//40662129628873754736267876961679128669015529184351166531013321069758590089940590012970860239887658088459176147630
	largeNumberStr14 := "32607835244060611683605331688857170339502887804705168719185209092573100622180459949786476022808182126212885141918"
	var bigIntG_r_bX big.Int
	bigIntG_r_bX.SetString(largeNumberStr14, 10)

	//137574152425504189518083675552703433516071891763966884687761945592893336683595648192456388869618608994129453303591
	largeNumberStr15 := "219325212115656834382152939655638415953925251595620183154982460959254577375655557107453618578376790183089342057620"
	var bigIntG_r_bY big.Int
	bigIntG_r_bY.SetString(largeNumberStr15, 10)
	assignment.G_r_b_list = sw_bls12377.G1Affine{
		X: frontend.Variable(bigIntG_r_bX),
		Y: frontend.Variable(bigIntG_r_bY),
	}
	largeNumberStr3 := "16923138503228348321746045345131010467419377185473546576536403543095977357941379250157548391941453488266640124397"
	//var bigIntNumPkOut big.Int
	bigIntNum223.SetString(largeNumberStr3, 10)
	//assignment.Pk_ = frontend.Variable(bigIntNumPkOut)
	assignment.R_list = frontend.Variable(4506047376502066776)

	witness, _ := frontend.NewWitness(&assignment, ecc.BW6_761.ScalarField()) //BW6_761
	publicWitness, _ := witness.Public()

	// groth16: Prove & Verify
	proof, _ := groth16.Prove(ccs, pk, witness)
	//fmt.Println("Proof:", proof)
	groth16.Verify(proof, vk, publicWitness)
}
