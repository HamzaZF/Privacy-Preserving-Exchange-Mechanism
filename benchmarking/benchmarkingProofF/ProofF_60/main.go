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

// variable names must start with a capital letter
type RegisterCircuit struct {
	//public inputs
	Cm_out               frontend.Variable    `gnark:",public"`
	Sn_in                frontend.Variable    `gnark:",public"`
	Sk_in_xor_h_g_r_b    frontend.Variable    `gnark:",public"`
	Pk_out_xor_h_h_g_r_b frontend.Variable    `gnark:",public"`
	B_xor_h_h_h_g_r_b    frontend.Variable    `gnark:",public"`
	G_r                  sw_bls12377.G1Affine `gnark:",public"`
	G                    sw_bls12377.G1Affine `gnark:",public"`
	G_b                  sw_bls12377.G1Affine `gnark:",public"`

	//secret inputs
	N_in  NoteFull
	N_out NoteFull
	B_i   frontend.Variable
	G_r_b sw_bls12377.G1Affine
}

func (circuit *RegisterCircuit) Define(api frontend.API) error {

	var n = 60

	//api.Println(frontend.Variable(n))

	//1) C == (sk_in||pk_out||b) XOR (H(g_r_b)||H(H(g_r_b))||H(H(H(g_r_b))))

	var Sk_in_computed frontend.Variable
	var H_g_r_b frontend.Variable

	for i := 0; i < n; i++ {
		//	H(g_r_b)
		H_g_r_b_mimc, _ := mimc.NewMiMC(api)
		H_g_r_b_mimc.Write(circuit.G_r_b.X)
		H_g_r_b_mimc.Write(circuit.G_r_b.Y)
		H_g_r_b = H_g_r_b_mimc.Sum()
		//	sk_in + H(g_r_b)
		Sk_in_computed = api.Sub(circuit.Sk_in_xor_h_g_r_b, H_g_r_b)
		api.AssertIsEqual(circuit.N_in.Sk, Sk_in_computed)
	}

	var h_h_g_r_b frontend.Variable
	//	H(H(g_r_b))
	for i := 0; i < n; i++ {
		H_H_g_r_b_mimc, _ := mimc.NewMiMC(api)
		H_H_g_r_b_mimc.Write(H_g_r_b)
		h_h_g_r_b = H_H_g_r_b_mimc.Sum()
		//	pk_out XOR H(H(g_r_b))
		Pk_out_computed := api.Sub(circuit.Pk_out_xor_h_h_g_r_b, h_h_g_r_b)
		api.AssertIsEqual(circuit.N_out.Pk, Pk_out_computed)
	}

	for i := 0; i < n; i++ {
		//	H(H(H(g_r_b)))
		H_h_H_g_r_b_mimc, _ := mimc.NewMiMC(api)
		H_h_H_g_r_b_mimc.Write(h_h_g_r_b)
		H_H_H_g_r_b := H_h_H_g_r_b_mimc.Sum()
		//	b XOR H(H(H(g_r_b)))
		B_computed := api.Sub(circuit.B_xor_h_h_h_g_r_b, H_H_H_g_r_b)
		api.AssertIsEqual(circuit.B_i, B_computed)
	}

	//2) compute Sn
	for i := 0; i < n; i++ {
		sn_mimc, _ := mimc.NewMiMC(api)
		sn_mimc.Write(Sk_in_computed)
		sn_mimc.Write(circuit.N_in.Rho)
		Sn_computed := sn_mimc.Sum()
		api.AssertIsEqual(circuit.Sn_in, Sn_computed)
	}

	//3) Compute auction (dummy values for benchmarking only)

	//for benchmarking purposes, we will use dummy values for the bid B_i and a prechoosed price p (specified by the auctioneer)
	//We will consider the case where no bid is sufficient for performing transactions
	//We suppose there is n/2 buyers and n/2 sellers (n in 2Z)

	p := frontend.Variable(3206047376502166799)

	//check if the buyers curve goes below the price p -- (n/2)*api.Cmp
	for i := 0; i < n/2; i++ {
		api.Cmp(p, circuit.B_i)
	}

	//check if the sellers curve goes above the price p -- (n/2)*api.Cmp
	for i := 0; i < n/2; i++ {
		api.Cmp(circuit.B_i, p)
	}
	//4) Compute cm_out

	for i := 0; i < n; i++ {
		Cm_out_mimc, _ := mimc.NewMiMC(api)
		Cm_out_mimc.Write(circuit.N_out.T[0])
		Cm_out_mimc.Write(circuit.N_out.T[1])
		Cm_out_mimc.Write(circuit.N_out.R)
		Cm_out_mimc.Write(circuit.N_out.Rho)
		Cm_out_mimc.Write(circuit.N_out.Pk)
		Cm_out_computed := Cm_out_mimc.Sum()
		api.AssertIsEqual(circuit.Cm_out, Cm_out_computed)
	}

	return nil
}

// Declare global variables

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
	var bigIntNu222 big.Int
	bigIntNum222.SetString(largeNumberStr2, 10)
	bigIntNu222.SetString(largeNumberStr2, 10)
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
	largeNumberStr6SnIn := "113659196871612072543459970138388673998289533012026854082664823224600205847961680581286110096985633740750331734254"
	var Sn_in big.Int
	Sn_in.SetString(largeNumberStr6SnIn, 10)
	assignment.Cm_out = frontend.Variable(bigIntNum2) //must be a number
	assignment.Sn_in = frontend.Variable(Sn_in)
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
	var bigIntNu big.Int
	bigIntNum.SetString(largeNumberStr, 10)
	bigIntNu.SetString(largeNumberStr, 10)

	assignment.N_in = NoteFull{
		T: [2]frontend.Variable{frontend.Variable(5267903284545154886), frontend.Variable(3427758880465230113)},
		//save as bigint
		Pk:  frontend.Variable(bigIntNum),
		Sk:  frontend.Variable(3472352472855481322),
		Rho: frontend.Variable(1706047376502066796),
		R:   frontend.Variable(4312748660626696319),
		Cm:  frontend.Variable(bigIntNum222),
	}

	assignment.N_out = NoteFull{
		T: [2]frontend.Variable{frontend.Variable(5267903284545154886), frontend.Variable(3427758880465230113)},
		//save as bigint
		Pk:  frontend.Variable(bigIntNu),
		Sk:  frontend.Variable(3472352472855481322),
		Rho: frontend.Variable(1706047376502066796),
		R:   frontend.Variable(4312748660626696319),
		Cm:  frontend.Variable(bigIntNu222),
	}

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
	//largeNumberStr3 := "16923138503228348321746045345131010467419377185473546576536403543095977357941379250157548391941453488266640124397"
	//var bigIntNumPkOut big.Int
	//bigIntNum223.SetString(largeNumberStr3, 10)
	//assignment.Pk_out = frontend.Variable(bigIntNumPkOut)

	witness, _ := frontend.NewWitness(&assignment, ecc.BW6_761.ScalarField()) //BW6_761
	publicWitness, _ := witness.Public()

	// groth16: Prove & Verify
	proof, _ := groth16.Prove(ccs, pk, witness)
	//fmt.Println("Proof:", proof)
	groth16.Verify(proof, vk, publicWitness)
}
