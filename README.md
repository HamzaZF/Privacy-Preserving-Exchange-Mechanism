# Privacy-Preserving-Exchange-Mechanism

This project implements three Zero-Knowledge Proofs (ZKPs) related to the paper titled "Privacy-Preserving Exchange Mechanism and its Application to Energy Market". These ZKPs have been implemented using **Gnark**, a high-level zk-SNARK library developed by ConsenSys. Gnark is designed for easy circuit design and efficient SNARK proof generation, with support for both Groth16 and PlonK proving systems.

## Table of Contents
- [Installation](#installation)
- [Usage](#usage)
- [License](#license)
- [Contact](#contact)

## Installing Gnark

To install Gnark, you need to have Go installed on your machine. Follow the steps below to get started:

1. Install Go from [https://golang.org/dl/](https://golang.org/dl/)
2. Once Go is installed, install Gnark by running the following command:

```bash
go get github.com/consensys/gnark
```

This will download and install the Gnark library along with its dependencies.

## Usage

To compile and prove a ZKP using Gnark, you need to first write the circuit, compile it, and then run the proving system. For example, here’s how you can prove using Groth16:

1. **Write the Circuit:**
   Define your circuit in Go, including the constraints. For example:

```go
type Circuit struct {
    X frontend.Variable
    Y frontend.Variable `gnark:",public"`
}
```

2. **Compile the Circuit:**
   Compile the circuit using:

```go
cs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &myCircuit)
```

3. **Setup and Prove:**
   Run the setup and generate the proof using Groth16:

```go
pk, vk, err := groth16.Setup(cs)
proof, err := groth16.Prove(cs, pk, witness)
```

4. **Verify the Proof:**
   Verify the generated proof with the verification key:

```go
err := groth16.Verify(proof, vk, publicWitness)
```

## License

This project is licensed under the MIT License - see the LICENSE.md file for details.

## Contact

If you have any questions or suggestions regarding this implementation, feel free to reach out to me at [hamza.zarfaoui@telecom-paris.fr].
