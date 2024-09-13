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

To compile and prove a ZKP, you need to place yourself in the desired proof folder (ProofDraw, ProofF, ProofReg or ProofTx) then run the command :

```bash
go run main.go
```

If you want to run a benchmark, go to the benchmarking folder associated with the proof and run the python script with the command :

```bash
python3 main.py
```

## License

This project is licensed under the MIT License - see the LICENSE.md file for details.

## Contact

If you have any questions or suggestions regarding this implementation, feel free to reach out to me at [hamza.zarfaoui@telecom-paris.fr].
