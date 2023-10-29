use clap::Parser;
use halo2_curves::bn256::{Bn256, Fr};
use halo2_proofs::{
    circuit::Value,
    poly::{commitment::Params, kzg::commitment::ParamsKZG},
};
use snark_verifier::loader::evm::{self, deploy_and_call, encode_calldata};
use std::{
    fs::{self, File},
    io::BufReader,
};

use halo2_evm_verifier::{
    circuits::simple::SimpleCircuit,
    generator::{gen_pk, gen_proof, gen_sol_verifier, gen_srs},
    opts::{Opts, Subcommands},
};

fn main() {
    let opts = Opts::parse();

    match opts.sub {
        Subcommands::Params { file } => {
            let mut params_file = File::create(file.clone())
                .unwrap_or_else(|_| panic!("create params file [{}] error", file));
            let params = gen_srs(4);
            params.write(&mut params_file).expect("write file error");
        }

        Subcommands::Solidity {
            file,
            params,
            constant,
            bytecode,
        } => {
            // TODO support select circuit
            let constant = Fr::from(constant);
            let empty_circuit = SimpleCircuit {
                constant,
                a: Value::unknown(),
                b: Value::unknown(),
            };
            let params_raw = fs::read(params).expect("read params file error");
            let params = ParamsKZG::<Bn256>::read(&mut BufReader::new(params_raw.as_slice()))
                .expect("restore params error");

            let sol_code = gen_sol_verifier(&params, empty_circuit, vec![1])
                .expect("generate solidity file error");
            if bytecode {
                fs::write(
                    file,
                    format!(
                        "0x{}",
                        hex::encode(evm::compile_solidity(sol_code.as_str()))
                    ),
                )
                .expect("write verifier bytecode error");
            } else {
                fs::write(file, sol_code).expect("write verifier solidity error");
            }
        }

        Subcommands::Proof {
            file,
            verify,
            params,
            constant,
            a,
            b,
        } => {
            // TODO support select circuit
            let constant = Fr::from(constant);
            let a = Fr::from(a);
            let b = Fr::from(b);
            let params_raw = fs::read(params).expect("read params file error");
            let params = ParamsKZG::<Bn256>::read(&mut BufReader::new(params_raw.as_slice()))
                .expect("restore params error");

            let empty_circuit = SimpleCircuit {
                constant,
                a: Value::unknown(),
                b: Value::unknown(),
            };
            let pk = gen_pk(&params, &empty_circuit);

            let c = constant * a.square() * b.square();
            let circuit = SimpleCircuit {
                constant,
                a: Value::known(a),
                b: Value::known(b),
            };
            let instances = vec![vec![c]];
            let proof = gen_proof(&params, &pk, circuit.clone(), &instances);
            let calldata = encode_calldata(&instances, &proof);
            if verify {
                let deployment_code = gen_sol_verifier(&params, empty_circuit, vec![1])
                    .expect("generate contract error");
                let deployment_code = evm::compile_solidity(&deployment_code);
                let gas_cost = deploy_and_call(deployment_code.clone(), calldata.clone())
                    .expect("verify proof error");
                println!("verified gas cost: {}", gas_cost);
            }

            let output = format!(
                r#"{{
    "proof": "0x{}",
    "calldata": "0x{}"
}}"#,
                hex::encode(&proof),
                hex::encode(&calldata),
            );

            fs::write(file, output).expect("write proof file error");
        }
    }
}
