use clap::Parser;
use halo2_curves::bn256::{Bn256, Fr, G1Affine};
use halo2_proofs::{
    circuit::Value,
    dev::CircuitLayout,
    plonk,
    poly::{
        commitment::{Params, ParamsProver},
        kzg::{commitment::ParamsKZG, multiopen::VerifierGWC, strategy::AccumulatorStrategy},
        VerificationStrategy,
    },
    transcript::TranscriptReadBuffer,
};
use hex::FromHex;
use itertools::Itertools;
use snark_verifier::{
    loader::evm::{self, deploy_and_call, encode_calldata},
    system::halo2::transcript::evm::EvmTranscript,
};
use std::{
    fs::{self, File},
    io::BufReader,
};

use halo2_evm_verifier::{
    circuits::simple::SimpleCircuit,
    generator::{gen_pk, gen_proof, gen_sol_verifier, gen_srs, verify_proof},
    opts::{Opts, Subcommands},
};
use plotters::prelude::{BitMapBackend, IntoDrawingArea, WHITE};

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
            println!(
                "Generated verifier contract size: {}",
                evm::compile_solidity(sol_code.as_str()).len()
            );
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

        Subcommands::Graph { file, title, k } => {
            let circuit = SimpleCircuit::<Fr>::default();
            let root = BitMapBackend::new(&file, (1024, 768)).into_drawing_area();
            root.fill(&WHITE).unwrap();
            let root = root.titled(&title, ("sans-serif", 60)).unwrap();
            CircuitLayout::default()
                .show_labels(true)
                .render(k, &circuit, &root)
                .unwrap();
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

            let accept = {
                let instances = instances
                    .iter()
                    .map(|instances| instances.as_slice())
                    .collect_vec();
                let mut transcript = TranscriptReadBuffer::<_, G1Affine, _>::init(proof.as_slice());
                VerificationStrategy::<_, VerifierGWC<_>>::finalize(
                    plonk::verify_proof::<_, VerifierGWC<_>, _, EvmTranscript<_, _, _, _>, _>(
                        params.verifier_params(),
                        pk.get_vk(),
                        AccumulatorStrategy::new(params.verifier_params()),
                        &[instances.as_slice()],
                        &mut transcript,
                    )
                    .unwrap(),
                )
            };
            assert!(accept);

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

        Subcommands::Verify {
            params,
            constant,
            c,
            proof,
        } => {
            let constant = Fr::from(constant);
            let params_raw = fs::read(params).expect("read params file error");
            let params = ParamsKZG::<Bn256>::read(&mut BufReader::new(params_raw.as_slice()))
                .expect("restore params error");

            let empty_circuit = SimpleCircuit {
                constant,
                a: Value::unknown(),
                b: Value::unknown(),
            };
            let pk = gen_pk(&params, &empty_circuit);
            let instances = vec![vec![Fr::from(c)]];
            let proof = Vec::from_hex(proof).unwrap();
            let result = verify_proof(&params, &pk, proof, &instances);

            println!("Verify proof result: {}", result);
        }
    }
}
