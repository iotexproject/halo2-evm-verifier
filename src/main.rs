use std::{fs, rc::Rc};

use halo2_curves::bn256::{Bn256, Fq, Fr, G1Affine};
use halo2_hello::circuits::simple::SimpleCircuit;
use halo2_proofs::{
    circuit::Value,
    dev::MockProver,
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ProvingKey, VerifyingKey},
    poly::{
        commitment::{Params, ParamsProver},
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverGWC, VerifierGWC},
            strategy::AccumulatorStrategy,
        },
        VerificationStrategy,
    },
    transcript::{TranscriptReadBuffer, TranscriptWriterBuffer},
    SerdeFormat,
};
use itertools::Itertools;
use rand::rngs::OsRng;
use snark_verifier::{
    loader::evm::{self, deploy_and_call, encode_calldata, EvmLoader},
    pcs::kzg::{Gwc19, KzgAs},
    system::halo2::{compile, transcript::evm::EvmTranscript, Config},
    verifier::{self, SnarkVerifier},
};

type PlonkVerifier = verifier::plonk::PlonkVerifier<KzgAs<Bn256, Gwc19>>;

fn gen_srs(k: u32) -> ParamsKZG<Bn256> {
    ParamsKZG::<Bn256>::setup(k, OsRng)
}

fn gen_pk<C: Circuit<Fr>>(params: &ParamsKZG<Bn256>, circuit: &C) -> ProvingKey<G1Affine> {
    let vk = keygen_vk(params, circuit).unwrap();
    keygen_pk(params, vk, circuit).unwrap()
}

fn gen_evm_verifier(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    num_instance: Vec<usize>,
) -> Vec<u8> {
    let protocol = compile(
        params,
        vk,
        Config::kzg().with_num_instance(num_instance.clone()),
    );
    let vk = (params.get_g()[0], params.g2(), params.s_g2()).into();

    let loader = EvmLoader::new::<Fq, Fr>();
    let protocol = protocol.loaded(&loader);
    let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(&loader);

    let instances = transcript.load_instances(num_instance);
    let proof = PlonkVerifier::read_proof(&vk, &protocol, &instances, &mut transcript).unwrap();
    PlonkVerifier::verify(&vk, &protocol, &instances, &proof).unwrap();

    evm::compile_yul(&loader.yul_code())
}

fn gen_proof<C: Circuit<Fr>>(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: C,
    instances: &Vec<Vec<Fr>>,
) -> Vec<u8> {
    MockProver::run(params.k(), &circuit, instances.clone())
        .unwrap()
        .assert_satisfied();

    let instances = instances
        .iter()
        .map(|instances| instances.as_slice())
        .collect_vec();
    let proof = {
        let mut transcript = TranscriptWriterBuffer::<_, G1Affine, _>::init(Vec::new());
        create_proof::<KZGCommitmentScheme<Bn256>, ProverGWC<_>, _, _, EvmTranscript<_, _, _, _>, _>(
            params,
            pk,
            &[circuit],
            &[instances.as_slice()],
            OsRng,
            &mut transcript,
        )
        .unwrap();
        transcript.finalize()
    };

    let accept = {
        let mut transcript = TranscriptReadBuffer::<_, G1Affine, _>::init(proof.as_slice());
        VerificationStrategy::<_, VerifierGWC<_>>::finalize(
            verify_proof::<_, VerifierGWC<_>, _, EvmTranscript<_, _, _, _>, _>(
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

    proof
}

fn main() {
    // prepare verifier
    let constant = Fr::from(7);
    let params = gen_srs(4);
    let empty_circuit = SimpleCircuit {
        constant,
        a: Value::unknown(),
        b: Value::unknown(),
    };

    let pk = gen_pk(&params, &empty_circuit);
    let deployment_code = gen_evm_verifier(&params, pk.get_vk(), vec![1]);

    // store raw pk
    let pk_raw = pk.to_bytes(SerdeFormat::RawBytes);

    // prove & verify
    let pk = ProvingKey::<G1Affine>::from_bytes::<SimpleCircuit<Fr>>(
        &pk_raw.clone(),
        SerdeFormat::RawBytes,
    )
    .unwrap();
    let a = Fr::from(2);
    let b = Fr::from(6);
    let c = constant * a.square() * b.square();
    let circuit = SimpleCircuit {
        constant,
        a: Value::known(a),
        b: Value::known(b),
    };
    let instances = vec![vec![c]];
    let proof = gen_proof(&params, &pk, circuit.clone(), &instances);
    let calldata = encode_calldata(&instances, &proof);

    let gas_cost = deploy_and_call(deployment_code.clone(), calldata.clone()).unwrap();
    println!("verified gas cost: {}", gas_cost);

    let output = format!(
        r#"{{
    "contract": "0x{}",
    "pk": "0x{}",
    "proof": "0x{}",
    "calldata": "0x{}"
}}"#,
        hex::encode(&deployment_code),
        hex::encode(&pk_raw),
        hex::encode(&proof),
        hex::encode(&calldata),
    );

    let _ = fs::write("output.json", output);
}
