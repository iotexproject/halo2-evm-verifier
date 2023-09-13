use std::rc::Rc;

use halo2_curves::{bn256::{Bn256, Fq, Fr, G1Affine}, ff::Field};
use halo2_hello::simple::MyCircuit;
use halo2_proofs::{
    circuit::Value,
    plonk::{keygen_pk, keygen_vk, Circuit, ProvingKey, VerifyingKey, create_proof, verify_proof},
    poly::{kzg::{commitment::{ParamsKZG, KZGCommitmentScheme}, multiopen::{VerifierGWC, ProverGWC}, strategy::AccumulatorStrategy}, commitment::{ParamsProver, Params}, VerificationStrategy}, dev::MockProver, transcript::{TranscriptWriterBuffer, TranscriptReadBuffer},
};
use rand::rngs::OsRng;
use snark_verifier::{
    loader::evm::{self, deploy_and_call, encode_calldata, EvmLoader},
    pcs::kzg::{Gwc19, KzgAs},
    system::halo2::{compile, transcript::evm::EvmTranscript, Config},
    verifier::{self, SnarkVerifier},
};
use itertools::Itertools;

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
    instances: Vec<Vec<Fr>>,
) -> Vec<u8> {
    MockProver::run(
        params.k(), &circuit, instances.clone())
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

fn evm_verify(deployment_code: Vec<u8>, instances: Vec<Vec<Fr>>, proof: Vec<u8>) {
    let calldata = encode_calldata(&instances, &proof);
    let gas_cost = deploy_and_call(deployment_code, calldata).unwrap();
    dbg!(gas_cost);
}

fn main() {
    let params = gen_srs(4);

    let constant = Fr::from(7);
    let a = Fr::from(2);
    let b = Fr::from(3);
    let c = constant * a.square() * b.square();

    let circuit = MyCircuit {
        constant,
        a: Value::known(a),
        b: Value::known(b),
    };

    let pk = gen_pk(&params, &circuit);
    let deployment_code = gen_evm_verifier(&params, pk.get_vk(), vec![1]);

    let proof = gen_proof(&params, &pk, circuit.clone(),  vec![vec![c]]);
    evm_verify(deployment_code, vec![vec![c]], proof);
}
