use std::{fs, io::BufReader, rc::Rc};

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
    let mut params_raw = vec![];
    params.write(&mut params_raw).unwrap();

    // load raw params
    // let data = "040000009d0d8fc58d435dd33d0bc7f528eb780a2c4679786fa36e662fdf079ac1770a0e3a1b1e8b1b87baa67b168eeb51d6f114588cf2f0de46ddcc5ebe0f3483ef141c19b85cb7538b593e1abf968ed23fd3e3b00aed7c998728334524e1106fa9d222e90cb4d18f97b17e6afe16d8dab6ec376270f3502298bc6f691e8a60fdffbc167fa14c77e05d9b8b5cd9f39bda62ed4b0809cb57d14a38fe9963f76ed4936b12d1567e958f264009268df0df4a5e8a9aab3ec186b78ffb11e998b77ca706df230f39fa1ad75d19f1f805bc07b98f15cd9e72f8ee7a9fbc3638e675c58579d42f398d19cdb0212eaa595f6bff13919613997b1d6c32545300c6cb543a242e062146196166e552a0505ee508734d1086a947fa9e55f5d044c02416405bf962a016786f8ca5c94cb6b69f97007e480d767cb3e3ba5208360289c71b217ce074f313e0b05ab6f42e2fccac96153d8fc2d85538fc96951e221c64aa66da627f28b208bee532ae3f33a603611c50cf88d56119e5c86a99e760b5362453a1cc99fa92072382a7938f0ff3306f3be4026ae0632c27d1e3c797c6032a6ff3c8a2de58f213cd8cfa3b02ed2f2c422913afc086a17dc5fcc9e3fb65ef6e5891261673744700d0d30510f2ad254d68d5420dfa3034b7a3d9159072fc82549ea32d8f0ba84f2fb1d35e4c128b188aade51ff3b3486d5b43212b3434ffd5ee6d4e8600e82fdb05354fd696661634e1ad3adaa29bb5af4fc15f1d793e909cd965a26bc0fc346b2b58c1b72899c191313c8c78a3cc86c90423a611582d62a49e6df75b558a711b0556920f6dea7dfb6b5d4d8b8941e8dde26a97948166011ba15bc17757d9ff3b0403a7d70ccc3a332d2a988462bad3512c06d36505cfab3f3a0391c4ef0584e10be7ad017c19aaf80140aed3b86f7c80ccf5c255c4a8b30fc9c59da877075a980df293aa2d7e9de2cb494d3534babf880ae530d8b484813c4a4b90113f3ff0400a23a4c38fbc92a2165070828860bf36c9369fece1f2d3b5e8abd00c19d91e05107df95277ecde211559e76c1ba6337b26abfae58ce1879f95db89910fc5e80d02f28915dee5d17087178c6c6528b76c33c018950e9d40c0fe29b44fdf74b5e10d192cb6a750cec4839594b976f9ee0c89ff0eb9d5997842b7272daf8a12d8c82572b560563aa0d9bd8cfe0835000d9c860c0458ab404c14f9a4fdd765585ad10b282a98e06b388e4dd709e86081d6bab1f4ed76306bf3e83d7dc390859a86ca2e8ad5e58c8c09d3081303cfd75d43e398a9ac47004cba11e719ff74c6b985071730e4a4b6d7543669f888c21e96d82e26069b147c79e4ed8bfb5dc72eb6f6f92dff9b55a337b4c04a402be6706ea7eb78684c7e3b2df95ac6623a1bf3d2434213f2b23642baac8d5dbc8351818dc030a59f56494810e9410b83cfb4d5ec85b404b2563dbe47688d453b43789652b7ce187e3aee93a2201398458dd2eb489c9f0ca7b97ea78787fd2b5b2dc2054595e0f540e622c0ed682b511619b49804a5a121539cf4ba3bebf5ae333db989e3005d3f1bf6f289494e53a70d14c40c2e35540e47fa5efe3afed571fa46f435b13c707747bd4d034d95f5ecc94eaaac7aeb072cf8da6f8de543aaa6ea937890a7386d88991904ec57e998be8f3cc89de42b1d02c2e79a1cbc5dc3c73c81890398b133199fecbad1dbdcdf944f8fc966b7481d219da939574f688a8f8ab8c0711ab2a6217d8b4eb53a5f3c632fb3959f44c24710d852e915c367bfdd58486690340c31ece8a401f8754d253eb80ed09405ff251902f8a8bdc97302640d389b29f68cf104545464a62a63d4aed18f89627ed71e145c83e4765c5b3d22de14b56c6a9fa69f411599dd01ca057aa2411498ac6ad818332b3d5df19943ecbffe93c4afe5c1cfbe4b83e12f73f4df7d5a78aa5f27c114a0570a678a1604807eb185087c8d35ae66428083dae6826789314bbe10df79060651339d92d6779731b64bab3380f72b88aea80f0deceb84b3b0dadfcccb16072d69536da6bc0e7b22f28912994850ae3f9a6e824cc7d31ee384a9aa16816a1120ba7b6762cd023d27ecc9f5e2359736d5b89459ae58b33e1b23221d08a19a1559758001ddd1f0ebe4bc34d961df14f4da5df4c1e203434dbc4a9b45c4b4031603bce8d576fa3657ef3505b300f7ea06ad6e76c8bc60fbba369e783f556195042387ec6104ea0971f1cc080a9b141bad358ecc0ad3eb83376e790bd774faf61e3c54c8f2c3afd8d8d4daf610651c58a1648e9692fcb4482bc2bf513ce24cc304a49922e66314aadeec29fb2ba147353c85edaa512de3d89b6f352e99ee213e209dc6626f84c2d3991d1047aafa922e6348000e20484c5237e88218eb8c489a07379103f6e6f6a6fb28c2f0655493d5c692c012e0158f9ee33ac7ad61b983f2074381b6709c0b514f0b9698748a7ecf92aa322d47d07ac04b969747b0816ed322455723fa9fd2fcde946f624bb9105bbc922d4090fa62cd32923628f7ac73d90a100fb56497111a24a3a9a966946b5232c9f977585475e2a16f146e55d3facd2f8281e7e24413159691354c10df31849b07c1c8ca40ec263fffcea01aba4daf2a77edaf69b3874a84680263aa8283b9c180ab48b2f9ab108ea2d19e4990b060024637b85098b0d1003585427fa24b54e16a0a2ce3c0855853c0eacdea31519e0aefd35d3b3bfa405fef1672dabddd9993a3aeb8468c667bac351db17329a06d0220d311d88c9bd1f7a8eca72e89992985939453a1861420efb1b2bd908c23971d4d89bb8541461c0e4ba7dca5a20873e43acbee887b5223ddd51db6657c56cb0e7c34bfea794a9486ce2800e8d6affdfdc3f473d9b148d4b2bcffe0c04ac203072620bc02d1b5838e72017b493519ebdcdf1a81974726b8fb3b5096af4138571940614ca87d73b4afc4d802585add4360862fa052fc50e9096b7bea3a83f0fe14f6e96b889dfa9d61789b9ef597d27ffefe7d1b23621a9eff06429eaeeb7efd28ee5618c7565b0964bb3c7d3222f957dc76103533be35f9558264fd93e6a0a40da0daaacd2a71ef7125f86c48acfdecbff095a44df4d11ab63bbf7498256b970b73b87b07649ecc68d5e37dd792ecaa18bd52a35266367054b291e7fa54c6e82ebd45f5a898635124b9d20b3432d033465fc7d68241f5d0560b0c73224b0490074072a302f3909426cbb62373ae3c8dd5e1a23815de571ccb3c8f6d7d3e3f652c";
    // let params_raw = hex::decode(data).unwrap();
    let params = ParamsKZG::<Bn256>::read(&mut BufReader::new(params_raw.as_slice())).unwrap();

    let empty_circuit = SimpleCircuit {
        constant,
        a: Value::unknown(),
        b: Value::unknown(),
    };

    let pk = gen_pk(&params, &empty_circuit);
    let deployment_code = gen_evm_verifier(&params, pk.get_vk(), vec![1]);

    // prove & verify
    let pk = gen_pk(&params, &empty_circuit);
    let a = Fr::from(2);
    let b = Fr::from(9);
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
        "params": "0x{}",
        "proof": "0x{}",
        "calldata": "0x{}"
    }}"#,
        hex::encode(&deployment_code),
        hex::encode(&params_raw),
        hex::encode(&proof),
        hex::encode(&calldata),
    );

    let _ = fs::write("output.json", output);
}
