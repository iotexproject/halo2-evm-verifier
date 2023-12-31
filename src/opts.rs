use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[clap(name = "evm-generator", version = "0.1.0")]
pub struct Opts {
    #[clap(subcommand)]
    pub sub: Subcommands,
}

#[derive(Debug, Subcommand)]
#[clap(
    about = "Halo2 EVM verifier generator from your command line.",
    after_help = "Find more information can refer code: https://github.com/ququzone/halo2-evm-generator",
    next_display_order = None
)]
pub enum Subcommands {
    #[clap(name = "params")]
    #[clap(about = "Generate KZG params (don't used in production).")]
    Params {
        #[clap(long, short, value_name = "file", default_value = "output/params.bin")]
        file: String,
    },

    #[clap(name = "solidity")]
    #[clap(visible_aliases = &["sol"])]
    #[clap(about = "Generate verifier solidity contract.")]
    Solidity {
        #[clap(
            long,
            short,
            value_name = "file",
            default_value = "output/Verifier.sol"
        )]
        file: String,
        #[clap(
            long,
            short,
            value_name = "params",
            default_value = "output/params.bin"
        )]
        params: String,
        #[clap(long, short, value_name = "constant", default_value = "7")]
        constant: u64,
        #[clap(long, short, value_name = "bytecode")]
        bytecode: bool,
    },

    #[clap(name = "graph")]
    #[clap(visible_aliases = &["gp"])]
    #[clap(about = "Generate circuit layout graph.")]
    Graph {
        #[clap(long, short, value_name = "file", default_value = "output/graph.png")]
        file: String,
        #[clap(long, short, value_name = "title", default_value = "Simple circuit")]
        title: String,
        #[clap(short, value_name = "k", default_value = "5")]
        k: u32,
    },

    #[clap(name = "proof")]
    #[clap(visible_aliases = &["pro"])]
    #[clap(about = "Generate proof for circuit.")]
    Proof {
        #[clap(long, short, value_name = "file", default_value = "output/proof.json")]
        file: String,
        #[clap(long, short)]
        verify: bool,
        #[clap(
            long,
            short,
            value_name = "params",
            default_value = "output/params.bin"
        )]
        params: String,
        #[clap(long, short, value_name = "constant", default_value = "7")]
        constant: u64,
        #[clap(short, default_value = "3")]
        a: u64,
        #[clap(short, default_value = "5")]
        b: u64,
    },

    #[clap(name = "verify")]
    #[clap(visible_aliases = &["ver"])]
    #[clap(about = "Verify proof for circuit.")]
    Verify {
        #[clap(
            long,
            short,
            value_name = "params",
            default_value = "output/params.bin"
        )]
        params: String,
        #[clap(long, short, value_name = "constant", default_value = "7")]
        constant: u64,
        #[clap(short, default_value = "1575")]
        c: u64,
        #[clap(long, short, value_name = "proof")]
        proof: String,
    },
}
