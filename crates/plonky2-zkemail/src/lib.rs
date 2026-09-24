//! Plonky2 circuits for RSA/SHA-256 DKIM verification.
pub use plonky2;
pub type F = plonky2::field::goldilocks_field::GoldilocksField;
pub type C = plonky2::plonk::config::PoseidonGoldilocksConfig;
pub const D: usize = 2;
pub type Builder = plonky2::plonk::circuit_builder::CircuitBuilder<F, D>;
pub mod bigint;
pub mod email;
pub mod eml;
pub mod regex;
pub mod rsa;
pub mod sha256;
pub mod utils;

/// Uses Plonky2's standard parameters with witness-hiding enabled explicitly.
pub fn circuit_config() -> plonky2::plonk::circuit_data::CircuitConfig {
    let mut config = plonky2::plonk::circuit_data::CircuitConfig::standard_recursion_config();
    config.zero_knowledge = true;
    config
}

/// Reports Plonky2 circuit size without conflating gate rows with R1CS constraints.
pub fn print_circuit_size(label: &str, gate_rows: usize, padded_rows: usize) {
    println!("{label}: {gate_rows} constraint gate rows; {padded_rows} padded trace rows");
}
