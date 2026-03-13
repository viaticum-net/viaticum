// Quick script to generate fixed BIP39 mnemonics from entropy seeds.
// Run: cargo run --example gen_mnemonics -p syncback
// Or just copy-paste the output.
fn main() {
    for seed in [50u8, 51, 52, 53, 54] {
        let entropy = [seed; 32];
        let m = bip39::Mnemonic::from_entropy(&entropy).expect("valid entropy");
        let words: Vec<&str> = m.words().collect();
        println!("seed {seed}: \"{}\"", words.join(" "));
    }
}
