use syncback_core::erasure::{Symbol, chunk_symbols_by_size};
use syncback_core::messages::{Message, SymbolTransferMsg, to_cbor};
use syncback_core::types::{SourceBlockId, Timestamp};
use syncback_core::constants::SYMBOL_TRANSFER_CHUNK_BUDGET_BYTES;
use rand::RngCore;

fn run(label: &str, count: u32, fill_random: bool) {
    let mut rng = rand::thread_rng();
    let symbols: Vec<Symbol> = (0..count)
        .map(|i| {
            let mut data = vec![0u8; 65535];
            if fill_random { rng.fill_bytes(&mut data); }
            Symbol { esi: i, data }
        })
        .collect();
    let raw_total: usize = symbols.iter().map(|s| s.data.len()).sum();
    let chunks = chunk_symbols_by_size(symbols, SYMBOL_TRANSFER_CHUNK_BUDGET_BYTES);
    println!("\n=== {} ===  random={} count={} raw_total={} ({:.1} MiB)  chunks={}",
        label, fill_random, count, raw_total, raw_total as f64 / 1048576.0, chunks.len());
    for (i, c) in chunks.iter().enumerate() {
        let raw: usize = c.iter().map(|s| s.data.len()).sum();
        let msg = Message::SymbolTransfer(SymbolTransferMsg {
            v: 1,
            source_block_id: SourceBlockId([0; 32]),
            symbols: c.clone(),
            timestamp: Timestamp::now(),
        });
        let cbor = to_cbor(&msg).unwrap();
        let overhead_pct = (cbor.len() as f64 - raw as f64) / raw as f64 * 100.0;
        println!("  chunk {}: {} symbols, raw={} ({:.1} MiB), cbor={} ({:.1} MiB) — overhead {:+.1}%",
            i, c.len(), raw, raw as f64 / 1048576.0,
            cbor.len(), cbor.len() as f64 / 1048576.0,
            overhead_pct);
    }
}

fn main() {
    run("zeros 149", 149, false);
    run("random 149", 149, true);
    run("zeros 2400", 2400, false);
    run("random 2400", 2400, true);
}
