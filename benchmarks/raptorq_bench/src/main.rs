// RaptorQ 2.0.1 benchmark
//
// API constraints discovered:
//   - symbol_size (T) is u16, max 65535 bytes. Cannot use 256KB symbols.
//   - We use T=65528 (largest multiple of 8 fitting in u16, ≈63.99 KB ≈ 64 KB).
//   - MAX_SOURCE_SYMBOLS_PER_BLOCK = 56403, so K <= 56403 per source block.
//
// Scenarios:
//   1. K=761,  T=65528 — ~50 MB batch  (matches user's "50 MB" intent)
//   2. K=4096, T=65528 — ~256 MB batch (main syncback scenario)
//   3. K=32000, T=65528 — ~1.95 GB     (large file scenario, ~2 GB intent)

use raptorq::{Decoder, Encoder, ObjectTransmissionInformation};
use std::time::Instant;

const T: usize = 65528; // largest multiple of 8 that fits in u16 (≈64 KB)
const ALIGNMENT: u8 = 8;

// Read current RSS from /proc/self/status (Linux).
fn current_rss_kb() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in status.lines() {
        if line.starts_with("VmRSS:") {
            return line
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
        }
    }
    0
}

// Read peak RSS (VmHWM) from /proc/self/status.
fn peak_rss_kb() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in status.lines() {
        if line.starts_with("VmHWM:") {
            return line
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
        }
    }
    0
}

fn gen_data(size_bytes: usize) -> Vec<u8> {
    let mut data = vec![0u8; size_bytes];
    let mut state: u64 = 0xdeadbeef_cafebabe;
    for chunk in data.chunks_mut(8) {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let bytes = state.to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
    data
}

// Build OTI for exactly K source symbols of size T in a single source block.
// Requires K <= MAX_SOURCE_SYMBOLS_PER_BLOCK (56403).
fn oti_single_block(k: usize) -> ObjectTransmissionInformation {
    let transfer_length = (k * T) as u64;
    ObjectTransmissionInformation::new(transfer_length, T as u16, 1, 1, ALIGNMENT)
}

struct BenchResult {
    label: String,
    k: usize,
    data_mb: f64,
    encode_ms: f64,
    decode_ms: f64,
    encode_mbps: f64,
    decode_mbps: f64,
    rss_before_mb: f64,
    rss_after_encode_mb: f64,
    rss_after_decode_mb: f64,
    roundtrip_ok: bool,
}

fn run_bench(label: &str, k: usize) -> BenchResult {
    let data_bytes = k * T;
    let data_mb = data_bytes as f64 / 1024.0 / 1024.0;

    println!(
        "  generating {:.1} MB of data (K={}, T={}B)...",
        data_mb, k, T
    );
    let original = gen_data(data_bytes);
    let config = oti_single_block(k);

    // ---- Encode ----
    let rss_before = current_rss_kb();
    let t0 = Instant::now();
    let encoder = Encoder::new(&original, config);
    // K source packets + 3 repair packets
    let packets = encoder.get_encoded_packets(3);
    let encode_ms = t0.elapsed().as_secs_f64() * 1000.0;
    let rss_after_encode = current_rss_kb();

    println!(
        "  encode: {:.1} ms  ({} source + 3 repair = {} packets total)",
        encode_ms,
        k,
        packets.len()
    );

    // ---- Decode using K+3 packets ----
    // Decoder is given all source packets + repair packets, stops as soon as decoded.
    let t1 = Instant::now();
    let mut decoder = Decoder::new(config);
    let mut decoded: Option<Vec<u8>> = None;
    let packet_count = packets.len();
    for packet in packets {
        decoded = decoder.decode(packet);
        if decoded.is_some() {
            break;
        }
    }
    let decode_ms = t1.elapsed().as_secs_f64() * 1000.0;
    let rss_after_decode = current_rss_kb();

    let roundtrip_ok = decoded.as_deref().map_or(false, |d| d == original.as_slice());

    println!(
        "  decode: {:.1} ms  (fed {} packets, roundtrip: {})",
        decode_ms,
        packet_count,
        if roundtrip_ok { "OK" } else { "FAIL" }
    );

    let encode_mbps = data_mb / (encode_ms / 1000.0);
    let decode_mbps = data_mb / (decode_ms / 1000.0);

    BenchResult {
        label: label.to_string(),
        k,
        data_mb,
        encode_ms,
        decode_ms,
        encode_mbps,
        decode_mbps,
        rss_before_mb: rss_before as f64 / 1024.0,
        rss_after_encode_mb: rss_after_encode as f64 / 1024.0,
        rss_after_decode_mb: rss_after_decode as f64 / 1024.0,
        roundtrip_ok,
    }
}

// Test that individual symbol generation by ESI is possible without encoding all symbols.
// raptorq SourceBlockEncoder::repair_packets(start_esi, count) generates repair symbols on demand.
// Source symbols (ESI 0..K) are always systematic (verbatim).
// Repair symbols (ESI >= K) are generated from intermediate symbols, one at a time.
fn bench_streaming(k: usize) {
    let data_bytes = k * T;
    let data_mb = data_bytes as f64 / 1024.0 / 1024.0;
    println!(
        "\n[Streaming / single symbol generation] K={}, T={}B ({:.0} MB)",
        k, T, data_mb
    );

    let original = gen_data(data_bytes);
    let config = oti_single_block(k);
    let encoder = Encoder::new(&original, config);
    let block_encoders = encoder.get_block_encoders();

    // Generate 100 individual repair symbols by ESI (streaming scenario).
    // In syncback: each holder gets one unique repair symbol (different ESI).
    let num_to_gen = 100usize;
    let t0 = Instant::now();
    for block_enc in block_encoders {
        for esi_offset in 0..num_to_gen as u32 {
            let pkts = block_enc.repair_packets(esi_offset, 1);
            assert_eq!(pkts.len(), 1);
        }
    }
    let elapsed_us = t0.elapsed().as_micros();
    println!(
        "  {} individual repair symbols generated in {} µs ({:.1} µs/symbol, {:.1} ms/symbol)",
        num_to_gen,
        elapsed_us,
        elapsed_us as f64 / num_to_gen as f64,
        elapsed_us as f64 / num_to_gen as f64 / 1000.0
    );
    println!(
        "  => Individual symbol generation by ESI is SUPPORTED (streaming is possible)"
    );

    // Verify: K+1 symbols (K source + 1 repair) suffice to decode when 1 source symbol is missing.
    // Replace source symbol 0 with 1 repair packet and decode.
    let source_pkts = block_encoders[0].source_packets();
    let repair_pkt = block_encoders[0].repair_packets(0, 1);

    let mut decoder2 = Decoder::new(config);
    // Feed source packets 1..K (skip index 0) + 1 repair
    for pkt in source_pkts.into_iter().skip(1) {
        let _ = decoder2.decode(pkt);
    }
    let result = decoder2.decode(repair_pkt.into_iter().next().unwrap());
    assert!(result.is_some(), "decode with 1 missing source + 1 repair failed");
    let ok = result.unwrap() == original;
    println!(
        "  Decode with 1 missing source symbol + 1 repair: {}",
        if ok { "PASS" } else { "FAIL" }
    );
}

fn print_summary(results: &[BenchResult]) {
    println!();
    println!("=============================================================================");
    println!(" RaptorQ 2.0.1 Benchmark Summary");
    println!("=============================================================================");
    println!(" T (symbol size) = {} bytes = {:.2} KB", T, T as f64 / 1024.0);
    println!(" MAX_SOURCE_SYMBOLS_PER_BLOCK = 56403");
    println!();

    println!(
        " {:<28} {:>6} {:>8} {:>10} {:>10} {:>10} {:>10}",
        "Scenario", "K", "Data MB", "Enc ms", "Dec ms", "Enc MB/s", "Dec MB/s"
    );
    println!(" {}", "-".repeat(88));
    for r in results {
        println!(
            " {:<28} {:>6} {:>8.0} {:>10.1} {:>10.1} {:>10.0} {:>10.0}  {}",
            r.label,
            r.k,
            r.data_mb,
            r.encode_ms,
            r.decode_ms,
            r.encode_mbps,
            r.decode_mbps,
            if r.roundtrip_ok { "PASS" } else { "FAIL" }
        );
    }

    println!();
    println!(
        " {:<28} {:>12} {:>18} {:>18}",
        "Scenario", "Before (MB)", "After encode (MB)", "After decode (MB)"
    );
    println!(" {}", "-".repeat(76));
    for r in results {
        println!(
            " {:<28} {:>12.0} {:>18.0} {:>18.0}",
            r.label,
            r.rss_before_mb,
            r.rss_after_encode_mb,
            r.rss_after_decode_mb,
        );
    }
    println!();
    println!(
        " Peak RSS (VmHWM) at report time: {} MB",
        peak_rss_kb() / 1024
    );
    println!();
    println!(" Note: RSS values are cumulative (OS may not release pages between runs).");
    println!(" Memory delta for each scenario ≈ rss_after_decode - rss_before.");
}

fn main() {
    println!("RaptorQ 2.0.1 benchmark");
    println!(
        "T = {} bytes ({:.2} KB) — largest multiple of 8 fitting in u16",
        T,
        T as f64 / 1024.0
    );
    println!();

    let mut results = Vec::new();

    // Scenario 1: ~50 MB, K=761
    // 761 * 65528 = 49,867,528 bytes ≈ 47.6 MB
    // User intent: "K=200, T=256KB, 50 MB". T=256KB is impossible (>u16), so we use
    // K=761 to get ~50 MB with T=65528.
    println!("[1/3] ~50 MB batch  (K=761, T={})", T);
    results.push(run_bench("50MB batch (K=761)", 761));
    println!();

    // Scenario 2: 256 MB, K=4096 — main syncback scenario
    // 4096 * 65528 = 268,402,688 bytes = 256.0 MB
    println!("[2/3] 256 MB batch  (K=4096, T={})", T);
    results.push(run_bench("256MB unit (K=4096)", 4096));
    println!();

    // Scenario 3: ~2 GB, K=32000
    // 32000 * 65528 = 2,096,896,000 bytes ≈ 1.95 GB
    println!("[3/3] ~2 GB video   (K=32000, T={})", T);
    results.push(run_bench("2GB video (K=32000)", 32000));
    println!();

    // Streaming test on the main scenario
    bench_streaming(4096);

    print_summary(&results);
}
