// L1b К1 (INV-G0, delete-i9): the id of a block sealed at generation 0 is the id it had
// before the seal generation existed. Written before the generation entered the nonce.
// Spec: private/beta-planning/tasks/c_l1b_serviceable_block.md (v1.1) §2.2.

use super::pipeline::compress_and_encrypt;

const GOLDEN_KEY: [u8; 32] = [0x42; 32];
const GOLDEN_PLAINTEXT: &[u8] = b"viaticum L1b golden block: generation zero keeps its id";

/// INV-G0: the id of a block sealed at generation 0 is the id every block had before
/// L1b. The hex was taken on the code before the generation entered the nonce
/// (vps/l0 @ 635ef2d).
#[test]
fn seal_generation_zero_matches_pre_l1b_block_id() {
    let stored = compress_and_encrypt(GOLDEN_PLAINTEXT, &GOLDEN_KEY).unwrap();
    let id = viaticum_core::types::hex_encode(blake3::hash(&stored).as_bytes());
    assert_eq!(
        id,
        "aee0a8162ce3a9db798424d323d26f96f914e18f7f263b30ec5694bf13d070b4"
    );
}
