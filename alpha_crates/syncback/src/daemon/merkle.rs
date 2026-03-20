//! BLAKE3-based Merkle tree over 64 KB blocks, shared by shard_manager and storage.
//!
//! Layout: leaves are at indices 0..num_leaves (power-of-2 padded).
//! Internal nodes fill the remainder in level-order bottom-up.
//! The root is at the last position in the returned vec.

pub const BLOCK_SIZE: usize = 65_536;

/// Hash a single 64 KB block. Pads with zeros if shorter than BLOCK_SIZE.
fn hash_block(block: &[u8]) -> [u8; 32] {
    if block.len() == BLOCK_SIZE {
        *blake3::hash(block).as_bytes()
    } else {
        let mut padded = [0u8; BLOCK_SIZE];
        padded[..block.len()].copy_from_slice(block);
        *blake3::hash(&padded).as_bytes()
    }
}

/// Hash an internal node from left and right child hashes.
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

/// Next power of two >= n. Returns 1 for n == 0.
fn next_power_of_two(n: usize) -> usize {
    if n <= 1 {
        return 1;
    }
    let mut p = 1;
    while p < n {
        p <<= 1;
    }
    p
}

/// Compute the BLAKE3 Merkle root over 64 KB blocks of data.
///
/// Empty data: single leaf = blake3([0u8; 65536]).
pub fn merkle_root(data: &[u8]) -> [u8; 32] {
    let tree = merkle_tree(data);
    *tree.last().expect("merkle_tree always returns at least one element")
}

/// Build full Merkle tree.
///
/// Returns a vector of length 2*num_leaves - 1 where:
///   - indices 0..num_leaves are the leaf hashes (power-of-2 padded)
///   - the remaining are internal nodes built bottom-up
///   - the last element is the root
pub fn merkle_tree(data: &[u8]) -> Vec<[u8; 32]> {
    let raw_blocks = if data.is_empty() {
        1
    } else {
        data.len().div_ceil(BLOCK_SIZE)
    };
    let num_leaves = next_power_of_two(raw_blocks);

    let mut nodes: Vec<[u8; 32]> = Vec::with_capacity(2 * num_leaves - 1);

    // Build leaf hashes.
    for i in 0..num_leaves {
        let start = i * BLOCK_SIZE;
        if start < data.len() {
            let end = (start + BLOCK_SIZE).min(data.len());
            nodes.push(hash_block(&data[start..end]));
        } else if i < raw_blocks {
            // raw_blocks > 0, all data blocks covered above
            nodes.push(hash_block(&[]));
        } else {
            // Padding: duplicate the last real leaf.
            let last_leaf = nodes[raw_blocks - 1];
            nodes.push(last_leaf);
        }
    }

    // Build internal nodes bottom-up.
    let mut level_start = 0usize;
    let mut level_len = num_leaves;
    while level_len > 1 {
        let next_level_start = level_start + level_len;
        let next_level_len = level_len / 2;
        for i in 0..next_level_len {
            let left = nodes[level_start + 2 * i];
            let right = nodes[level_start + 2 * i + 1];
            nodes.push(hash_pair(&left, &right));
        }
        level_start = next_level_start;
        level_len = next_level_len;
    }

    nodes
}

/// Extract the Merkle proof for leaf at `leaf_index`.
///
/// `tree` must be the output of `merkle_tree`. `leaf_index` is 0-indexed within leaves.
/// Returns sibling hashes from leaf level up to (but not including) the root.
pub fn merkle_proof(tree: &[[u8; 32]], leaf_index: usize) -> Vec<[u8; 32]> {
    let total = tree.len();
    // num_leaves = ceil(total / 2) for a complete binary tree
    let num_leaves = total.div_ceil(2);
    let mut proof = Vec::new();

    let mut idx = leaf_index;
    let mut level_start = 0usize;
    let mut level_len = num_leaves;

    while level_len > 1 {
        let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        proof.push(tree[level_start + sibling_idx]);
        level_start += level_len;
        level_len /= 2;
        idx /= 2;
    }

    proof
}

/// Verify a Merkle inclusion proof.
///
/// `root`: expected Merkle root.
/// `leaf_hash`: the hash of the leaf block.
/// `leaf_index`: 0-indexed position of the leaf in the padded leaf array.
/// `proof`: sibling hashes from leaf level up to root.
pub fn verify_merkle_proof(
    root: &[u8; 32],
    leaf_hash: &[u8; 32],
    leaf_index: usize,
    proof: &[[u8; 32]],
) -> bool {
    let mut current = *leaf_hash;
    let mut idx = leaf_index;
    for sibling in proof {
        current = if idx % 2 == 0 {
            hash_pair(&current, sibling)
        } else {
            hash_pair(sibling, &current)
        };
        idx /= 2;
    }
    &current == root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_root_empty_data_is_deterministic() {
        let r1 = merkle_root(&[]);
        let r2 = merkle_root(&[]);
        assert_eq!(r1, r2);
    }

    #[test]
    fn merkle_root_single_block() {
        let data = vec![0xabu8; 1000];
        let root = merkle_root(&data);
        // Root of a single leaf tree is the leaf hash itself.
        let expected = hash_block(&data);
        assert_eq!(root, expected);
    }

    #[test]
    fn merkle_root_two_blocks() {
        let data = vec![0x01u8; BLOCK_SIZE * 2];
        let root = merkle_root(&data);
        let leaf0 = hash_block(&data[..BLOCK_SIZE]);
        let leaf1 = hash_block(&data[BLOCK_SIZE..]);
        let expected = hash_pair(&leaf0, &leaf1);
        assert_eq!(root, expected);
    }

    #[test]
    fn merkle_root_partial_last_block_pads_to_block_size() {
        // 1 block + partial second block
        let data = vec![0x42u8; BLOCK_SIZE + 100];
        let root = merkle_root(&data);

        let leaf0 = hash_block(&data[..BLOCK_SIZE]);
        // Partial block padded to BLOCK_SIZE
        let mut padded = [0u8; BLOCK_SIZE];
        padded[..100].fill(0x42);
        let leaf1 = *blake3::hash(&padded).as_bytes();
        // Two leaves -> padded to 2 (already power of 2)
        let expected = hash_pair(&leaf0, &leaf1);
        assert_eq!(root, expected);
    }

    #[test]
    fn merkle_proof_and_verify_single_leaf() {
        let data = vec![0xffu8; 500];
        let tree = merkle_tree(&data);
        let leaf_hash = tree[0];
        let root = *tree.last().unwrap();
        let proof = merkle_proof(&tree, 0);
        assert!(verify_merkle_proof(&root, &leaf_hash, 0, &proof));
    }

    #[test]
    fn merkle_proof_and_verify_three_blocks() {
        // 3 blocks -> padded to 4 leaves
        let data = vec![0x11u8; BLOCK_SIZE * 3 + 100];
        let tree = merkle_tree(&data);
        let root = *tree.last().unwrap();

        for leaf_index in 0..4usize {
            let leaf_hash = tree[leaf_index];
            let proof = merkle_proof(&tree, leaf_index);
            assert!(
                verify_merkle_proof(&root, &leaf_hash, leaf_index, &proof),
                "proof failed for leaf {leaf_index}"
            );
        }
    }

    #[test]
    fn verify_merkle_proof_rejects_wrong_hash() {
        let data = vec![0x55u8; BLOCK_SIZE * 2];
        let tree = merkle_tree(&data);
        let root = *tree.last().unwrap();
        let proof = merkle_proof(&tree, 0);
        let wrong_hash = [0xffu8; 32];
        assert!(!verify_merkle_proof(&root, &wrong_hash, 0, &proof));
    }

    #[test]
    fn merkle_tree_length_is_correct() {
        for n_blocks in [1, 2, 3, 4, 5, 8, 9, 16] {
            let data = vec![0u8; BLOCK_SIZE * n_blocks];
            let tree = merkle_tree(&data);
            let num_leaves = next_power_of_two(n_blocks);
            assert_eq!(tree.len(), 2 * num_leaves - 1, "n_blocks={n_blocks}");
        }
    }
}
