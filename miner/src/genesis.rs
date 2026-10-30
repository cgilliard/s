//! Mainnet's genesis, written by `tools/genesis.rs`: do not edit by hand.
//!
//! The genesis block is empty, timestamped 1793322871, and its nonce is
//! the hash of Bitcoin block 973758, so the chain did not exist before that block.
//! Its first blocks need about 65535 hashes each (the testing target).

/// Genesis time, unix seconds; the ASERT anchor.
pub const TIMESTAMP: u64 = 1793322871;
/// The Bitcoin block hash, in the byte order block explorers show.
pub const BITCOIN_HASH_HEX: &str = "00000000000000000000c4750b0959be11adfd86268999ae3ca6b95f667e9737";
pub const BITCOIN_HASH: [u8; 32] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 196, 117, 11, 9, 89, 190, 17, 173, 253, 134, 38, 137, 153, 174, 60, 166, 185, 95, 102, 126, 151, 55];
/// Height and time of that Bitcoin block, for reference.
pub const BITCOIN_HEIGHT: u64 = 973758;
pub const BITCOIN_TIME: u64 = 1793322482;
/// Target of the first block after genesis (little-endian 64-bit limbs).
pub const TARGET: [u64; 4] = [0, 0, 0, 1099511627776];
/// Expected hashes per block at that target.
pub const HASHES_PER_BLOCK: u64 = 65535;
/// The genesis block id, as `tabminer show` prints it.
pub const ID: &str = "669b5a6a43535c1a9f4a80067ad5804421287d217ee30818a7fcee6c125ca354";
