/// The depth of the packet queue, replenished every poll.
pub const EVENT_CNT: usize = 4096;

/// The max serialized size of a transaction.
pub const TXN_MAX_SZ: usize = 1232; // TODO is this still accurate?

/// Number of concurrent in-flight streams.
pub const REASM_DEPTH: usize = 1024;

/// The max number of fragments per transaction.
/// Used to combat slowloris attacks.
pub const TXN_MAX_FRAGS: usize = 16;

const _: () = assert!(EVENT_CNT <= u16::MAX as usize);
