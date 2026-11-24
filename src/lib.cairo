pub mod proofs;
pub mod protocol;
pub mod vault;

pub use proofs::{
    prove_duress_pq_sweep_conservation, prove_nfc_header_bijection,
    prove_offline_voucher_balance_conservation, prove_poseidon_nullifier_fork_soundness,
    prove_rln_shamir_fork_algebra_in_fp, prove_u256_double_spend_merchant_coverage,
};
pub use protocol::{
    OfflineVoucher, build_offline_voucher, compute_challenge_x, compute_duress_hash,
    compute_note_commitment, compute_voucher_hash, decode_nfc_header, pack_nfc_header, poseidon2,
    poseidon3, recover_secret_from_fork,
};
pub use vault::{
    FaradayVault, IERC20, IERC20Dispatcher, IERC20DispatcherTrait, IFaradayVault,
    IFaradayVaultDispatcher, IFaradayVaultDispatcherTrait, OfflineNote, STATUS_ACTIVE,
    STATUS_CLOSED, STATUS_CLOSING, STATUS_DURESS_SWEPT, STATUS_NONE, STATUS_SLASHED,
};

#[cfg(test)]
mod tests;
