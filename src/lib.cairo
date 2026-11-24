pub mod hop;
pub mod proofs;
pub mod vault;

pub use hop::{
    FaradayOfflineHopReceipt, FaradayPhoneNfcFrame, compute_duress_tag_hash,
    compute_note_root_commitment, decode_phone_nfc_header, execute_faraday_offline_hop,
    execute_phone_nfc_tap_and_enclave_duress, recover_secret_from_offline_fork,
};
pub use proofs::{
    prove_duress_shelter_conservation, prove_faraday_offline_hop_conservation,
    prove_offline_hop_euf_fork_and_nullifier_soundness, prove_phone_nfc_header_bijection,
    prove_shamir_offline_fork_algebra_in_fp, prove_u256_double_spend_merchant_insurance,
};
pub use vault::{FaradayVault, IFaradayVault, IFaradayVaultDispatcher, IFaradayVaultDispatcherTrait};

#[cfg(test)]
mod tests;
