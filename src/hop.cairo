use core::num::traits::DivRem;
use core::pedersen::pedersen;
use core::zeroable::NonZero;

/// Off-chain Stwo Chihuahua (`CanonicalSmall`) hop receipt for the Faraday protocol.
/// Binds the updated carrier commitment, hop spend nullifier, and RLN Shamir share `(x, y)` in F_P.
#[derive(Drop, Copy, PartialEq, Serde)]
pub struct FaradayOfflineHopReceipt {
    pub next_carrier_commitment: felt252,
    pub spend_nullifier: felt252,
    pub merchant_challenge_x: felt252,
    pub shamir_share_y: felt252,
    pub remaining_balance: u128,
}

/// Compact 3-word (96-byte wire payload) Phone NFC ISO-DEP APDU / BLE / LoRa / QR frame.
/// Wire serialization packs `(packed_seq_and_spend, biometric_mode)` alongside `spend_nullifier`
/// and `shamir_share_y` or `enclave_mode_tag` to fit inside a single <256-byte NFC tap or LoRa
/// packet.
#[derive(Drop, Copy, PartialEq, Serde)]
pub struct FaradayPhoneNfcFrame {
    pub packed_seq_and_spend: u128,
    pub spend_nullifier: felt252,
    pub shamir_share_y: felt252,
    pub enclave_mode_tag: felt252,
}

/// Computes the on-chain carrier root commitment `pedersen(secret_key, note_id)` registered at mint
/// time.
pub fn compute_note_root_commitment(secret_key: felt252, note_id: felt252) -> felt252 {
    pedersen(secret_key, note_id)
}

/// Derives the hardware enclave duress mode tag (`mode = 1`) and its blinded on-chain commitment
/// hash `pedersen(enclave_duress_tag, note_id)` registered at mint time.
pub fn compute_duress_tag_hash(
    secret_key: felt252, device_enclave_id: felt252, note_id: felt252,
) -> (felt252, felt252) {
    let enclave_bind = pedersen(secret_key, device_enclave_id);
    let enclave_duress_tag = pedersen(enclave_bind, 1);
    let duress_tag_hash = pedersen(enclave_duress_tag, note_id);
    (enclave_duress_tag, duress_tag_hash)
}

/// Pure Stwo Chihuahua (`CanonicalSmall`, `PedersenPoints::<9>`, `log_size <= 20`) offline hop
/// transition.
/// Proves on a phone in Airplane Mode (~28 MB RAM, 5 Pedersen hashes, 0 storage syscalls) that:
/// 1. `spend_amount` and `relay_tip` are covered by `prev_balance` without `u128` overflow,
/// 2. `a1 = pedersen(pedersen(secret_key, note_id), seq_no)` is the unique RLN slope for `(note_id,
/// seq_no)`, 3. `y = secret_key + a1 * merchant_challenge_x (mod P)` lies on that degree-1 Shamir
/// line.
pub fn execute_faraday_offline_hop(
    secret_key: felt252,
    note_id: felt252,
    seq_no: u64,
    prev_balance: u128,
    spend_amount: u128,
    relay_tip: u128,
    merchant_challenge_x: felt252,
) -> FaradayOfflineHopReceipt {
    assert(seq_no < 1_000_000, 'SEQ_OVERFLOW');
    assert(spend_amount <= prev_balance, 'INSUFFICIENT_OFFLINE_BALANCE');
    let after_spend = prev_balance - spend_amount;
    assert(relay_tip <= after_spend, 'INSUFFICIENT_FOR_RELAY_TIP');
    let remaining_balance = after_spend - relay_tip;

    let note_secret_bind = pedersen(secret_key, note_id);
    let a1 = pedersen(note_secret_bind, seq_no.into());
    let spend_nullifier = pedersen(a1, 1);
    let shamir_share_y = secret_key + a1 * merchant_challenge_x;
    let next_carrier_commitment = pedersen(
        pedersen(note_secret_bind, (seq_no + 1).into()), remaining_balance.into(),
    );

    FaradayOfflineHopReceipt {
        next_carrier_commitment,
        spend_nullifier,
        merchant_challenge_x,
        shamir_share_y,
        remaining_balance,
    }
}

/// Phone Secure Enclave / Android StrongBox Offline Tap Prover (`4` Pedersen hashes, `0` storage
/// syscalls).
/// Packs `(seq_no, spend_amount)` into a single 128-bit header word (`spend_amount * 1_000_000 +
/// seq_no`)
/// and binds the hardware biometric mode (`0` = Normal FaceID/TouchID, `1` = Duress Finger / Panic
/// PIN).
pub fn execute_phone_nfc_tap_and_enclave_duress(
    secret_key: felt252,
    device_enclave_id: felt252,
    seq_no: u64,
    spend_amount: u64,
    merchant_challenge_x: felt252,
    biometric_mode: felt252,
) -> FaradayPhoneNfcFrame {
    assert(seq_no < 1_000_000, 'SEQ_OVERFLOW');
    assert(spend_amount <= 1_000_000_000, 'SPEND_CAP');
    let packed_seq_and_spend: u128 = spend_amount.into() * 1_000_000_u128 + seq_no.into();
    let enclave_bind = pedersen(secret_key, device_enclave_id);
    let a1 = pedersen(enclave_bind, seq_no.into());
    let spend_nullifier = pedersen(a1, 1);
    let shamir_share_y = secret_key + a1 * merchant_challenge_x;
    let enclave_mode_tag = pedersen(enclave_bind, biometric_mode);

    FaradayPhoneNfcFrame { packed_seq_and_spend, spend_nullifier, shamir_share_y, enclave_mode_tag }
}

/// Losslessly decodes `(spend_amount, seq_no)` from a packed 128-bit NFC/LoRa header word
/// using a single Sierra `u128_safe_divmod` instruction.
pub fn decode_phone_nfc_header(packed_seq_and_spend: u128) -> (u128, u128) {
    let divisor: NonZero<u128> = 1_000_000_u128.try_into().unwrap();
    DivRem::div_rem(packed_seq_and_spend, divisor)
}

/// Rate-Limiting Nullifier (RLN) Shamir Equivocation Extractor over F_P:
/// Given two conflicting offline shares `(x1, y1)` and `(x2, y2)` signed at the same `(note_id,
/// seq_no)`, recovers `Option::Some((secret_key, a1))` when `x1 != x2`, or `Option::None` when `x1
/// == x2`.
pub fn recover_secret_from_offline_fork(
    x1: felt252, y1: felt252, x2: felt252, y2: felt252,
) -> Option<(felt252, felt252)> {
    let dx: felt252 = x1 - x2;
    match dx.try_into() {
        Option::Some(nz_dx) => {
            let a1 = core::felt252_div(y1 - y2, nz_dx);
            let secret_key = y1 - a1 * x1;
            Option::Some((secret_key, a1))
        },
        Option::None => Option::None,
    }
}
