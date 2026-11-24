use core::hash::HashStateTrait;
use core::num::traits::DivRem;
use core::poseidon::PoseidonTrait;
use core::zeroable::NonZero;

/// Off-chain Faraday voucher produced locally on a phone in Airplane Mode.
/// Carries the nullifier, deterministic RLNv2 challenge `x`, Shamir share `y`,
/// and `voucher_hash` signed by the note's ephemeral `signer_pubkey`.
#[derive(Drop, Copy, PartialEq, Serde)]
pub struct OfflineVoucher {
    pub note_id: felt252,
    pub seq_no: u64,
    pub nullifier: felt252,
    pub challenge_x: felt252,
    pub shamir_y: felt252,
    pub packed_nfc_header: u128,
    pub voucher_hash: felt252,
}

/// 2-to-1 Starknet Poseidon hash (`hades_permutation(a, b, 2)` — post-quantum, M31/Stwo
/// friendly).
pub fn poseidon2(a: felt252, b: felt252) -> felt252 {
    PoseidonTrait::new().update(a).update(b).finalize()
}

/// 3-to-1 Starknet Poseidon sponge hash (`PoseidonTrait` — matches `starknet.js`
/// `poseidonHashMany`).
pub fn poseidon3(a: felt252, b: felt252, c: felt252) -> felt252 {
    PoseidonTrait::new().update(a).update(b).update(c).finalize()
}

/// Computes the blinded on-chain note commitment `Poseidon(secret_s, note_id)`.
pub fn compute_note_commitment(secret_s: felt252, note_id: felt252) -> felt252 {
    poseidon2(secret_s, note_id)
}

/// Computes the blinded on-chain anti-coercion duress hash `Poseidon(duress_secret, note_id)`.
pub fn compute_duress_hash(duress_secret: felt252, note_id: felt252) -> felt252 {
    poseidon2(duress_secret, note_id)
}

/// Deterministic RLNv2 challenge `x = Poseidon(merchant, amount, merchant_nonce)`.
/// Prevents a double-spender from reusing the same `x` across two merchants to hide `secret_s`.
pub fn compute_challenge_x(merchant: felt252, amount: u128, merchant_nonce: felt252) -> felt252 {
    poseidon3(merchant, amount.into(), merchant_nonce)
}

/// Canonical message hash signed by the phone's `signer_pubkey` for on-chain `settle_voucher`.
pub fn compute_voucher_hash(
    note_id: felt252, nullifier: felt252, merchant: felt252, amount: u128, relay_fee: u128,
) -> felt252 {
    let left = poseidon2(note_id, nullifier);
    let right = poseidon3(merchant, amount.into(), relay_fee.into());
    poseidon2(left, right)
}

/// Packs `(amount, seq_no)` into a single 128-bit NFC / QR / LoRa frame header word.
pub fn pack_nfc_header(amount: u64, seq_no: u64) -> u128 {
    assert(seq_no < 1_000_000, 'SEQ_OVERFLOW');
    assert(amount <= 1_000_000_000_000, 'AMOUNT_CAP');
    amount.into() * 1_000_000_u128 + seq_no.into()
}

/// Losslessly decodes `(amount, seq_no)` in one Sierra `u128_safe_divmod` instruction.
pub fn decode_nfc_header(packed_header: u128) -> (u128, u128) {
    let divisor: NonZero<u128> = 1_000_000_u128.try_into().unwrap();
    DivRem::div_rem(packed_header, divisor)
}

/// Pure offline pocket tap kernel (`0` storage syscalls, Poseidon-only, Stwo M31 ready).
/// Proves balance sufficiency (`amount + relay_fee <= prev_balance`), derives the unique RLN
/// line `y = secret_s + a1 * x (mod P)` for `(note_id, seq_no)`, and outputs `(OfflineVoucher,
/// next_balance)`.
pub fn build_offline_voucher(
    secret_s: felt252,
    note_id: felt252,
    seq_no: u64,
    prev_balance: u128,
    merchant: felt252,
    amount: u64,
    relay_fee: u64,
    merchant_nonce: felt252,
) -> (OfflineVoucher, u128) {
    assert(seq_no < 1_000_000, 'SEQ_OVERFLOW');
    assert(amount <= 1_000_000_000_000, 'AMOUNT_CAP');
    let amount_u128: u128 = amount.into();
    let fee_u128: u128 = relay_fee.into();
    assert(amount_u128 <= prev_balance, 'INSUFFICIENT_OFFLINE_BALANCE');
    let after_amount = prev_balance - amount_u128;
    assert(fee_u128 <= after_amount, 'INSUFFICIENT_FOR_RELAY_FEE');
    let next_balance = after_amount - fee_u128;

    let commitment = compute_note_commitment(secret_s, note_id);
    let a1 = poseidon2(commitment, seq_no.into());
    let nullifier = poseidon2(a1, 1);
    let challenge_x = compute_challenge_x(merchant, amount_u128, merchant_nonce);
    let shamir_y = secret_s + a1 * challenge_x;
    let packed_nfc_header = amount_u128 * 1_000_000_u128 + seq_no.into();
    let voucher_hash = compute_voucher_hash(note_id, nullifier, merchant, amount_u128, fee_u128);

    (
        OfflineVoucher {
            note_id, seq_no, nullifier, challenge_x, shamir_y, packed_nfc_header, voucher_hash,
        },
        next_balance,
    )
}

/// Rate-Limiting Nullifier (RLNv2) Shamir Equivocation Extractor over F_P:
/// Given two conflicting offline shares `(x1, y1)` and `(x2, y2)` signed at the same `(note_id,
/// seq_no)`, recovers `Option::Some((secret_s, a1))` when `x1 != x2`, or `Option::None` when `x1 ==
/// x2`.
pub fn recover_secret_from_fork(
    x1: felt252, y1: felt252, x2: felt252, y2: felt252,
) -> Option<(felt252, felt252)> {
    let dx: felt252 = x1 - x2;
    match dx.try_into() {
        Option::Some(nz_dx) => {
            let a1 = core::felt252_div(y1 - y2, nz_dx);
            let secret_s = y1 - a1 * x1;
            Option::Some((secret_s, a1))
        },
        Option::None => Option::None,
    }
}
