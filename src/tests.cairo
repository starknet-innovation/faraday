use starknet::ContractAddress;
use starknet::syscalls::deploy_syscall;
use starknet::testing::set_contract_address;
use super::{
    FaradayVault, IFaradayVaultDispatcher, IFaradayVaultDispatcherTrait, compute_duress_tag_hash,
    compute_note_root_commitment, decode_phone_nfc_header, execute_faraday_offline_hop,
    execute_phone_nfc_tap_and_enclave_duress, prove_duress_shelter_conservation,
    prove_faraday_offline_hop_conservation, prove_offline_hop_euf_fork_and_nullifier_soundness,
    prove_phone_nfc_header_bijection, prove_shamir_offline_fork_algebra_in_fp,
    prove_u256_double_spend_merchant_insurance, recover_secret_from_offline_fork,
};

fn addr(val: felt252) -> ContractAddress {
    val.try_into().unwrap()
}

fn deploy_vault(
    governor: felt252, initial_carrier: u128, initial_bond: u128,
) -> IFaradayVaultDispatcher {
    let mut calldata = array![governor, initial_carrier.into(), initial_bond.into()];
    let (contract_address, _) = deploy_syscall(
        FaradayVault::TEST_CLASS_HASH.try_into().unwrap(), 0, calldata.span(), false,
    )
        .unwrap();
    IFaradayVaultDispatcher { contract_address }
}

#[test]
fn test_multi_hop_offline_chain_and_rln_secret_extraction() {
    let alice_secret: felt252 = 0x1337cafe;
    let note_id: felt252 = 0x42;

    // Hop 0: Alice pays Merchant A 150 USDC + 1 USDC mesh relay tip in Airplane Mode
    let hop0 = execute_faraday_offline_hop(alice_secret, note_id, 0, 1000, 150, 1, 0xaaaa);
    assert(hop0.remaining_balance == 849, 'wrong hop0 balance');

    // Hop 1: Alice increments seq_no = 1 and pays Merchant B 200 USDC + 1 USDC tip offline
    let hop1 = execute_faraday_offline_hop(
        alice_secret, note_id, 1, hop0.remaining_balance, 200, 1, 0xbbbb,
    );
    assert(hop1.remaining_balance == 648, 'wrong hop1 balance');
    assert(hop0.spend_nullifier != hop1.spend_nullifier, 'distinct hop nullifiers');

    // Honest single spend at seq_no = 0 cannot be interpolated against itself
    let no_fork = recover_secret_from_offline_fork(
        0xaaaa, hop0.shamir_share_y, 0xaaaa, hop0.shamir_share_y,
    );
    assert(no_fork.is_none(), 'honest hop must not extract');

    // Dishonest rollback: Alice re-spends seq_no = 0 to Merchant C (challenge 0xcccc)
    let cheat_hop0 = execute_faraday_offline_hop(alice_secret, note_id, 0, 1000, 150, 1, 0xcccc);
    assert(cheat_hop0.spend_nullifier == hop0.spend_nullifier, 'fork tag must match');
    assert(cheat_hop0.shamir_share_y != hop0.shamir_share_y, 'distinct Shamir shares');

    // RLN Lagrange degree-1 extraction recovers Alice's exact secret key in F_P
    let (extracted_secret, _extracted_a1) = recover_secret_from_offline_fork(
        0xaaaa, hop0.shamir_share_y, 0xcccc, cheat_hop0.shamir_share_y,
    )
        .expect('fork must extract secret');
    assert(extracted_secret == alice_secret, 'extracted secret mismatch');
}

#[test]
fn test_nfc_frame_bijection_and_formal_proof_harnesses() {
    let alice_secret: felt252 = 0x1337cafe;
    let enclave_id: felt252 = 0xdeadbeef;

    let normal = execute_phone_nfc_tap_and_enclave_duress(
        alice_secret, enclave_id, 7, 250, 0xaaaa, 0,
    );
    let duress = execute_phone_nfc_tap_and_enclave_duress(
        alice_secret, enclave_id, 7, 250, 0xaaaa, 1,
    );
    let (spend, seq) = decode_phone_nfc_header(normal.packed_seq_and_spend);
    assert(spend == 250 && seq == 7, 'nfc header decode mismatch');
    assert(normal.enclave_mode_tag != duress.enclave_mode_tag, 'duress tag collision');

    prove_faraday_offline_hop_conservation(alice_secret, 0x42, 3, 1000, 150, 2, 0xaaaa);
    prove_shamir_offline_fork_algebra_in_fp(alice_secret, 0x9999, 0xaaaa, 0xcccc);
    prove_u256_double_spend_merchant_insurance(150, 1000_u256);
    prove_offline_hop_euf_fork_and_nullifier_soundness(alice_secret, 0x42, 0, 1);
    prove_phone_nfc_header_bijection(alice_secret, enclave_id, 7, 250, 0xaaaa);
    prove_duress_shelter_conservation(1000, 25, 975);
}

#[test]
fn test_vault_end_to_end_settlement_slashing_and_duress_shelter() {
    let governor: felt252 = 0x9001;
    let alice: felt252 = 0xa11ce;
    let merchant_coffee: felt252 = 0xb0b;
    let merchant_merch: felt252 = 0xca201;
    let relay_node: felt252 = 0x5a7e11;

    let vault = deploy_vault(governor, 0, 0);
    vault.invariant_five_pool_solvency_conservation();
    vault.invariant_relay_fee_and_freeze_policy();

    // 1. Alice mints carrier note #1 (1,000 USDC + 1,000 USDC anti-fraud bond)
    let alice_secret: felt252 = 0x77777;
    let enclave_id: felt252 = 0xeec1a7e;
    let note_1: felt252 = 0x101;
    let root_1 = compute_note_root_commitment(alice_secret, note_1);
    let (duress_tag_1, duress_hash_1) = compute_duress_tag_hash(alice_secret, enclave_id, note_1);

    set_contract_address(addr(alice));
    vault.mint_offline_carrier(note_1, root_1, duress_hash_1, 1000, 1000);
    vault.invariant_five_pool_solvency_conservation();

    // 2. Honest offline tap to Coffee Merchant (25 USDC + 1 USDC mesh relay tip)
    let hop0 = execute_faraday_offline_hop(alice_secret, note_1, 0, 1000, 25, 1, 0x1111);
    set_contract_address(addr(relay_node));
    vault.settle_offline_voucher_via_mesh(merchant_coffee, hop0.spend_nullifier, 25, 1);
    assert(vault.is_nullifier_settled(hop0.spend_nullifier), 'nullifier not marked');
    assert(vault.get_merchant_balance(merchant_coffee) == 25, 'coffee merchant not credited');
    vault.invariant_five_pool_solvency_conservation();

    // 3. Coffee Merchant transfers 10 USDC claim to Merch Merchant and withdraws 15 USDC
    set_contract_address(addr(merchant_coffee));
    vault.transfer_merchant_claim(merchant_coffee, merchant_merch, 10);
    vault.withdraw_merchant_claim(15);
    assert(vault.get_merchant_balance(merchant_coffee) == 0, 'coffee residual wrong');
    assert(vault.get_merchant_balance(merchant_merch) == 10, 'merch transfer wrong');
    vault.invariant_five_pool_solvency_conservation();

    // 4. Alice double-spends seq_no = 1 offline to two merchants -> RLN extracts secret & slashes
    // bond!
    let fork_a = execute_faraday_offline_hop(alice_secret, note_1, 1, 974, 200, 1, 0x2222);
    let fork_b = execute_faraday_offline_hop(alice_secret, note_1, 1, 974, 200, 1, 0x3333);
    let (leaked_secret, _) = recover_secret_from_offline_fork(
        0x2222, fork_a.shamir_share_y, 0x3333, fork_b.shamir_share_y,
    )
        .unwrap();

    set_contract_address(addr(relay_node));
    vault
        .slash_offline_fork(
            note_1,
            1,
            leaked_secret,
            0x2222,
            fork_a.shamir_share_y,
            0x3333,
            fork_b.shamir_share_y,
            merchant_merch,
            400,
            50,
        );
    assert(vault.is_note_slashed(note_1), 'note should be slashed');
    assert(vault.get_merchant_balance(merchant_merch) == 410, 'defrauded merchant compensated');
    vault.invariant_five_pool_solvency_conservation();

    // 5. Mint note #2 and test Anti-Coercion Duress Shelter ($25 decoy + $949 PQ safe-house sweep)
    let note_2: felt252 = 0x202;
    let root_2 = compute_note_root_commitment(alice_secret, note_2);
    let (duress_tag_2, duress_hash_2) = compute_duress_tag_hash(alice_secret, enclave_id, note_2);
    set_contract_address(addr(alice));
    vault.mint_offline_carrier(note_2, root_2, duress_hash_2, 974, 1000);

    let attacker_pos: felt252 = 0xbad01;
    set_contract_address(addr(relay_node));
    vault.trigger_duress_pq_shelter(note_2, duress_tag_2, attacker_pos, 25, 949);
    assert(vault.is_duress_triggered(note_2), 'duress should be triggered');
    let (total, carrier, bond, merchants, pq, relay_fees) = vault.get_vault_pools();
    assert(pq == 949, 'pq shelter amount wrong');
    assert(total == carrier + bond + merchants + pq + relay_fees, 'solvency mismatch');
    vault.invariant_five_pool_solvency_conservation();
    let _ = duress_tag_1;

    // 6. Governor fee policy + emergency freeze
    set_contract_address(addr(governor));
    vault.set_relay_fee_cap(15);
    assert(vault.get_max_relay_fee_bps() == 15, 'fee cap not updated');
    vault.activate_emergency_freeze();
    assert(vault.is_emergency_frozen(), 'freeze not active');
    assert(vault.get_max_relay_fee_bps() == 0, 'fee cap not zeroed on freeze');
    vault.invariant_relay_fee_and_freeze_policy();
}

#[test]
#[should_panic(expected: ('OFFLINE_VOUCHER_ALREADY_SETTLED', 'ENTRYPOINT_FAILED'))]
fn test_replay_nullifier_rejected() {
    let vault = deploy_vault(0x9001, 1000, 1000);
    set_contract_address(addr(0x5a7e11));
    vault.settle_offline_voucher_via_mesh(0xb0b, 0xdeadbeef, 100, 1);
    vault.settle_offline_voucher_via_mesh(0xb0b, 0xdeadbeef, 100, 1);
}

#[test]
#[should_panic(expected: ('SECRET_MISMATCH_FOR_NOTE', 'ENTRYPOINT_FAILED'))]
fn test_forged_slash_secret_rejected() {
    let vault = deploy_vault(0x9001, 0, 0);
    let real_secret: felt252 = 0x77777;
    let fake_secret: felt252 = 0x88888;
    let note_id: felt252 = 0x101;
    let root = compute_note_root_commitment(real_secret, note_id);
    let (_, duress_hash) = compute_duress_tag_hash(real_secret, 0xee, note_id);

    set_contract_address(addr(0xa11ce));
    vault.mint_offline_carrier(note_id, root, duress_hash, 500, 500);

    let fake_a = execute_faraday_offline_hop(fake_secret, note_id, 0, 500, 50, 1, 0x11);
    let fake_b = execute_faraday_offline_hop(fake_secret, note_id, 0, 500, 50, 1, 0x22);

    set_contract_address(addr(0x5a7e11));
    vault
        .slash_offline_fork(
            note_id,
            0,
            fake_secret,
            0x11,
            fake_a.shamir_share_y,
            0x22,
            fake_b.shamir_share_y,
            0xb0b,
            100,
            10,
        );
}

#[test]
#[should_panic(expected: ('INVALID_DURESS_PROOF', 'ENTRYPOINT_FAILED'))]
fn test_forged_duress_sweep_rejected() {
    let vault = deploy_vault(0x9001, 0, 0);
    let real_secret: felt252 = 0x77777;
    let note_id: felt252 = 0x101;
    let root = compute_note_root_commitment(real_secret, note_id);
    let (_, duress_hash) = compute_duress_tag_hash(real_secret, 0xee, note_id);

    set_contract_address(addr(0xa11ce));
    vault.mint_offline_carrier(note_id, root, duress_hash, 500, 500);

    set_contract_address(addr(0xbad01));
    vault.trigger_duress_pq_shelter(note_id, 0xdeadbad, 0xbad01, 25, 475);
}
