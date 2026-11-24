use starknet::ContractAddress;
use starknet::syscalls::deploy_syscall;
use starknet::testing::{set_block_timestamp, set_contract_address};
use super::{
    FaradayVault, IFaradayVaultDispatcher, IFaradayVaultDispatcherTrait, STATUS_CLOSED,
    STATUS_DURESS_SWEPT, STATUS_SLASHED, build_offline_voucher, compute_duress_hash,
    compute_note_commitment, decode_nfc_header, pack_nfc_header, poseidon2,
    prove_duress_pq_sweep_conservation, prove_nfc_header_bijection,
    prove_offline_voucher_balance_conservation, prove_poseidon_nullifier_fork_soundness,
    prove_rln_shamir_fork_algebra_in_fp, prove_u256_double_spend_merchant_coverage,
    recover_secret_from_fork,
};

#[starknet::interface]
trait IMockERC20<TContractState> {
    fn mint(ref self: TContractState, to: ContractAddress, amount: u256);
    fn balance_of(self: @TContractState, account: ContractAddress) -> u256;
    fn transfer(ref self: TContractState, recipient: ContractAddress, amount: u256) -> bool;
    fn transfer_from(
        ref self: TContractState, sender: ContractAddress, recipient: ContractAddress, amount: u256,
    ) -> bool;
}

#[starknet::contract]
mod MockERC20 {
    use core::num::traits::Zero;
    use starknet::storage::{Map, StorageMapReadAccess, StorageMapWriteAccess};
    use starknet::{ContractAddress, get_caller_address};

    #[storage]
    struct Storage {
        balances: Map<ContractAddress, u256>,
    }

    #[abi(embed_v0)]
    impl MockERC20Impl of super::IMockERC20<ContractState> {
        fn mint(ref self: ContractState, to: ContractAddress, amount: u256) {
            let _caller = get_caller_address();
            assert(!to.is_zero(), 'ZERO_MINT_TO');
            let cur = self.balances.read(to);
            self.balances.write(to, cur + amount);
        }

        fn balance_of(self: @ContractState, account: ContractAddress) -> u256 {
            self.balances.read(account)
        }

        fn transfer(ref self: ContractState, recipient: ContractAddress, amount: u256) -> bool {
            let sender = get_caller_address();
            assert(!sender.is_zero() && !recipient.is_zero(), 'ZERO_TRANSFER_ADDR');
            let cur = self.balances.read(sender);
            assert(cur >= amount, 'ERC20_INSUFFICIENT');
            self.balances.write(sender, cur - amount);
            let rec_cur = self.balances.read(recipient);
            self.balances.write(recipient, rec_cur + amount);
            true
        }

        fn transfer_from(
            ref self: ContractState,
            sender: ContractAddress,
            recipient: ContractAddress,
            amount: u256,
        ) -> bool {
            let _caller = get_caller_address();
            assert(!sender.is_zero() && !recipient.is_zero(), 'ZERO_TRANSFER_ADDR');
            let cur = self.balances.read(sender);
            assert(cur >= amount, 'ERC20_INSUFFICIENT');
            self.balances.write(sender, cur - amount);
            let rec_cur = self.balances.read(recipient);
            self.balances.write(recipient, rec_cur + amount);
            true
        }
    }
}

// Ephemeral Stark-curve note signer (`priv = 0x1337a11ce`) & precomputed signatures for note #0x101
const NOTE_SIGNER_PUBKEY: felt252 =
    0x7691cff6757abbf896564a499e6c8e6cb4e49c336428e011ce8fb49bf2755e7;
const V0_SIG_R: felt252 = 0x706dbb2b682f8ea1931dd78b4c12129392c07ebc7c33052f2b8dd08ca50a7ed;
const V0_SIG_S: felt252 = 0x6b60933da363b0dd0e540e4fe71fc25eb68114623e2b499f08d97ac9411f704;
const V1_SIG_R: felt252 = 0x454fd39ac875c455deb9b6cb17523f95ee84856a06f68c66669665dbec5ae2f;
const V1_SIG_S: felt252 = 0x31f9bb5cd9f7f05809dbe6aabca2829e365ace578c3ad0247158e94e2072e6a;

fn addr(val: felt252) -> ContractAddress {
    val.try_into().unwrap()
}

fn setup_usdc_and_vault() -> (IMockERC20Dispatcher, IFaradayVaultDispatcher) {
    let empty = array![];
    let (usdc_addr, _) = deploy_syscall(
        MockERC20::TEST_CLASS_HASH.try_into().unwrap(), 0, empty.span(), false,
    )
        .unwrap();
    let calldata = array![usdc_addr.into(), 86_400]; // 24h settlement grace period
    let (vault_addr, _) = deploy_syscall(
        FaradayVault::TEST_CLASS_HASH.try_into().unwrap(), 1, calldata.span(), false,
    )
        .unwrap();
    (
        IMockERC20Dispatcher { contract_address: usdc_addr },
        IFaradayVaultDispatcher { contract_address: vault_addr },
    )
}

#[test]
fn test_poseidon_offline_chain_and_rln_extraction() {
    let secret_s: felt252 = 0x1337cafe;
    let note_id: felt252 = 0x42;

    let (hop0, rem0) = build_offline_voucher(secret_s, note_id, 0, 1000, 0xb0b, 150, 1, 0x1111);
    assert(rem0 == 849, 'wrong hop0 balance');

    let (hop1, rem1) = build_offline_voucher(secret_s, note_id, 1, rem0, 0xca201, 200, 1, 0x2222);
    assert(rem1 == 648, 'wrong hop1 balance');
    assert(hop0.nullifier != hop1.nullifier, 'distinct hop nullifiers');

    // Honest single spend at seq = 0 cannot extract a secret against itself
    let no_fork = recover_secret_from_fork(
        hop0.challenge_x, hop0.shamir_y, hop0.challenge_x, hop0.shamir_y,
    );
    assert(no_fork.is_none(), 'honest tap must not extract');

    // Dishonest double-spend at seq = 0 to a second merchant produces distinct challenge_x & leaks
    // s
    let (cheat0, _) = build_offline_voucher(secret_s, note_id, 0, 1000, 0xda7e, 150, 1, 0x3333);
    assert(cheat0.nullifier == hop0.nullifier, 'fork nullifier must match');
    assert(cheat0.challenge_x != hop0.challenge_x, 'deterministic x must differ');

    let (extracted_s, _) = recover_secret_from_fork(
        hop0.challenge_x, hop0.shamir_y, cheat0.challenge_x, cheat0.shamir_y,
    )
        .expect('fork must extract secret');
    assert(extracted_s == secret_s, 'extracted secret mismatch');
}

#[test]
fn test_nfc_header_bijection_and_formal_proofs() {
    let packed = pack_nfc_header(250, 7);
    let (amount, seq) = decode_nfc_header(packed);
    assert(amount == 250 && seq == 7, 'nfc header decode mismatch');

    prove_offline_voucher_balance_conservation(0x77, 0x42, 3, 1000, 0xb0b, 150, 2, 0xaaaa);
    prove_rln_shamir_fork_algebra_in_fp(0x77, 0x9999, 0xaaaa, 0xcccc);
    prove_u256_double_spend_merchant_coverage(150, 1000_u256);
    prove_poseidon_nullifier_fork_soundness(0x77, 0x42, 0, 1);
    prove_nfc_header_bijection(250, 7);
    prove_duress_pq_sweep_conservation(1000, 1000, 25);
}

#[test]
fn test_erc20_lifecycle_settle_grace_window_and_close() {
    let (usdc, vault) = setup_usdc_and_vault();
    let alice = addr(0xa11ce);
    let coffee_shop = addr(0xb0b);
    let bookstore = addr(0xca201);
    let mesh_courier = addr(0x5a7e11);
    let pq_cold_vault = addr(0x900d99);

    set_contract_address(alice);
    usdc.mint(alice, 2000);
    let secret_s: felt252 = 0x77777;
    let duress_secret: felt252 = 0x99999;
    let note_id: felt252 = 0x101;

    set_block_timestamp(1_000);
    set_contract_address(alice);
    vault
        .open_note(
            note_id,
            NOTE_SIGNER_PUBKEY,
            compute_note_commitment(secret_s, note_id),
            compute_duress_hash(duress_secret, note_id),
            pq_cold_vault,
            0, // anonymous cypherpunk mode (`citizen_tag = 0`)
            1000,
            1000,
        );
    assert(usdc.balance_of(alice) == 0, 'alice funded 2000');
    assert(usdc.balance_of(vault.contract_address) == 2000, 'vault holds 2000');
    vault.invariant_escrow_conservation();

    // Hop 0 offline ($25 coffee + $1 courier tip), settled by mesh courier
    let (v0, rem0) = build_offline_voucher(secret_s, note_id, 0, 1000, 0xb0b, 25, 1, 0x1111);
    set_contract_address(mesh_courier);
    vault.settle_voucher(note_id, v0.nullifier, coffee_shop, 25, 1, V0_SIG_R, V0_SIG_S);
    assert(usdc.balance_of(coffee_shop) == 25, 'coffee shop paid 25');
    assert(usdc.balance_of(mesh_courier) == 1, 'courier paid 1');
    vault.invariant_escrow_conservation();

    // Alice returns online and requests note closure; bookstore settles Hop 1 during the 24h grace
    // window!
    set_contract_address(alice);
    vault.request_close(note_id);

    let (v1, _) = build_offline_voucher(secret_s, note_id, 1, rem0, 0xca201, 50, 1, 0x2222);
    set_block_timestamp(10_000);
    set_contract_address(mesh_courier);
    vault.settle_voucher(note_id, v1.nullifier, bookstore, 50, 1, V1_SIG_R, V1_SIG_S);
    assert(usdc.balance_of(bookstore) == 50, 'bookstore paid during grace');

    // After 24h grace period expires, Alice gets 100% of remaining $923 cash + $1,000 bond = $1,923
    set_block_timestamp(1_000 + 86_400);
    set_contract_address(alice);
    vault.finalize_close(note_id);
    assert(usdc.balance_of(alice) == 1923, 'alice refunded 1923');
    assert(vault.get_note(note_id).status == STATUS_CLOSED, 'status closed');
    let (tot, _, _) = vault.get_vault_totals();
    assert(tot == 0, 'vault fully drained cleanly');
    vault.invariant_escrow_conservation();
}

#[test]
fn test_multi_victim_rln_slash_and_citizen_tag_accountability() {
    let (usdc, vault) = setup_usdc_and_vault();
    let cheater = addr(0xbadc0de);
    let merchant_a = addr(0xb0b);
    let merchant_b = addr(0xca201);
    let merchant_c = addr(0xda7e);
    let snap_watchtower = addr(0xfc5ca9);

    set_contract_address(cheater);
    usdc.mint(cheater, 1000);
    let secret_s: felt252 = 0x424242;
    let note_id: felt252 = 0x202;
    let citizen_fid_tag = poseidon2(19420, 0xabc); // Opt-in Network State / Farcaster FID bond

    set_contract_address(cheater);
    vault
        .open_note(
            note_id,
            NOTE_SIGNER_PUBKEY,
            compute_note_commitment(secret_s, note_id),
            compute_duress_hash(0x999, note_id),
            addr(0x900d99),
            citizen_fid_tag,
            500,
            500,
        );

    // Cheater triple-spends seq = 0 offline to Merchants A, B, and C ($200 each)!
    let (va, _) = build_offline_voucher(secret_s, note_id, 0, 500, 0xb0b, 200, 1, 0xaa);
    let (vb, _) = build_offline_voucher(secret_s, note_id, 0, 500, 0xca201, 200, 1, 0xbb);
    let (vc, _) = build_offline_voucher(secret_s, note_id, 0, 500, 0xda7e, 200, 1, 0xcc);

    let (leaked_s, _) = recover_secret_from_fork(
        va.challenge_x, va.shamir_y, vb.challenge_x, vb.shamir_y,
    )
        .unwrap();

    // Watchtower slashes for Merchant B ($200 + $25 bounty) AND Merchant C ($200 + $25 bounty)!
    set_contract_address(snap_watchtower);
    vault
        .slash_fork(
            note_id,
            0,
            leaked_s,
            va.challenge_x,
            va.shamir_y,
            vb.challenge_x,
            vb.shamir_y,
            merchant_b,
            200,
            25,
        );
    vault
        .slash_fork(
            note_id,
            0,
            leaked_s,
            va.challenge_x,
            va.shamir_y,
            vc.challenge_x,
            vc.shamir_y,
            merchant_c,
            200,
            25,
        );

    assert(usdc.balance_of(merchant_b) == 200, 'merchant B made 100% whole');
    assert(usdc.balance_of(merchant_c) == 200, 'merchant C made 100% whole');
    assert(usdc.balance_of(snap_watchtower) == 50, 'watchtower earned 2x25 bounty');
    assert(vault.get_note(note_id).status == STATUS_SLASHED, 'cheater note frozen');
    let _ = merchant_a;
    vault.invariant_escrow_conservation();
}

#[test]
fn test_duress_sweep_teleports_to_pq_safe_vault() {
    let (usdc, vault) = setup_usdc_and_vault();
    let alice = addr(0xa11ce);
    let mugger_pos = addr(0x666);
    let pq_cold_vault = addr(0x5afe99);
    let relayer = addr(0x5a7e11);

    set_contract_address(alice);
    usdc.mint(alice, 2000);
    let note_id: felt252 = 0x303;
    let duress_secret: felt252 = 0xdec07;

    set_contract_address(alice);
    vault
        .open_note(
            note_id,
            NOTE_SIGNER_PUBKEY,
            compute_note_commitment(0x777, note_id),
            compute_duress_hash(duress_secret, note_id),
            pq_cold_vault,
            0,
            1000,
            1000,
        );

    set_contract_address(relayer);
    vault.duress_sweep(note_id, duress_secret, mugger_pos, 25);

    assert(usdc.balance_of(mugger_pos) == 25, 'mugger sees $25 decoy');
    assert(usdc.balance_of(pq_cold_vault) == 1975, '$1975 swept to PQ cold vault');
    assert(vault.get_note(note_id).status == STATUS_DURESS_SWEPT, 'duress status set');
    vault.invariant_escrow_conservation();
}

#[test]
#[should_panic(expected: ('INVALID_VOUCHER_SIGNATURE', 'ENTRYPOINT_FAILED'))]
fn test_forged_voucher_signature_rejected() {
    let (usdc, vault) = setup_usdc_and_vault();
    let alice = addr(0xa11ce);
    set_contract_address(alice);
    usdc.mint(alice, 2000);
    set_contract_address(alice);
    vault
        .open_note(
            0x101,
            NOTE_SIGNER_PUBKEY,
            compute_note_commitment(0x77777, 0x101),
            compute_duress_hash(0x99999, 0x101),
            addr(0x900d99),
            0,
            1000,
            1000,
        );

    set_contract_address(addr(0x5a7e11));
    vault.settle_voucher(0x101, 0xdeadbeef, addr(0xb0b), 25, 1, 0x111, 0x222);
}

#[test]
#[should_panic(expected: ('VOUCHER_ALREADY_SETTLED', 'ENTRYPOINT_FAILED'))]
fn test_replay_voucher_nullifier_rejected() {
    let (usdc, vault) = setup_usdc_and_vault();
    let alice = addr(0xa11ce);
    set_contract_address(alice);
    usdc.mint(alice, 2000);
    set_contract_address(alice);
    vault
        .open_note(
            0x101,
            NOTE_SIGNER_PUBKEY,
            compute_note_commitment(0x77777, 0x101),
            compute_duress_hash(0x99999, 0x101),
            addr(0x900d99),
            0,
            1000,
            1000,
        );

    let (v0, _) = build_offline_voucher(0x77777, 0x101, 0, 1000, 0xb0b, 25, 1, 0x1111);
    set_contract_address(addr(0x5a7e11));
    vault.settle_voucher(0x101, v0.nullifier, addr(0xb0b), 25, 1, V0_SIG_R, V0_SIG_S);
    vault.settle_voucher(0x101, v0.nullifier, addr(0xb0b), 25, 1, V0_SIG_R, V0_SIG_S);
}

#[test]
#[should_panic(expected: ('GRACE_PERIOD_ACTIVE', 'ENTRYPOINT_FAILED'))]
fn test_early_finalize_close_during_grace_period_rejected() {
    let (usdc, vault) = setup_usdc_and_vault();
    let alice = addr(0xa11ce);
    set_contract_address(alice);
    usdc.mint(alice, 2000);
    set_block_timestamp(1_000);
    set_contract_address(alice);
    vault
        .open_note(
            0x101,
            NOTE_SIGNER_PUBKEY,
            compute_note_commitment(0x77777, 0x101),
            compute_duress_hash(0x99999, 0x101),
            addr(0x900d99),
            0,
            1000,
            1000,
        );
    vault.request_close(0x101);
    set_block_timestamp(1_000 + 3_600); // Only 1h elapsed out of 24h grace period
    vault.finalize_close(0x101);
}

#[test]
#[should_panic(expected: ('SECRET_MISMATCH_FOR_NOTE', 'ENTRYPOINT_FAILED'))]
fn test_forged_slash_secret_rejected() {
    let (usdc, vault) = setup_usdc_and_vault();
    let alice = addr(0xa11ce);
    set_contract_address(alice);
    usdc.mint(alice, 1000);
    set_contract_address(alice);
    vault
        .open_note(
            0x101,
            NOTE_SIGNER_PUBKEY,
            compute_note_commitment(0x77777, 0x101),
            compute_duress_hash(0x99999, 0x101),
            addr(0x900d99),
            0,
            500,
            500,
        );

    let (fa, _) = build_offline_voucher(0x88888, 0x101, 0, 500, 0xb0b, 50, 1, 0x11);
    let (fb, _) = build_offline_voucher(0x88888, 0x101, 0, 500, 0xca201, 50, 1, 0x22);
    set_contract_address(addr(0x5a7e11));
    vault
        .slash_fork(
            0x101,
            0,
            0x88888,
            fa.challenge_x,
            fa.shamir_y,
            fb.challenge_x,
            fb.shamir_y,
            addr(0xb0b),
            50,
            5,
        );
}

#[test]
#[should_panic(expected: ('INVALID_DURESS_SECRET', 'ENTRYPOINT_FAILED'))]
fn test_forged_duress_secret_rejected() {
    let (usdc, vault) = setup_usdc_and_vault();
    let alice = addr(0xa11ce);
    set_contract_address(alice);
    usdc.mint(alice, 1000);
    set_contract_address(alice);
    vault
        .open_note(
            0x101,
            NOTE_SIGNER_PUBKEY,
            compute_note_commitment(0x77777, 0x101),
            compute_duress_hash(0x99999, 0x101),
            addr(0x900d99),
            0,
            500,
            500,
        );
    set_contract_address(addr(0x666));
    vault.duress_sweep(0x101, 0xbadbad, addr(0x666), 25);
}
