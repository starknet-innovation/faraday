#[starknet::interface]
pub trait IFaradayVault<TContractState> {
    fn mint_offline_carrier(
        ref self: TContractState,
        note_id: felt252,
        root_commitment: felt252,
        duress_tag_hash: felt252,
        carrier_deposit: u128,
        bond_deposit: u128,
    );
    fn settle_offline_voucher_via_mesh(
        ref self: TContractState,
        merchant: felt252,
        nullifier: felt252,
        spend_amount: u128,
        relay_tip: u128,
    );
    fn slash_offline_fork(
        ref self: TContractState,
        note_id: felt252,
        seq_no: u64,
        secret_key: felt252,
        x1: felt252,
        y1: felt252,
        x2: felt252,
        y2: felt252,
        defrauded_merchant: felt252,
        victim_compensation: u128,
        mesh_hunter_bounty: u128,
    );
    fn trigger_duress_pq_shelter(
        ref self: TContractState,
        note_id: felt252,
        enclave_duress_tag: felt252,
        decoy_recipient: felt252,
        decoy_spend: u128,
        shelter_amount: u128,
    );
    fn transfer_merchant_claim(ref self: TContractState, from: felt252, to: felt252, amount: u128);
    fn withdraw_merchant_claim(ref self: TContractState, amount: u128);
    fn set_relay_fee_cap(ref self: TContractState, new_fee_bps: u32);
    fn activate_emergency_freeze(ref self: TContractState);

    fn get_vault_pools(self: @TContractState) -> (u128, u128, u128, u128, u128, u128);
    fn get_merchant_balance(self: @TContractState, merchant: felt252) -> u128;
    fn is_nullifier_settled(self: @TContractState, nullifier: felt252) -> bool;
    fn is_note_slashed(self: @TContractState, note_id: felt252) -> bool;
    fn is_duress_triggered(self: @TContractState, note_id: felt252) -> bool;
    fn is_emergency_frozen(self: @TContractState) -> bool;
    fn get_max_relay_fee_bps(self: @TContractState) -> u32;

    fn invariant_five_pool_solvency_conservation(self: @TContractState);
    fn invariant_relay_fee_and_freeze_policy(self: @TContractState);
}

#[starknet::contract]
pub mod FaradayVault {
    use core::pedersen::pedersen;
    use starknet::get_caller_address;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };

    #[storage]
    struct Storage {
        governor: felt252,
        total_vault_assets: u128,
        active_carrier_pool: u128,
        slash_bond_pool: u128,
        merchant_claims_pool: u128,
        pq_recovery_pool: u128,
        relay_fee_pool: u128,
        max_relay_fee_bps: u32,
        emergency_frozen: bool,
        registered_notes: Map<felt252, bool>,
        note_root_commitments: Map<felt252, felt252>,
        note_duress_hashes: Map<felt252, felt252>,
        slashed_notes: Map<felt252, bool>,
        duress_triggered_notes: Map<felt252, bool>,
        settled_nullifiers: Map<felt252, bool>,
        merchant_balances: Map<felt252, u128>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        CarrierMinted: CarrierMinted,
        VoucherSettled: VoucherSettled,
        OfflineForkSlashed: OfflineForkSlashed,
        DuressShelterTriggered: DuressShelterTriggered,
        MerchantClaimWithdrawn: MerchantClaimWithdrawn,
        EmergencyFreezeActivated: EmergencyFreezeActivated,
    }

    #[derive(Drop, starknet::Event)]
    pub struct CarrierMinted {
        #[key]
        pub note_id: felt252,
        pub owner: felt252,
        pub carrier_deposit: u128,
        pub bond_deposit: u128,
    }

    #[derive(Drop, starknet::Event)]
    pub struct VoucherSettled {
        #[key]
        pub nullifier: felt252,
        pub merchant: felt252,
        pub spend_amount: u128,
        pub relay_tip: u128,
    }

    #[derive(Drop, starknet::Event)]
    pub struct OfflineForkSlashed {
        #[key]
        pub note_id: felt252,
        pub seq_no: u64,
        pub defrauded_merchant: felt252,
        pub victim_compensation: u128,
        pub mesh_hunter_bounty: u128,
    }

    #[derive(Drop, starknet::Event)]
    pub struct DuressShelterTriggered {
        #[key]
        pub note_id: felt252,
        pub decoy_spend: u128,
        pub shelter_amount: u128,
    }

    #[derive(Drop, starknet::Event)]
    pub struct MerchantClaimWithdrawn {
        #[key]
        pub merchant: felt252,
        pub amount: u128,
    }

    #[derive(Drop, starknet::Event)]
    pub struct EmergencyFreezeActivated {
        pub governor: felt252,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        governor: felt252,
        initial_carrier_pool: u128,
        initial_bond_pool: u128,
    ) {
        assert(governor != 0, 'ZERO_GOVERNOR');
        assert(initial_carrier_pool <= 1_000_000_000_000, 'CARRIER_CAP');
        assert(initial_bond_pool <= 1_000_000_000_000, 'BOND_CAP');
        self.governor.write(governor);
        self.active_carrier_pool.write(initial_carrier_pool);
        self.slash_bond_pool.write(initial_bond_pool);
        self.merchant_claims_pool.write(0);
        self.pq_recovery_pool.write(0);
        self.relay_fee_pool.write(0);
        self.total_vault_assets.write(initial_carrier_pool + initial_bond_pool);
        self.max_relay_fee_bps.write(100);
        self.emergency_frozen.write(false);
    }

    /// 1. Mint an offline Faraday carrier note + anti-fraud RLN Shamir bond before going off-grid.
    #[external(v0)]
    fn mint_offline_carrier(
        ref self: ContractState,
        note_id: felt252,
        root_commitment: felt252,
        duress_tag_hash: felt252,
        carrier_deposit: u128,
        bond_deposit: u128,
    ) {
        let caller: felt252 = get_caller_address().into();
        assert(caller != 0, 'ZERO_CALLER');
        assert(!self.emergency_frozen.read(), 'VAULT_FROZEN');
        assert(note_id != 0 && root_commitment != 0 && duress_tag_hash != 0, 'ZERO_COMMITMENT');
        assert(!self.registered_notes.read(note_id), 'NOTE_ALREADY_REGISTERED');
        assert(carrier_deposit > 0 && carrier_deposit <= 1_000_000_000, 'INVALID_CARRIER');
        assert(bond_deposit >= carrier_deposit && bond_deposit <= 2_000_000_000, 'BOND_TOO_LOW');

        let cur_carrier = self.active_carrier_pool.read();
        let cur_bond = self.slash_bond_pool.read();
        let cur_total = self.total_vault_assets.read();
        let total_added = carrier_deposit + bond_deposit;
        assert(cur_carrier <= 100_000_000_000_000, 'POOL_CAP');
        assert(cur_bond <= 100_000_000_000_000, 'BOND_POOL_CAP');
        assert(cur_total <= 200_000_000_000_000, 'TOTAL_CAP');

        self.registered_notes.write(note_id, true);
        self.note_root_commitments.write(note_id, root_commitment);
        self.note_duress_hashes.write(note_id, duress_tag_hash);
        self.active_carrier_pool.write(cur_carrier + carrier_deposit);
        self.slash_bond_pool.write(cur_bond + bond_deposit);
        self.total_vault_assets.write(cur_total + total_added);

        self.emit(CarrierMinted { note_id, owner: caller, carrier_deposit, bond_deposit });
    }

    /// 2. Settle an offline Stwo Chihuahua receipt relayed when either phone or a mesh node gets
    /// signal.
    #[external(v0)]
    fn settle_offline_voucher_via_mesh(
        ref self: ContractState,
        merchant: felt252,
        nullifier: felt252,
        spend_amount: u128,
        relay_tip: u128,
    ) {
        let relay_caller: felt252 = get_caller_address().into();
        assert(relay_caller != 0, 'ZERO_RELAY');
        assert(merchant != 0 && nullifier != 0, 'ZERO_SETTLE_TARGET');
        assert(!self.emergency_frozen.read(), 'VAULT_FROZEN');
        assert(!self.settled_nullifiers.read(nullifier), 'OFFLINE_VOUCHER_ALREADY_SETTLED');
        assert(spend_amount <= 1_000_000_000 && relay_tip <= 10_000_000, 'SETTLE_CAP');

        let total_debit = spend_amount + relay_tip;
        let cur_carrier = self.active_carrier_pool.read();
        let cur_merchants = self.merchant_claims_pool.read();
        let cur_relay = self.relay_fee_pool.read();
        let cur_merchant_bal = self.merchant_balances.read(merchant);
        assert(cur_carrier >= total_debit, 'CARRIER_POOL_INSUFFICIENT');
        assert(cur_merchants <= 100_000_000_000_000, 'MERCHANT_POOL_CAP');
        assert(cur_relay <= 100_000_000_000_000, 'RELAY_POOL_CAP');
        assert(cur_merchant_bal <= 100_000_000_000_000, 'MERCHANT_BAL_CAP');

        self.settled_nullifiers.write(nullifier, true);
        self.active_carrier_pool.write(cur_carrier - total_debit);
        self.merchant_claims_pool.write(cur_merchants + spend_amount);
        self.merchant_balances.write(merchant, cur_merchant_bal + spend_amount);
        self.relay_fee_pool.write(cur_relay + relay_tip);

        self.emit(VoucherSettled { nullifier, merchant, spend_amount, relay_tip });
    }

    /// 3. Rate-Limiting Nullifier (RLN) Shamir Equivocation Slashing in F_P.
    #[external(v0)]
    fn slash_offline_fork(
        ref self: ContractState,
        note_id: felt252,
        seq_no: u64,
        secret_key: felt252,
        x1: felt252,
        y1: felt252,
        x2: felt252,
        y2: felt252,
        defrauded_merchant: felt252,
        victim_compensation: u128,
        mesh_hunter_bounty: u128,
    ) {
        let hunter: felt252 = get_caller_address().into();
        assert(hunter != 0, 'ZERO_HUNTER');
        assert(defrauded_merchant != 0, 'ZERO_MERCHANT');
        assert(seq_no < 1_000_000, 'SEQ_OVERFLOW');
        assert(self.registered_notes.read(note_id), 'UNKNOWN_NOTE');
        assert(!self.slashed_notes.read(note_id), 'NOTE_ALREADY_SLASHED');

        let computed_root = pedersen(secret_key, note_id);
        assert(
            computed_root == self.note_root_commitments.read(note_id), 'SECRET_MISMATCH_FOR_NOTE',
        );
        let a1 = pedersen(computed_root, seq_no.into());

        assert(x1 != x2, 'NOT_A_FORK_SAME_CHALLENGE');
        assert(y1 == secret_key + a1 * x1, 'INVALID_SHAMIR_SHARE_1');
        assert(y2 == secret_key + a1 * x2, 'INVALID_SHAMIR_SHARE_2');
        assert(
            victim_compensation <= 1_000_000_000 && mesh_hunter_bounty <= 100_000_000, 'SLASH_CAP',
        );

        let total_slashed = victim_compensation + mesh_hunter_bounty;
        let cur_bond = self.slash_bond_pool.read();
        let cur_merchants = self.merchant_claims_pool.read();
        let cur_relay = self.relay_fee_pool.read();
        let cur_merchant_bal = self.merchant_balances.read(defrauded_merchant);
        assert(cur_bond >= total_slashed, 'BOND_POOL_INSUFFICIENT');
        assert(cur_merchants <= 100_000_000_000_000, 'MERCHANT_POOL_CAP');
        assert(cur_relay <= 100_000_000_000_000, 'RELAY_POOL_CAP');
        assert(cur_merchant_bal <= 100_000_000_000_000, 'MERCHANT_BAL_CAP');

        self.slashed_notes.write(note_id, true);
        self.slash_bond_pool.write(cur_bond - total_slashed);
        self.merchant_claims_pool.write(cur_merchants + victim_compensation);
        self.merchant_balances.write(defrauded_merchant, cur_merchant_bal + victim_compensation);
        self.relay_fee_pool.write(cur_relay + mesh_hunter_bounty);

        self
            .emit(
                OfflineForkSlashed {
                    note_id, seq_no, defrauded_merchant, victim_compensation, mesh_hunter_bounty,
                },
            );
    }

    /// 4. MACI-Inspired Anti-Coercion Duress Shelter.
    #[external(v0)]
    fn trigger_duress_pq_shelter(
        ref self: ContractState,
        note_id: felt252,
        enclave_duress_tag: felt252,
        decoy_recipient: felt252,
        decoy_spend: u128,
        shelter_amount: u128,
    ) {
        let caller: felt252 = get_caller_address().into();
        assert(caller != 0, 'ZERO_CALLER');
        assert(decoy_recipient != 0, 'ZERO_DECOY_RECIPIENT');
        assert(self.registered_notes.read(note_id), 'UNKNOWN_NOTE');
        assert(!self.duress_triggered_notes.read(note_id), 'DURESS_ALREADY_TRIGGERED');

        let computed_duress_hash = pedersen(enclave_duress_tag, note_id);
        assert(
            computed_duress_hash == self.note_duress_hashes.read(note_id), 'INVALID_DURESS_PROOF',
        );
        assert(decoy_spend <= 10_000_000 && shelter_amount <= 1_000_000_000, 'DURESS_CAP');

        let total_moved = decoy_spend + shelter_amount;
        let cur_carrier = self.active_carrier_pool.read();
        let cur_merchants = self.merchant_claims_pool.read();
        let cur_pq = self.pq_recovery_pool.read();
        let cur_recipient_bal = self.merchant_balances.read(decoy_recipient);
        assert(cur_carrier >= total_moved, 'CARRIER_INSUFFICIENT');
        assert(cur_merchants <= 100_000_000_000_000, 'MERCHANT_POOL_CAP');
        assert(cur_pq <= 100_000_000_000_000, 'PQ_POOL_CAP');
        assert(cur_recipient_bal <= 100_000_000_000_000, 'MERCHANT_BAL_CAP');

        self.duress_triggered_notes.write(note_id, true);
        self.active_carrier_pool.write(cur_carrier - total_moved);
        self.merchant_claims_pool.write(cur_merchants + decoy_spend);
        self.merchant_balances.write(decoy_recipient, cur_recipient_bal + decoy_spend);
        self.pq_recovery_pool.write(cur_pq + shelter_amount);

        self.emit(DuressShelterTriggered { note_id, decoy_spend, shelter_amount });
    }

    /// 5. Transfer settled merchant claims between distinct merchant keys inside
    /// `merchant_claims_pool`.
    #[external(v0)]
    fn transfer_merchant_claim(ref self: ContractState, from: felt252, to: felt252, amount: u128) {
        let caller: felt252 = get_caller_address().into();
        assert(caller == from && caller != 0, 'UNAUTHORIZED_MERCHANT');
        assert(to != 0, 'ZERO_RECIPIENT');
        assert(from != to, 'SELF_TRANSFER_FORBIDDEN');
        assert(amount <= 1_000_000_000, 'TRANSFER_CAP');

        let from_bal = self.merchant_balances.read(from);
        let to_bal = self.merchant_balances.read(to);
        assert(from_bal >= amount, 'INSUFFICIENT_MERCHANT_CLAIM');
        assert(to_bal <= 100_000_000_000_000, 'MERCHANT_BAL_CAP');

        self.merchant_balances.write(from, from_bal - amount);
        self.merchant_balances.write(to, to_bal + amount);
    }

    /// 6. Withdraw settled merchant claims from `merchant_claims_pool`, updating
    /// `total_vault_assets` atomically.
    #[external(v0)]
    fn withdraw_merchant_claim(ref self: ContractState, amount: u128) {
        let caller: felt252 = get_caller_address().into();
        assert(caller != 0, 'ZERO_CALLER');
        assert(!self.emergency_frozen.read(), 'VAULT_FROZEN');
        assert(amount > 0 && amount <= 1_000_000_000, 'WITHDRAW_CAP');

        let cur_bal = self.merchant_balances.read(caller);
        let cur_merchants = self.merchant_claims_pool.read();
        let cur_total = self.total_vault_assets.read();
        assert(cur_bal >= amount, 'INSUFFICIENT_MERCHANT_CLAIM');
        assert(cur_merchants >= amount && cur_total >= amount, 'POOL_UNDERFLOW');

        self.merchant_balances.write(caller, cur_bal - amount);
        self.merchant_claims_pool.write(cur_merchants - amount);
        self.total_vault_assets.write(cur_total - amount);

        self.emit(MerchantClaimWithdrawn { merchant: caller, amount });
    }

    /// 7. Governor setter for maximum mesh relay fee (in bps, capped at 300 bps = 3%).
    #[external(v0)]
    fn set_relay_fee_cap(ref self: ContractState, new_fee_bps: u32) {
        let caller: felt252 = get_caller_address().into();
        assert(caller == self.governor.read(), 'NOT_GOVERNOR');
        assert(!self.emergency_frozen.read(), 'FROZEN_ZERO_FEE_REQUIRED');
        assert(new_fee_bps <= 300, 'FEE_CAP_EXCEEDED');
        self.max_relay_fee_bps.write(new_fee_bps);
    }

    /// 8. Emergency freeze: halts new carrier mints/settlements and zeros the relay fee cap.
    #[external(v0)]
    fn activate_emergency_freeze(ref self: ContractState) {
        let caller: felt252 = get_caller_address().into();
        assert(caller == self.governor.read(), 'NOT_GOVERNOR');
        self.emergency_frozen.write(true);
        self.max_relay_fee_bps.write(0);
        self.emit(EmergencyFreezeActivated { governor: caller });
    }

    #[external(v0)]
    fn get_vault_pools(self: @ContractState) -> (u128, u128, u128, u128, u128, u128) {
        (
            self.total_vault_assets.read(),
            self.active_carrier_pool.read(),
            self.slash_bond_pool.read(),
            self.merchant_claims_pool.read(),
            self.pq_recovery_pool.read(),
            self.relay_fee_pool.read(),
        )
    }

    #[external(v0)]
    fn get_merchant_balance(self: @ContractState, merchant: felt252) -> u128 {
        self.merchant_balances.read(merchant)
    }

    #[external(v0)]
    fn is_nullifier_settled(self: @ContractState, nullifier: felt252) -> bool {
        self.settled_nullifiers.read(nullifier)
    }

    #[external(v0)]
    fn is_note_slashed(self: @ContractState, note_id: felt252) -> bool {
        self.slashed_notes.read(note_id)
    }

    #[external(v0)]
    fn is_duress_triggered(self: @ContractState, note_id: felt252) -> bool {
        self.duress_triggered_notes.read(note_id)
    }

    #[external(v0)]
    fn is_emergency_frozen(self: @ContractState) -> bool {
        self.emergency_frozen.read()
    }

    #[external(v0)]
    fn get_max_relay_fee_bps(self: @ContractState) -> u32 {
        self.max_relay_fee_bps.read()
    }

    /// Inductive Invariant #1 (5-Pool Solvency Conservation):
    /// `total_vault_assets == active_carrier_pool + slash_bond_pool + merchant_claims_pool +
    /// pq_recovery_pool + relay_fee_pool`
    #[external(v0)]
    fn invariant_five_pool_solvency_conservation(self: @ContractState) {
        let total = self.total_vault_assets.read();
        let carriers = self.active_carrier_pool.read();
        let bonds = self.slash_bond_pool.read();
        let merchants = self.merchant_claims_pool.read();
        let pq_shelter = self.pq_recovery_pool.read();
        let relay_fees = self.relay_fee_pool.read();
        assert(
            total == carriers + bonds + merchants + pq_shelter + relay_fees,
            'FIVE_POOL_SOLVENCY_BROKEN',
        );
    }

    /// Inductive Invariant #2 (Relay Fee Cap & Freeze Safety):
    /// `max_relay_fee_bps <= 300` and whenever `emergency_frozen` is true, `max_relay_fee_bps ==
    /// 0`.
    #[external(v0)]
    fn invariant_relay_fee_and_freeze_policy(self: @ContractState) {
        let fee = self.max_relay_fee_bps.read();
        let frozen = self.emergency_frozen.read();
        assert(fee <= 300, 'RELAY_FEE_EXCEEDS_MAX');
        assert(!frozen || fee == 0, 'NONZERO_FEE_WHILE_FROZEN');
    }
}
