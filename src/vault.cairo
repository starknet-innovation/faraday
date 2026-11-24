use starknet::ContractAddress;

pub const STATUS_NONE: u8 = 0;
pub const STATUS_ACTIVE: u8 = 1;
pub const STATUS_CLOSING: u8 = 2;
pub const STATUS_CLOSED: u8 = 3;
pub const STATUS_SLASHED: u8 = 4;
pub const STATUS_DURESS_SWEPT: u8 = 5;

/// Self-contained offline bearer note backed by real ERC-20 collateral + RLNv2 slashing bond.
#[derive(Drop, Copy, Serde, starknet::Store)]
pub struct OfflineNote {
    pub owner: ContractAddress,
    pub signer_pubkey: felt252,
    pub commitment: felt252,
    pub duress_hash: felt252,
    pub pq_safe_recipient: ContractAddress,
    /// Optional community / Network State / Farcaster citizen commitment (`0` = anonymous mode).
    /// Never exposed during honest taps; emitted only if `slash_fork` proves offline equivocation.
    pub citizen_tag: felt252,
    pub balance: u128,
    pub bond: u128,
    pub close_unlock_at: u64,
    pub status: u8,
}

#[starknet::interface]
pub trait IERC20<TContractState> {
    fn transfer(ref self: TContractState, recipient: ContractAddress, amount: u256) -> bool;
    fn transfer_from(
        ref self: TContractState, sender: ContractAddress, recipient: ContractAddress, amount: u256,
    ) -> bool;
}

#[starknet::interface]
pub trait IFaradayVault<TContractState> {
    fn open_note(
        ref self: TContractState,
        note_id: felt252,
        signer_pubkey: felt252,
        commitment: felt252,
        duress_hash: felt252,
        pq_safe_recipient: ContractAddress,
        citizen_tag: felt252,
        deposit: u128,
        bond: u128,
    );
    fn settle_voucher(
        ref self: TContractState,
        note_id: felt252,
        nullifier: felt252,
        merchant: ContractAddress,
        amount: u128,
        relay_fee: u128,
        sig_r: felt252,
        sig_s: felt252,
    );
    fn slash_fork(
        ref self: TContractState,
        note_id: felt252,
        seq_no: u64,
        secret_s: felt252,
        x1: felt252,
        y1: felt252,
        x2: felt252,
        y2: felt252,
        defrauded_merchant: ContractAddress,
        victim_claim: u128,
        hunter_bounty: u128,
    );
    fn duress_sweep(
        ref self: TContractState,
        note_id: felt252,
        duress_secret: felt252,
        decoy_recipient: ContractAddress,
        decoy_amount: u128,
    );
    fn request_close(ref self: TContractState, note_id: felt252);
    fn finalize_close(ref self: TContractState, note_id: felt252);

    fn get_note(self: @TContractState, note_id: felt252) -> OfflineNote;
    fn get_vault_totals(self: @TContractState) -> (u128, u128, u128);
    fn is_nullifier_settled(self: @TContractState, nullifier: felt252) -> bool;
    fn get_asset_token(self: @TContractState) -> ContractAddress;
    fn get_grace_period_secs(self: @TContractState) -> u64;
    fn invariant_escrow_conservation(self: @TContractState);
}

#[starknet::contract]
pub mod FaradayVault {
    use core::ecdsa::check_ecdsa_signature;
    use core::num::traits::Zero;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::{ContractAddress, get_block_timestamp, get_caller_address, get_contract_address};
    use super::super::protocol::{
        compute_duress_hash, compute_note_commitment, compute_voucher_hash, poseidon2, poseidon3,
    };
    use super::{
        IERC20Dispatcher, IERC20DispatcherTrait, OfflineNote, STATUS_ACTIVE, STATUS_CLOSED,
        STATUS_CLOSING, STATUS_DURESS_SWEPT, STATUS_NONE, STATUS_SLASHED,
    };

    #[storage]
    struct Storage {
        asset_token: ContractAddress,
        grace_period_secs: u64,
        total_vault_escrowed: u128,
        total_balance_escrowed: u128,
        total_bond_escrowed: u128,
        notes: Map<felt252, OfflineNote>,
        settled_nullifiers: Map<felt252, bool>,
        slashed_claims: Map<felt252, bool>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        NoteOpened: NoteOpened,
        VoucherSettled: VoucherSettled,
        OfflineForkSlashed: OfflineForkSlashed,
        DuressSweptToPqVault: DuressSweptToPqVault,
        NoteCloseRequested: NoteCloseRequested,
        NoteClosed: NoteClosed,
    }

    #[derive(Drop, starknet::Event)]
    pub struct NoteOpened {
        #[key]
        pub note_id: felt252,
        pub owner: ContractAddress,
        pub deposit: u128,
        pub bond: u128,
    }

    #[derive(Drop, starknet::Event)]
    pub struct VoucherSettled {
        #[key]
        pub note_id: felt252,
        #[key]
        pub nullifier: felt252,
        pub merchant: ContractAddress,
        pub amount: u128,
        pub relay_fee: u128,
    }

    #[derive(Drop, starknet::Event)]
    pub struct OfflineForkSlashed {
        #[key]
        pub note_id: felt252,
        pub seq_no: u64,
        /// Zero for anonymous notes; non-zero exposes the citizen/FID bond tag on proven fraud.
        pub citizen_tag: felt252,
        pub defrauded_merchant: ContractAddress,
        pub victim_claim: u128,
        pub hunter_bounty: u128,
    }

    #[derive(Drop, starknet::Event)]
    pub struct DuressSweptToPqVault {
        #[key]
        pub note_id: felt252,
        pub decoy_amount: u128,
        pub sheltered_amount: u128,
        pub pq_safe_recipient: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct NoteCloseRequested {
        #[key]
        pub note_id: felt252,
        pub unlock_at: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct NoteClosed {
        #[key]
        pub note_id: felt252,
        pub owner: ContractAddress,
        pub refunded_total: u128,
    }

    #[constructor]
    fn constructor(ref self: ContractState, asset_token: ContractAddress, grace_period_secs: u64) {
        assert(!asset_token.is_zero(), 'ZERO_ASSET_TOKEN');
        assert(grace_period_secs >= 60 && grace_period_secs <= 604_800, 'INVALID_GRACE_PERIOD');
        self.asset_token.write(asset_token);
        self.grace_period_secs.write(grace_period_secs);
        self.total_vault_escrowed.write(0);
        self.total_balance_escrowed.write(0);
        self.total_bond_escrowed.write(0);
    }

    #[abi(embed_v0)]
    impl FaradayVaultImpl of super::IFaradayVault<ContractState> {
        /// 1. Lock ERC-20 spending cash + RLNv2 anti-fraud bond into an isolated `OfflineNote`.
        fn open_note(
            ref self: ContractState,
            note_id: felt252,
            signer_pubkey: felt252,
            commitment: felt252,
            duress_hash: felt252,
            pq_safe_recipient: ContractAddress,
            citizen_tag: felt252,
            deposit: u128,
            bond: u128,
        ) {
            let caller = get_caller_address();
            assert(!caller.is_zero(), 'ZERO_CALLER');
            assert(
                note_id != 0 && signer_pubkey != 0 && commitment != 0 && duress_hash != 0,
                'ZERO_NOTE_PARAM',
            );
            assert(!pq_safe_recipient.is_zero(), 'ZERO_PQ_RECIPIENT');

            let existing = self.notes.read(note_id);
            assert(existing.status == STATUS_NONE, 'NOTE_ALREADY_EXISTS');
            assert(deposit > 0 && deposit <= 1_000_000_000_000, 'INVALID_DEPOSIT');
            assert(bond >= deposit && bond <= 2_000_000_000_000, 'BOND_BELOW_DEPOSIT');

            let cur_bal = self.total_balance_escrowed.read();
            let cur_bond = self.total_bond_escrowed.read();
            let cur_total = self.total_vault_escrowed.read();
            assert(cur_bal <= 100_000_000_000_000_000, 'BAL_ESCROW_CAP');
            assert(cur_bond <= 100_000_000_000_000_000, 'BOND_ESCROW_CAP');

            let total_locked = deposit + bond;
            let token_addr = self.asset_token.read();
            let vault_addr = get_contract_address();

            // Effects strictly precede ERC-20 external call (CEI)
            self
                .notes
                .write(
                    note_id,
                    OfflineNote {
                        owner: caller,
                        signer_pubkey,
                        commitment,
                        duress_hash,
                        pq_safe_recipient,
                        citizen_tag,
                        balance: deposit,
                        bond,
                        close_unlock_at: 0,
                        status: STATUS_ACTIVE,
                    },
                );
            self.total_balance_escrowed.write(cur_bal + deposit);
            self.total_bond_escrowed.write(cur_bond + bond);
            self.total_vault_escrowed.write(cur_total + total_locked);
            self.emit(NoteOpened { note_id, owner: caller, deposit, bond });

            let erc20 = IERC20Dispatcher { contract_address: token_addr };
            assert(
                erc20.transfer_from(caller, vault_addr, total_locked.into()),
                'ERC20_TRANSFER_FROM_FAILED',
            );
        }

        /// 2. Settle a signed offline voucher when either phone or a mesh/Snap courier reconnects.
        fn settle_voucher(
            ref self: ContractState,
            note_id: felt252,
            nullifier: felt252,
            merchant: ContractAddress,
            amount: u128,
            relay_fee: u128,
            sig_r: felt252,
            sig_s: felt252,
        ) {
            let relayer = get_caller_address();
            assert(!relayer.is_zero() && !merchant.is_zero(), 'ZERO_SETTLE_ADDR');
            assert(nullifier != 0 && amount > 0, 'INVALID_VOUCHER');
            assert(!self.settled_nullifiers.read(nullifier), 'VOUCHER_ALREADY_SETTLED');
            assert(relay_fee <= amount, 'RELAY_FEE_EXCEEDS_AMOUNT');

            let mut note = self.notes.read(note_id);
            assert(
                note.status == STATUS_ACTIVE || note.status == STATUS_CLOSING,
                'NOTE_NOT_SETTLEABLE',
            );
            assert(amount <= note.balance, 'INSUFFICIENT_NOTE_BALANCE');
            let after_amount = note.balance - amount;
            assert(relay_fee <= after_amount, 'INSUFFICIENT_FOR_RELAY_FEE');

            let voucher_hash = compute_voucher_hash(
                note_id, nullifier, merchant.into(), amount, relay_fee,
            );
            assert(
                check_ecdsa_signature(voucher_hash, note.signer_pubkey, sig_r, sig_s),
                'INVALID_VOUCHER_SIGNATURE',
            );

            let total_debit = amount + relay_fee;
            let cur_bal = self.total_balance_escrowed.read();
            let cur_total = self.total_vault_escrowed.read();
            assert(cur_bal >= total_debit && cur_total >= total_debit, 'ESCROW_UNDERFLOW');
            let token_addr = self.asset_token.read();

            // Effects before external ERC-20 payouts (CEI)
            note.balance = after_amount - relay_fee;
            self.settled_nullifiers.write(nullifier, true);
            self.notes.write(note_id, note);
            self.total_balance_escrowed.write(cur_bal - total_debit);
            self.total_vault_escrowed.write(cur_total - total_debit);
            self.emit(VoucherSettled { note_id, nullifier, merchant, amount, relay_fee });

            let erc20 = IERC20Dispatcher { contract_address: token_addr };
            assert(erc20.transfer(merchant, amount.into()), 'MERCHANT_TRANSFER_FAILED');
            if relay_fee > 0 {
                assert(erc20.transfer(relayer, relay_fee.into()), 'RELAY_TRANSFER_FAILED');
            }
        }

        /// 3. RLNv2 Shamir Double-Spend Slashing:
        /// Verifies two distinct points `(x1, y1)` and `(x2, y2)` on `y = secret_s + a1 * x (mod
        /// P)`
        /// for `(note_id, seq_no)`, freezes the cheater's note (`STATUS_SLASHED`), and reimburses
        /// defrauded merchants out of `note.bond + note.balance`.
        fn slash_fork(
            ref self: ContractState,
            note_id: felt252,
            seq_no: u64,
            secret_s: felt252,
            x1: felt252,
            y1: felt252,
            x2: felt252,
            y2: felt252,
            defrauded_merchant: ContractAddress,
            victim_claim: u128,
            hunter_bounty: u128,
        ) {
            let hunter = get_caller_address();
            assert(!hunter.is_zero() && !defrauded_merchant.is_zero(), 'ZERO_SLASH_ADDR');
            assert(seq_no < 1_000_000, 'SEQ_OVERFLOW');
            assert(victim_claim > 0, 'ZERO_VICTIM_CLAIM');

            let claim_key = poseidon3(note_id, seq_no.into(), defrauded_merchant.into());
            assert(!self.slashed_claims.read(claim_key), 'CLAIM_ALREADY_COMPENSATED');

            let mut note = self.notes.read(note_id);
            assert(
                note.status == STATUS_ACTIVE
                    || note.status == STATUS_CLOSING
                    || note.status == STATUS_SLASHED,
                'NOTE_NOT_SLASHABLE',
            );

            let computed_commitment = compute_note_commitment(secret_s, note_id);
            assert(computed_commitment == note.commitment, 'SECRET_MISMATCH_FOR_NOTE');
            let a1 = poseidon2(computed_commitment, seq_no.into());

            assert(x1 != x2, 'NOT_A_FORK_SAME_CHALLENGE');
            assert(y1 == secret_s + a1 * x1, 'INVALID_SHAMIR_SHARE_1');
            assert(y2 == secret_s + a1 * x2, 'INVALID_SHAMIR_SHARE_2');

            let collateral = note.bond + note.balance;
            assert(victim_claim <= collateral, 'INSUFFICIENT_SLASH_COLLATERAL');
            let after_victim = collateral - victim_claim;
            assert(hunter_bounty <= after_victim, 'INSUFFICIENT_FOR_BOUNTY');
            let total_slashed = victim_claim + hunter_bounty;

            // Drain `note.bond` first, then any residual from `note.balance`
            let (bond_taken, bal_taken) = if total_slashed <= note.bond {
                (total_slashed, 0_u128)
            } else {
                (note.bond, total_slashed - note.bond)
            };

            let cur_bal = self.total_balance_escrowed.read();
            let cur_bond = self.total_bond_escrowed.read();
            let cur_total = self.total_vault_escrowed.read();
            assert(
                cur_bond >= bond_taken && cur_bal >= bal_taken && cur_total >= total_slashed,
                'ESCROW_UNDERFLOW',
            );
            let citizen_tag = note.citizen_tag;
            let token_addr = self.asset_token.read();

            // Effects before external ERC-20 transfers (CEI)
            note.bond -= bond_taken;
            note.balance -= bal_taken;
            note.status = STATUS_SLASHED;
            self.slashed_claims.write(claim_key, true);
            self.notes.write(note_id, note);
            self.total_bond_escrowed.write(cur_bond - bond_taken);
            self.total_balance_escrowed.write(cur_bal - bal_taken);
            self.total_vault_escrowed.write(cur_total - total_slashed);
            self
                .emit(
                    OfflineForkSlashed {
                        note_id,
                        seq_no,
                        citizen_tag,
                        defrauded_merchant,
                        victim_claim,
                        hunter_bounty,
                    },
                );

            let erc20 = IERC20Dispatcher { contract_address: token_addr };
            assert(
                erc20.transfer(defrauded_merchant, victim_claim.into()),
                'VICTIM_COMPENSATION_FAILED',
            );
            if hunter_bounty > 0 {
                assert(erc20.transfer(hunter, hunter_bounty.into()), 'HUNTER_BOUNTY_FAILED');
            }
        }

        /// 4. Anti-Coercion Duress Sweep ($5-Wrench Defense):
        /// Verifies `Poseidon(duress_secret, note_id) == note.duress_hash`, pays a small plausible
        /// `decoy_amount`, and sweeps 100% of remaining `balance + bond` directly to
        /// `note.pq_safe_recipient`.
        fn duress_sweep(
            ref self: ContractState,
            note_id: felt252,
            duress_secret: felt252,
            decoy_recipient: ContractAddress,
            decoy_amount: u128,
        ) {
            let caller = get_caller_address();
            assert(!caller.is_zero() && !decoy_recipient.is_zero(), 'ZERO_DURESS_ADDR');

            let mut note = self.notes.read(note_id);
            assert(
                note.status == STATUS_ACTIVE || note.status == STATUS_CLOSING,
                'NOTE_NOT_ACTIVE_FOR_DURESS',
            );
            assert(
                compute_duress_hash(duress_secret, note_id) == note.duress_hash,
                'INVALID_DURESS_SECRET',
            );
            assert(decoy_amount <= note.balance, 'DECOY_EXCEEDS_BALANCE');

            let old_bal = note.balance;
            let old_bond = note.bond;
            let total_drained = old_bal + old_bond;
            let sheltered_amount = (old_bal - decoy_amount) + old_bond;
            let pq_safe_recipient = note.pq_safe_recipient;

            let cur_bal = self.total_balance_escrowed.read();
            let cur_bond = self.total_bond_escrowed.read();
            let cur_total = self.total_vault_escrowed.read();
            assert(
                cur_bal >= old_bal && cur_bond >= old_bond && cur_total >= total_drained,
                'ESCROW_UNDERFLOW',
            );
            let token_addr = self.asset_token.read();

            // Effects before external ERC-20 transfers (CEI)
            note.balance = 0;
            note.bond = 0;
            note.status = STATUS_DURESS_SWEPT;
            self.notes.write(note_id, note);
            self.total_balance_escrowed.write(cur_bal - old_bal);
            self.total_bond_escrowed.write(cur_bond - old_bond);
            self.total_vault_escrowed.write(cur_total - total_drained);
            self
                .emit(
                    DuressSweptToPqVault {
                        note_id, decoy_amount, sheltered_amount, pq_safe_recipient,
                    },
                );

            let erc20 = IERC20Dispatcher { contract_address: token_addr };
            if decoy_amount > 0 {
                assert(erc20.transfer(decoy_recipient, decoy_amount.into()), 'DECOY_PAYOUT_FAILED');
            }
            if sheltered_amount > 0 {
                assert(
                    erc20.transfer(pq_safe_recipient, sheltered_amount.into()),
                    'PQ_SAFE_SWEEP_FAILED',
                );
            }
        }

        /// 5. Owner initiates note closure; offline merchants have `grace_period_secs` to settle or
        /// slash.
        fn request_close(ref self: ContractState, note_id: felt252) {
            let caller = get_caller_address();
            let mut note = self.notes.read(note_id);
            assert(caller == note.owner && !caller.is_zero(), 'NOT_NOTE_OWNER');
            assert(note.status == STATUS_ACTIVE, 'NOTE_NOT_ACTIVE');

            let now = get_block_timestamp();
            let grace = self.grace_period_secs.read();
            assert(now <= 10_000_000_000_000 && grace <= 604_800, 'TIMESTAMP_OVERFLOW');
            let unlock_at = now + grace;

            note.status = STATUS_CLOSING;
            note.close_unlock_at = unlock_at;
            self.notes.write(note_id, note);
            self.emit(NoteCloseRequested { note_id, unlock_at });
        }

        /// 6. After `grace_period_secs` elapses with zero fraud, returns 100% of remaining `balance
        /// + bond`.
        fn finalize_close(ref self: ContractState, note_id: felt252) {
            let caller = get_caller_address();
            let mut note = self.notes.read(note_id);
            assert(caller == note.owner && !caller.is_zero(), 'NOT_NOTE_OWNER');
            assert(note.status == STATUS_CLOSING, 'NOTE_NOT_CLOSING');
            assert(get_block_timestamp() >= note.close_unlock_at, 'GRACE_PERIOD_ACTIVE');

            let rem_bal = note.balance;
            let rem_bond = note.bond;
            let refunded_total = rem_bal + rem_bond;

            let cur_bal = self.total_balance_escrowed.read();
            let cur_bond = self.total_bond_escrowed.read();
            let cur_total = self.total_vault_escrowed.read();
            assert(
                cur_bal >= rem_bal && cur_bond >= rem_bond && cur_total >= refunded_total,
                'ESCROW_UNDERFLOW',
            );
            let token_addr = self.asset_token.read();

            // Effects before external ERC-20 refund (CEI)
            note.balance = 0;
            note.bond = 0;
            note.status = STATUS_CLOSED;
            self.notes.write(note_id, note);
            self.total_balance_escrowed.write(cur_bal - rem_bal);
            self.total_bond_escrowed.write(cur_bond - rem_bond);
            self.total_vault_escrowed.write(cur_total - refunded_total);
            self.emit(NoteClosed { note_id, owner: caller, refunded_total });

            if refunded_total > 0 {
                let erc20 = IERC20Dispatcher { contract_address: token_addr };
                assert(erc20.transfer(caller, refunded_total.into()), 'CLOSE_REFUND_FAILED');
            }
        }

        fn get_note(self: @ContractState, note_id: felt252) -> OfflineNote {
            self.notes.read(note_id)
        }

        fn get_vault_totals(self: @ContractState) -> (u128, u128, u128) {
            (
                self.total_vault_escrowed.read(),
                self.total_balance_escrowed.read(),
                self.total_bond_escrowed.read(),
            )
        }

        fn is_nullifier_settled(self: @ContractState, nullifier: felt252) -> bool {
            self.settled_nullifiers.read(nullifier)
        }

        fn get_asset_token(self: @ContractState) -> ContractAddress {
            self.asset_token.read()
        }

        fn get_grace_period_secs(self: @ContractState) -> u64 {
            self.grace_period_secs.read()
        }

        /// Solvency invariant: `total_vault_escrowed == total_balance_escrowed +
        /// total_bond_escrowed`.
        fn invariant_escrow_conservation(self: @ContractState) {
            let total = self.total_vault_escrowed.read();
            let bal = self.total_balance_escrowed.read();
            let bond = self.total_bond_escrowed.read();
            assert(total == bal + bond, 'ESCROW_CONSERVATION_BROKEN');
        }
    }
}
