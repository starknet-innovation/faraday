# Faraday Snap (`@farcaster/snap`)

Optional **Farcaster / Network State Protocol** courier relay and **RLNv2 watchtower** for Faraday offline vouchers.

## Why It Exists

At a crowded conference, basement venue, or pop-up campus, payments happen offline over NFC, QR, or BLE. The first phone that regains Wi-Fi or cell service can relay queued `faraday1:...` receipts to Starknet through an embedded feed card and earn the voucher's `relay_fee`.

If two conflicting offline receipts arrive for the same `(note_id, seq_no)`, [`src/rln.ts`](src/rln.ts) immediately recovers `secret_s` over $\mathbb{F}_P$ (`P = 2^251 + 17 * 2^192 + 1`) and synthesizes `FaradayVault::slash_fork` calldata to reimburse the defrauded merchant.

## Run

```bash
# Run pure TypeScript F_P RLNv2 + Watchtower unit tests (Node 22+, zero install needed)
node --experimental-strip-types src/rln.test.ts

# Run local Snap server for the Farcaster Snap Emulator
pnpm install
pnpm dev
```
