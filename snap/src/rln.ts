/**
 * Pure F_P Rate-Limiting Nullifier (RLNv2) Shamir extractor, compact URI codec,
 * and offline fork watchtower matching `src/protocol.cairo` bit-for-bit.
 */

export const STARK_PRIME = (1n << 251n) + 17n * (1n << 192n) + 1n;

export function modFp(x: bigint): bigint {
  const r = x % STARK_PRIME;
  return r >= 0n ? r : r + STARK_PRIME;
}

/** Extended Euclidean modular inverse over Starknet prime field F_P. */
export function invFp(a: bigint): bigint {
  let t = 0n;
  let newT = 1n;
  let r = STARK_PRIME;
  let newR = modFp(a);
  if (newR === 0n) {
    throw new Error("ZERO_DENOMINATOR_IN_FP");
  }
  while (newR !== 0n) {
    const q = r / newR;
    [t, newT] = [newT, t - q * newT];
    [r, newR] = [newR, r - q * newR];
  }
  return modFp(t);
}

/**
 * Recovers `(secretS, slopeA1)` in F_P from two distinct offline RLN shares `(x1, y1)` and `(x2, y2)`
 * generated at the same `(noteId, seqNo)`. Returns `null` for an honest non-fork (`x1 === x2`).
 */
export function recoverSecretFromFork(
  x1: bigint,
  y1: bigint,
  x2: bigint,
  y2: bigint,
): { secretS: bigint; slopeA1: bigint } | null {
  const dx = modFp(x1 - x2);
  if (dx === 0n) return null;
  const dy = modFp(y1 - y2);
  const slopeA1 = modFp(dy * invFp(dx));
  const secretS = modFp(y1 - modFp(slopeA1 * modFp(x1)));
  return { secretS, slopeA1 };
}

export interface FaradayCompactVoucher {
  noteId: bigint;
  seqNo: number;
  merchant: bigint;
  amount: bigint;
  relayFee: bigint;
  nullifier: bigint;
  challengeX: bigint;
  shamirY: bigint;
  sigR: bigint;
  sigS: bigint;
}

const hex = (v: bigint): string => "0x" + v.toString(16);

/** Encodes an offline tap receipt into a QR / BLE / Farcaster Snap pasteable `faraday1:` URI. */
export function encodeFaradayUri(v: FaradayCompactVoucher): string {
  return [
    "faraday1",
    hex(v.noteId),
    v.seqNo.toString(10),
    hex(v.merchant),
    v.amount.toString(10),
    v.relayFee.toString(10),
    hex(v.nullifier),
    hex(v.challengeX),
    hex(v.shamirY),
    hex(v.sigR),
    hex(v.sigS),
  ].join(":");
}

export function decodeFaradayUri(uri: string): FaradayCompactVoucher {
  const parts = uri.trim().split(":");
  if (parts.length !== 11 || parts[0] !== "faraday1") {
    throw new Error("INVALID_FARADAY_URI");
  }
  return {
    noteId: BigInt(parts[1]),
    seqNo: Number(parts[2]),
    merchant: BigInt(parts[3]),
    amount: BigInt(parts[4]),
    relayFee: BigInt(parts[5]),
    nullifier: BigInt(parts[6]),
    challengeX: BigInt(parts[7]),
    shamirY: BigInt(parts[8]),
    sigR: BigInt(parts[9]),
    sigS: BigInt(parts[10]),
  };
}

export type WatchtowerVerdict =
  | {
      kind: "QUEUED_SETTLEMENT";
      entrypoint: "settle_voucher";
      calldata: string[];
    }
  | {
      kind: "IDEMPOTENT_DUPLICATE";
    }
  | {
      kind: "DOUBLE_SPEND_SLASHABLE";
      entrypoint: "slash_fork";
      extractedSecretS: string;
      calldata: string[];
    };

/**
 * Stateful watchtower index for mesh / Snapchain relays:
 * caches observed `(noteId, seqNo)` shares and automatically synthesizes `slash_fork`
 * calldata the instant an offline double-spend collides on `(noteId, seqNo)`.
 */
export class FaradayWatchtower {
  private seenByHop = new Map<string, FaradayCompactVoucher>();

  ingest(v: FaradayCompactVoucher, hunterBounty = 5n): WatchtowerVerdict {
    const key = `${hex(v.noteId)}:${v.seqNo}`;
    const prior = this.seenByHop.get(key);
    if (!prior) {
      this.seenByHop.set(key, v);
      return {
        kind: "QUEUED_SETTLEMENT",
        entrypoint: "settle_voucher",
        calldata: [
          hex(v.noteId),
          hex(v.nullifier),
          hex(v.merchant),
          v.amount.toString(10),
          v.relayFee.toString(10),
          hex(v.sigR),
          hex(v.sigS),
        ],
      };
    }

    const fork = recoverSecretFromFork(
      prior.challengeX,
      prior.shamirY,
      v.challengeX,
      v.shamirY,
    );
    if (!fork) {
      return { kind: "IDEMPOTENT_DUPLICATE" };
    }

    return {
      kind: "DOUBLE_SPEND_SLASHABLE",
      entrypoint: "slash_fork",
      extractedSecretS: hex(fork.secretS),
      calldata: [
        hex(v.noteId),
        v.seqNo.toString(10),
        hex(fork.secretS),
        hex(prior.challengeX),
        hex(prior.shamirY),
        hex(v.challengeX),
        hex(v.shamirY),
        hex(v.merchant),
        v.amount.toString(10),
        hunterBounty.toString(10),
      ],
    };
  }
}
