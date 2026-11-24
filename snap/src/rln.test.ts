import assert from "node:assert/strict";
import {
  FaradayWatchtower,
  STARK_PRIME,
  decodeFaradayUri,
  encodeFaradayUri,
  modFp,
  recoverSecretFromFork,
} from "./rln.ts";

// 1. Verify exact F_P Shamir extraction over large 251-bit Stark field elements
const secretS = STARK_PRIME - 133742n;
const slopeA1 = (1n << 240n) + 99991n;
const x1 = 0x1111aaaa2222bbbbn;
const x2 = 0x3333cccc4444ddddn;
const y1 = modFp(secretS + modFp(slopeA1 * x1));
const y2 = modFp(secretS + modFp(slopeA1 * x2));

assert.equal(recoverSecretFromFork(x1, y1, x1, y1), null);
const extracted = recoverSecretFromFork(x1, y1, x2, y2);
assert.ok(extracted !== null);
assert.equal(extracted.secretS, secretS);
assert.equal(extracted.slopeA1, slopeA1);

// 2. Verify compact `faraday1:` URI roundtrip + Watchtower fork detection
const watchtower = new FaradayWatchtower();
const vA = {
  noteId: 0x202n,
  seqNo: 0,
  merchant: 0xb0bn,
  amount: 25n,
  relayFee: 1n,
  nullifier: 0xdeadbeefn,
  challengeX: x1,
  shamirY: y1,
  sigR: 0x123n,
  sigS: 0x456n,
};
const uri = encodeFaradayUri(vA);
const decoded = decodeFaradayUri(uri);
assert.equal(decoded.noteId, 0x202n);

const res1 = watchtower.ingest(decoded);
assert.equal(res1.kind, "QUEUED_SETTLEMENT");

const res2 = watchtower.ingest({
  ...vA,
  merchant: 0xca201n,
  challengeX: x2,
  shamirY: y2,
});
assert.equal(res2.kind, "DOUBLE_SPEND_SLASHABLE");
assert.equal(res2.extractedSecretS, "0x" + secretS.toString(16));

console.log("faraday-snap RLNv2 & Watchtower tests: 100% PASS");
