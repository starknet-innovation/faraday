import { Hono } from "hono";
import { SPEC_VERSION, type SnapFunction } from "@farcaster/snap";
import { registerSnapHandler } from "@farcaster/snap-hono";
import { FaradayWatchtower, decodeFaradayUri } from "./rln.js";

const MODE_FIELD = "mode" as const;
const VOUCHER_FIELD = "voucher_uri" as const;

const watchtower = new FaradayWatchtower();

const snap: SnapFunction = async (ctx) => {
  const base = resolveBaseUrl(ctx.request);
  const mode =
    ctx.action.type === "post" && typeof ctx.action.inputs[MODE_FIELD] === "string"
      ? (ctx.action.inputs[MODE_FIELD] as string)
      : "relay";
  const rawUri =
    ctx.action.type === "post" && typeof ctx.action.inputs[VOUCHER_FIELD] === "string"
      ? (ctx.action.inputs[VOUCHER_FIELD] as string).trim()
      : "";

  let badge = "Airplane-Mode Cash • Starknet RLNv2";
  let description =
    "Relay a 96B offline receipt when back on signal, or auto-slash double-spends in F_P.";

  if (rawUri.startsWith("faraday1:")) {
    try {
      const parsed = decodeFaradayUri(rawUri);
      const verdict = watchtower.ingest(parsed);
      if (verdict.kind === "QUEUED_SETTLEMENT") {
        badge = `SETTLE QUEUED • +$${parsed.relayFee.toString()} tip`;
        description = `Note 0x${parsed.noteId.toString(16)} seq=${parsed.seqNo}: $${parsed.amount.toString()} ready for FaradayVault.settle_voucher.`;
      } else if (verdict.kind === "DOUBLE_SPEND_SLASHABLE") {
        badge = "FORK CAUGHT • SECRET RECOVERED";
        description = `RLNv2 extracted s=${verdict.extractedSecretS.slice(0, 12)}... Ready to call FaradayVault.slash_fork & reimburse merchant.`;
      } else {
        badge = "ALREADY QUEUED";
        description = `Identical voucher for note 0x${parsed.noteId.toString(16)} seq=${parsed.seqNo} is already queued.`;
      }
    } catch {
      badge = "INVALID URI";
      description = "Expected compact receipt format: faraday1:<note>:<seq>:<merchant>:...";
    }
  } else if (mode === "duress") {
    badge = "$5-Wrench Shield • PQ Teleport";
    description =
      "Panic biometric pays a $25 decoy while sweeping 100% of remaining cash + bond to your external PQ cold vault.";
  } else if (mode === "citizen") {
    badge = "Opt-In Citizen Bond (FID)";
    description =
      "Anonymous by default (tag=0). Campus citizens can bond an FID commitment that stays hidden unless RLN proves fraud.";
  }

  return {
    version: SPEC_VERSION,
    theme: { accent: "green" },
    ui: {
      root: "page",
      elements: {
        page: {
          type: "stack",
          props: {},
          children: ["header", "modes", "status", "submit"],
        },
        header: {
          type: "item",
          props: {
            title: "Faraday // Offline Cash Relay",
            description,
          },
        },
        modes: {
          type: "toggle_group",
          props: {
            name: MODE_FIELD,
            options: ["relay", "duress", "citizen"],
          },
        },
        status: {
          type: "badge",
          props: { label: badge },
        },
        submit: {
          type: "button",
          props: { label: "Sync / Check Watchtower" },
          on: {
            press: {
              action: "submit",
              params: { target: `${base}/` },
            },
          },
        },
      },
    },
  };
};

const app = new Hono();
registerSnapHandler(app, snap);

export default app;

function resolveBaseUrl(request: Request): string {
  const fromEnv = process.env.SNAP_PUBLIC_BASE_URL?.trim();
  if (fromEnv) return fromEnv.replace(/\/$/, "");
  const host = (request.headers.get("x-forwarded-host") ?? request.headers.get("host"))
    ?.split(",")[0]
    ?.trim();
  if (!host) return `http://localhost:${process.env.PORT ?? "3003"}`;
  const isLocal = /^(localhost|127\.0\.0\.1|\[::1\]|::1)(:\d+)?$/.test(host);
  const proto = request.headers.get("x-forwarded-proto")?.split(",")[0]?.trim() ?? (isLocal ? "http" : "https");
  return `${proto}://${host}`.replace(/\/$/, "");
}
