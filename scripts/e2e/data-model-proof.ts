#!/usr/bin/env node

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { renderReviewCommentFromReport } from "../../dist/clawsweeper.js";
import { reviewReportFrontMatter } from "../../test/helpers.ts";

const baseline = process.argv.includes("--baseline");
assert.ok(process.argv.slice(2).every((arg) => arg === "--baseline"));
const receipts = [];
for (const override of [false, true]) {
  for (const status of ["sufficient", "missing"]) {
    const report = `${reviewReportFrontMatter({
      repository: "openclaw/openclaw",
      type: "pull_request",
      number: "74464",
      decision: "keep_open",
      close_reason: "none",
      review_status: "complete",
      confidence: "high",
      labels: JSON.stringify(["clawsweeper:automerge", ...(override ? ["proof: override"] : [])]),
      work_candidate: "none",
      pull_head_sha: "a".repeat(40),
      real_behavior_proof_status: status,
      data_model_change: "true",
      data_model_surfaces: JSON.stringify(["database schema: packages/database/schema.ts"]),
    })}

## Summary

Synthetic compatibility rendering scenario.

## What This Changes

Adds a stored database column.

## Real Behavior Proof

Status: ${status}

Evidence kind: terminal

Needs contributor action: false

Summary: Upgrade compatibility is verified against an existing database.

## Review Findings

Overall correctness: patch is correct

Overall confidence: 0.9

Full review comments:

- none
`;
    const comment = renderReviewCommentFromReport(report, "none");
    const observed = {
      compatibilityBlocker: comment.includes("Add data-model compatibility proof"),
      compatibilityRecorded: comment.includes(
        "Migration or upgrade compatibility proof is recorded",
      ),
      passMarker: comment.includes("clawsweeper-verdict:pass"),
    };
    const accepted = !baseline && status === "sufficient";
    assert.equal(observed.compatibilityBlocker, !accepted);
    assert.equal(observed.compatibilityRecorded, accepted);
    assert.equal(observed.passMarker, accepted);
    receipts.push({ status, override, observed });
  }
}
console.log(
  JSON.stringify(
    {
      mode: baseline ? "baseline" : "candidate",
      node: process.version,
      ownerSha256: createHash("sha256")
        .update(
          readFileSync(
            new URL("../../dist/clawsweeper-orchestration-foundation.js", import.meta.url),
          ),
        )
        .digest("hex"),
      surface: "compiled production report renderer with synthetic serialized reports",
      receipts,
      limits: "No live GitHub publication, canonical report, or actual database upgrade exercised.",
    },
    null,
    2,
  ),
);
