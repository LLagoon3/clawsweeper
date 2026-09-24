// Explicitly synthetic scanner transport; this does not run TruffleHog or a model.
// The default production collector, parser, classifier and agent runner stay intact.
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  appendFileSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync,
  readdirSync, realpathSync, rmSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const BASE = "9e699cd65b6ca74805280e150657904be9abf64c";
const HEAD = "2c3cad792a279d73c2ef607552aad2fa38733879";
const HOST = "e4f02ecdd2aa90acb8fe39fcf818a6913ca11738";
const BUILD_BASE = "4233d61c38cd30e6c2fdfbd8ac140f7fba2bcc9e";
const BUILD_TREE = "0687c5b32a54e9493dfc706aebce718fde545620";
const SOURCE = "skills/autoreview/tests/test_autoreview_hardening.py";
const BLOBS = [
  "77046bce188161a9cf7069a9054b64ee1f43baaf",
  "de010ae60dfe6d7d529a53a3bbd5be7e1aa29bf1",
];
const RAW_HASH = "7b8ee01b06a7e5b375164f2c45249bb258c75726a60b27e20a0ba6e42d5d0b27";
const LINES = [
  "1a0920c31a227ead081fd2e6582572dfee060995e266a5520f66021acaa918c9",
  "c445f98d7d20b87bca6fead0e081385981add30abd58123db8d8d71c799d14a9",
];
const PROMPT = { bytes: 124462, sha256: "7b51f9d43971b8b1ece943554332949a788044419b4eeaabcef2bdff242faba0" };
const SCHEMA = { bytes: 57818, sha256: "9020b3b32de50c91ce15299b80a9028434fc38722986bcbfd58d8fe739c4cd34" };
const MODULES = [
  "agent-runner", "agent-input-scan", "agent-input-scan-fixtures",
  "agent-input-scan-git-metadata", "agent-input-scan-patch", "pr-review-evidence",
  "review-tool-bootstrap", "content-hash", "openclaw-process", "codex-output-capture",
  "value-coerce", "codex-process", "codex-spawn", "command", "codex-env",
  "codex-process-worker", "codex-output-last-message",
].map((name) => `dist/${name}.js`);
const SELF = fileURLToPath(import.meta.url);
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const identity = (bytes) => ({ bytes: Buffer.byteLength(bytes), sha256: hash(bytes) });
class ProofFailure extends Error {}
function check(condition, label) {
  if (!condition) throw new ProofFailure(label);
}
function regular(path) {
  const metadata = lstatSync(path);
  check(metadata.isFile() && !metadata.isSymbolicLink(), "non-regular proof input");
  return readFileSync(path);
}
function sameIdentity(bytes, expected, label) {
  check(bytes.length === expected.bytes && hash(bytes) === expected.sha256, label);
}
function git(target, args) {
  const result = spawnSync("git", ["--no-pager", "-c", "core.fsmonitor=false", ...args], {
    cwd: target, encoding: null, timeout: 30_000, maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, GIT_OPTIONAL_LOCKS: "0", GIT_NO_LAZY_FETCH: "1" },
  });
  check(!result.error && result.status === 0, "target Git read failed");
  return result.stdout;
}
function targetIdentity(target) {
  check(git(target, ["rev-parse", "HEAD"]).toString().trim() === HEAD, "target HEAD changed");
  check(git(target, ["status", "--porcelain=v1", "-z"]).length === 0, "target is not clean");
  const endpoints = [BASE, HEAD].map((revision, index) => {
    check(
      git(target, ["ls-tree", "-z", revision, "--", SOURCE]).toString()
        === `100644 blob ${BLOBS[index]}\t${SOURCE}\0`,
      "canonical source path, mode or blob changed",
    );
    const bytes = git(target, ["cat-file", "blob", BLOBS[index]]);
    const witness = deriveWitness(bytes, BLOBS[index]);
    return { revision, blob: BLOBS[index], mode: "100644", lines: witness.lines, ...identity(bytes) };
  });
  return { base: BASE, head: HEAD, source: SOURCE, endpoints,
    indexSha256: hash(git(target, ["ls-files", "--stage", "-z"])) };
}
function deriveWitness(bytes, blob) {
  const oid = createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex");
  check(oid === blob, "source blob identity mismatch");
  const lines = new TextDecoder("utf-8", { fatal: true }).decode(bytes).split("\n");
  const matches = lines.flatMap((line, index) => LINES.includes(hash(line)) ? [{ line, number: index + 1 }] : []);
  check(matches.length === 2 && matches.every((row, index) => hash(row.line) === LINES[index]), "ordered source witnesses changed");
  const first = Buffer.from(matches[0].line);
  const values = [];
  for (let offset = 0; offset + 56 <= first.length; offset++) {
    const value = first.subarray(offset, offset + 56);
    if (hash(value) === RAW_HASH) values.push(value);
  }
  check(values.length === 1, "canonical 56-byte identity is not unique");
  const raw = values[0].toString("utf8");
  const occurrences = [];
  for (const line of lines) {
    for (let offset = line.indexOf(raw); offset !== -1; offset = line.indexOf(raw, offset + raw.length)) occurrences.push(hash(line));
  }
  check(JSON.stringify(occurrences) === JSON.stringify(LINES), "complete blob occurrence witnesses changed");
  return { raw, lines: matches.map((row) => row.number) };
}
function verifyArtifacts(root, manifestFile) {
  const bytes = regular(manifestFile);
  const manifest = JSON.parse(bytes);
  check(manifest.sourceBase === BUILD_BASE && manifest.sourceTree === BUILD_TREE
    && manifest.runtimeSourceCommit === HOST, "qualified build provenance mismatch");
  check(manifest.build?.node === "v24.21.0" && manifest.build?.pnpm === "12.4.1", "qualified build toolchain mismatch");
  const files = {};
  for (const path of ["package.json", ...MODULES]) {
    files[path] = hash(regular(join(root, path)));
    check(files[path] === manifest.files?.[path], "qualified artifact hash mismatch");
  }
  check(files["dist/agent-input-scan-fixtures.js"] === "134e8b39b32e2b271ee0579e4873c35d624b9a24c58e274ac0b87bd869a66c7b", "candidate policy artifact changed");
  check(JSON.parse(regular(join(root, "package.json"))).type === "module", "artifact module contract changed");
  return { sourceBase: BUILD_BASE, sourceTree: BUILD_TREE, runtimeSourceCommit: HOST,
    build: { node: manifest.build.node, pnpm: manifest.build.pnpm }, manifestSha256: hash(bytes), files };
}

// This child implements only the existing test scanner's transport contract.
// Finding bytes come from production-staged canonical blobs, never a copied literal.
function syntheticScanner(config, args) {
  for (const key of ["OPENAI_API_KEY", "GH_TOKEN", "CODEX_HOME", "NODE_OPTIONS", "GIT_CONFIG_COUNT"])
    check(process.env[key] === undefined, "scanner inherited a forbidden environment entry");
  if (args.length === 1 && args[0] === "--version") {
    process.stdout.write("trufflehog 3.97.4\n");
    return;
  }
  const [command, directory, ...flags] = args;
  check(command === "filesystem" && JSON.stringify(flags) === JSON.stringify([
    "--results=verified,unknown", "--fail", "--fail-on-scan-errors", "--no-update", "--json", "--no-color",
  ]), "production scanner arguments changed");
  check(lstatSync(directory).isDirectory() && (lstatSync(directory).mode & 0o777) === 0o700, "staging directory is not private");
  const staged = readdirSync(directory).sort().map((name) => {
    const file = join(directory, name);
    const bytes = regular(file);
    check((lstatSync(file).mode & 0o777) === 0o600, "staged input is not private");
    return { name, file, bytes };
  });
  sameIdentity(staged.find((row) => row.name === "prompt")?.bytes ?? Buffer.alloc(0), PROMPT, "staged prompt changed");
  sameIdentity(staged.find((row) => row.name === "schema")?.bytes ?? Buffer.alloc(0), SCHEMA, "staged schema changed");
  const findings = BLOBS.map((blob) => {
    const row = staged.find((input) => input.name === blob);
    check(Boolean(row), "canonical endpoint blob was not staged");
    const witness = deriveWitness(row.bytes, blob);
    const rawBytes = Buffer.from(witness.raw);
    if (config.altered) rawBytes[0] ^= 1;
    const uri = new URL(witness.raw);
    const authority = /^[^:]+:\/\/([^/?#]*)/.exec(witness.raw)?.[1];
    check(Boolean(authority), "canonical URI authority missing");
    return {
      DetectorType: 17, DetectorName: "URI", DecoderName: "PLAIN", SourceType: 15,
      Verified: false, VerificationError: "Synthetic transport: verification was not exercised.",
      Raw: rawBytes.toString("utf8"), RawV2: witness.raw, ExtraData: null, StructuredData: null,
      SecretParts: { host: authority.slice(authority.lastIndexOf("@") + 1), username: uri.username, password: uri.password },
      SourceMetadata: { Data: { Filesystem: { file: row.file, line: witness.lines[0] } } },
    };
  });
  const material = staged.map(({ name, bytes }) => ({ name, ...identity(bytes) }));
  writeFileSync(config.scanAudit, JSON.stringify({ material, directory, findings: findings.map((finding) => ({
    rawSha256: hash(finding.Raw), rawV2Sha256: hash(finding.RawV2),
  })) }), { mode: 0o600, flag: "wx" });
  process.stdout.write(findings.map((finding) => JSON.stringify(finding)).join("\n") + "\n");
  process.stderr.write(JSON.stringify({ level: "info-0", logger: "trufflehog", msg: "finished scanning",
    trufflehog_version: "3.97.4", chunks: staged.length,
    bytes: staged.reduce((total, row) => total + row.bytes.length, 0),
    verified_secrets: 0, unverified_secrets: findings.length }) + "\n");
  process.exitCode = 183;
}
function inertModel(config, args) {
  appendFileSync(config.sentinel, "invoked\n", { mode: 0o600 });
  const index = args.indexOf("--output-schema");
  check(args[0] === "exec" && index !== -1 && args[index + 1] === config.schema, "inert model schema arguments changed");
  sameIdentity(readFileSync(0), PROMPT, "inert model did not consume the complete prompt");
  sameIdentity(regular(config.schema), SCHEMA, "inert model schema changed");
}
async function runCase(config) {
  const artifacts = verifyArtifacts(config.host, config.manifest);
  const before = targetIdentity(config.target);
  const { runAgentProcess } = await import(pathToFileURL(join(config.host, "dist/agent-runner.js")));
  const { AgentInputScanError } = await import(pathToFileURL(join(config.host, "dist/agent-input-scan.js")));
  const notices = [];
  const originalError = console.error;
  let refusal;
  let result;
  try {
    console.error = (value) => {
      const notice = JSON.parse(String(value));
      check(notice.event === "agent_input_scan_classified" && notice.fixtureSha256 === RAW_HASH
        && notice.source === SOURCE && notice.detector === "URI", "unexpected classification notice");
      notices.push(notice);
    };
    result = runAgentProcess({ label: "synthetic-proxy-boundary", prompt: regular(config.prompt).toString("utf8"),
      scanSource: { kind: "committed", baseSha: BASE, headSha: HEAD }, model: "inert-proof",
      cwd: config.target, env: { ...process.env, CODEX_BIN: config.model }, timeoutMs: 180_000,
      codexExtraArgs: ["--output-schema", config.schema],
    });
  } catch (error) {
    if (!(error instanceof AgentInputScanError)) throw error;
    refusal = { reason: error.reason, diagnostic: error.scanDiagnostic };
  } finally {
    console.error = originalError;
  }
  const audit = JSON.parse(regular(config.scanAudit));
  const invocations = existsSync(config.sentinel) ? regular(config.sentinel).toString().split("\n").filter(Boolean).length : 0;
  check(!existsSync(audit.directory) && readdirSync(config.temporary).length === 0, "production temporary input or worker state leaked");
  check(JSON.stringify(before) === JSON.stringify(targetIdentity(config.target)), "target changed during proof");
  check(JSON.stringify(artifacts) === JSON.stringify(verifyArtifacts(config.host, config.manifest)), "artifact changed during proof");
  if (config.altered) {
    check(refusal?.reason === "findings" && refusal.diagnostic?.reason === "literal_not_reviewed"
      && notices.length === 0 && invocations === 0, "altered finding crossed the model boundary");
  } else {
    check(!refusal && result?.status === 0 && !result.error && !result.signal
      && invocations === 1 && notices.length === 1, "exact candidate did not reach only the inert model");
    check(notices[0].findings.length === 2 && notices[0].findings.every((finding, index) =>
      finding.blob === BLOBS[index] && finding.role === ["base", "head"][index]
      && finding.decoder === "PLAIN" && finding.occurrences === 1
      && finding.scannerLine === before.endpoints[index].lines[0]
      && finding.literalLine === before.endpoints[index].lines[0]), "endpoint classification attribution changed");
  }
  return { case: config.altered ? "one-byte-altered-raw" : "exact-reviewed-raw", result: refusal ? "refused" : "admitted",
    notices, ...(refusal ? { refusal } : {}), sentinelInvocations: invocations,
    material: audit.material, syntheticFindingHashes: audit.findings,
    scannerInputRemoved: true, workerTemporaryStateRemoved: true, targetUnchanged: true };
}
function wrapper(mode, config) {
  return `#!${process.execPath}\nconst {spawnSync}=require('node:child_process');\nconst result=spawnSync(${JSON.stringify(process.execPath)},[${JSON.stringify(SELF)},${JSON.stringify(mode)},${JSON.stringify(config)},...process.argv.slice(2)],{stdio:'inherit',env:process.env});\nprocess.exit(result.error||result.signal?97:result.status??97);\n`;
}
async function main(args) {
  const [hostArg, targetArg, promptArg, schemaArg, manifestArg, outputArg, ...extra] = args;
  check(Boolean(outputArg) && extra.length === 0, "pass candidate artifact root, target checkout, prompt, schema, artifact manifest and output JSON");
  const [host, target, prompt, schema, manifest, output] = [hostArg, targetArg, promptArg, schemaArg, manifestArg, outputArg].map((path) => resolve(path));
  check(!existsSync(output), "proof output already exists");
  sameIdentity(regular(prompt), PROMPT, "proof prompt identity changed");
  sameIdentity(regular(schema), SCHEMA, "proof schema identity changed");
  const artifacts = verifyArtifacts(host, manifest);
  const source = targetIdentity(target);
  const scratch = mkdtempSync(join(realpathSync(tmpdir()), "clawsweeper-proxy-boundary-"));
  const cases = [];
  try {
    for (const altered of [false, true]) {
      const root = join(scratch, altered ? "altered" : "exact");
      const bin = join(root, "bin");
      const temporary = join(root, "tmp");
      const home = join(root, "home");
      for (const directory of [root, bin, temporary, home]) mkdirSync(directory, { mode: 0o700 });
      const configFile = join(root, "case.json");
      const config = { altered, host, target, prompt, schema, manifest, temporary,
        scanAudit: join(root, "scan-audit.json"), sentinel: join(root, "sentinel"), model: join(bin, "codex") };
      writeFileSync(configFile, JSON.stringify(config), { mode: 0o600, flag: "wx" });
      writeFileSync(join(bin, "trufflehog"), wrapper("--synthetic-scanner", configFile), { mode: 0o755, flag: "wx" });
      writeFileSync(config.model, wrapper("--inert-model", configFile), { mode: 0o755, flag: "wx" });
      const child = spawnSync(process.execPath, [SELF, "--case", configFile], {
        cwd: scratch, encoding: "utf8", timeout: 200_000, maxBuffer: 4 * 1024 * 1024,
        env: { PATH: `${bin}${delimiter}${process.env.PATH ?? ""}`, HOME: home, TMPDIR: temporary, TMP: temporary, TEMP: temporary },
      });
      if (child.error || child.status !== 0 || child.stderr !== "") {
        let reason = "synthetic case process failed; no receipt admitted";
        try {
          const failure = JSON.parse(child.stderr);
          if (failure.result === "failed" && typeof failure.reason === "string") reason = failure.reason;
        } catch {}
        throw new ProofFailure(reason);
      }
      cases.push(JSON.parse(child.stdout));
    }
    check(JSON.stringify(cases[0].material) === JSON.stringify(cases[1].material), "case input staging differed");
    check(JSON.stringify(source) === JSON.stringify(targetIdentity(target)), "target changed between cases");
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
  check(!existsSync(scratch), "proof scratch cleanup failed");
  const receipt = { kind: "explicitly-synthetic-production-boundary", runner: identity(regular(SELF)),
    runtime: { node: process.version, platform: process.platform, arch: process.arch }, artifacts, source,
    prompt: PROMPT, schema: SCHEMA, rawSha256: RAW_HASH, orderedLineSha256: LINES,
    limits: "Synthetic scanner output and inert CODEX_BIN only. Native detector discovery and verification, model/provider execution, and historical hosted recovery are not exercised. Existing native compatibility receipts remain separate.",
    cases, proofScratchRemoved: true };
  writeFileSync(output, JSON.stringify(receipt, null, 2) + "\n", { mode: 0o600, flag: "wx" });
  process.stdout.write(JSON.stringify({ result: "proved", cases: cases.map(({ case: name, result, sentinelInvocations }) => ({ name, result, sentinelInvocations })), receipt: identity(regular(output)) }) + "\n");
}

try {
  const [mode, configFile, ...args] = process.argv.slice(2);
  if (["--synthetic-scanner", "--inert-model", "--case"].includes(mode)) {
    const config = JSON.parse(regular(configFile));
    if (mode === "--synthetic-scanner") syntheticScanner(config, args);
    else if (mode === "--inert-model") inertModel(config, args);
    else process.stdout.write(JSON.stringify(await runCase(config)) + "\n");
  } else await main(process.argv.slice(2));
} catch (error) {
  process.stderr.write(JSON.stringify({ result: "failed", reason: error instanceof ProofFailure ? error.message : "unexpected proof failure; no raw diagnostics emitted" }) + "\n");
  process.exitCode = 1;
}
