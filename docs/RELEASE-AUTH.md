# Release artifact authentication

`qnero-release` signs manifests with ML-DSA-87 and verifies them with a public
key the operator trusts separately. Each manifest authenticates a full source
revision, repository identity, relative file paths, byte lengths, SHA-512
digests and executable flags. Signatures cover the exact JSON bytes with the
context `QNERO_RELEASE_MANIFEST_V1`.

This is an artifact authentication tool. It does not establish that a build
reproduces its claimed source, that the signer reviewed it, or that the wallet
host will serve those same bytes. Qnero's proof-system qualification and other
transport boundaries remain as described in [CRYPTOGRAPHY.md](CRYPTOGRAPHY.md).
An official release signing root has to be provisioned and communicated by
the release owner before this mechanism can authenticate official releases.

## Trust and key handling

Build the verifier from a reviewed checkout using a trusted toolchain:

```bash
cargo build --locked --release -p qnero-release
```

The verifier executable, trusted public key file and expected revision are
inputs to the trust decision. Keep them separate from an untrusted artifact
download. A key, fingerprint or verifier supplied only with that download
cannot establish its own authenticity. For browser wallets, checking a bundle
before deployment protects that import; a page delivered by a compromised
host can still replace its own checks and steal a seed. Offline verification
and a trusted installation path are necessary for that threat.

Generate a dedicated release key on the signing machine. The directory in
this example must already exist on protected storage, outside the checkout:

```bash
target/release/qnero-release keygen \
  --private-key /protected/qnero.release-key \
  --public-key /protected/qnero-release.pub
```

The private file contains a 32-byte seed with a version header. Key creation
uses operating-system randomness, creates new files, and sets owner-only
permissions on Unix. Signing refuses a group- or world-accessible private key
on Unix; other systems require equivalent access controls from the operator.
Keep the seed offline, back it up securely, and keep it out of CI secrets,
build trees, command arguments and logs. The repository ignores
`*.release-key` as an additional precaution.

Communicate and confirm the public key's fingerprint through an independently
trusted channel. This command returns SHA-512 over the raw ML-DSA public key
bytes, excluding the file header, matching the fingerprint printed by keygen:

```bash
target/release/qnero-release fingerprint --public-key /trusted/qnero-release.pub
```

`public-key --private-key FILE --public-key NEW_FILE` recovers a public file
from a stored seed. Key rotation requires an explicit update of the trusted
key through the same independent process. The verifier never accepts a
replacement key from a manifest. It also requires an expected full lowercase
40-character commit, supplied from the operator's trusted release decision.
That pin rejects a valid signature for a different revision; it does not
maintain a global release counter or detect an operator selecting an old pin.

## Sign and verify a bundle

Build artifacts from a clean, reviewed source revision. After review, sign
selected files or entire directories beneath a bundle root. These commands
use placeholders for the exact reviewed commit and new output paths:

```bash
target/release/qnero-release sign \
  --root release-bundle \
  --private-key /protected/qnero.release-key \
  --revision <full-reviewed-commit> \
  --manifest release-bundle.release.json \
  --signature release-bundle.release.json.sig \
  bin wallet

target/release/qnero-release verify \
  --root release-bundle \
  --public-key /trusted/qnero-release.pub \
  --revision <full-reviewed-commit> \
  --manifest release-bundle.release.json \
  --signature release-bundle.release.json.sig \
  --require-path bin --require-path wallet \
  --output-dir verified-bundle
```

`--require-path` checks every existing file below each specified path is
covered by the signed manifest. Verification checks every listed artifact,
including ones outside those required paths. Callers select the required
paths themselves. A successful signature authenticates the signer's metadata
and bytes, including the claimed revision; proving their build provenance
requires a separate reproducibility or attestation process.

`--output-dir` must be new. The verifier hashes while copying into a private
temporary directory and publishes the directory only after all checks pass.
Consumers should use this snapshot so later changes to the download cannot
change the bytes they install. A failed check removes the temporary snapshot
and leaves an existing output alone. On Unix, signed executable flags become
0755 or 0644; setuid, setgid and other source mode bits are never copied.

Paths use portable ASCII letters, numbers, dots, underscores and hyphens in
relative slash-separated components. Parent traversal, symlinks, special
files, Windows reserved names and case-insensitive duplicate file paths are
refused. The parser limits manifests to 4 MiB and 4096 files; directory walks
are limited to 16384 entries. File contents are streamed. Verification works
offline. Local input, key and output directories must be controlled by the
operator; this tool does not isolate malicious processes running as that user.

## Prebuilt browser prover packages

The prebuilt staging path requires this authentication for both `pkg` and
`pkg-threaded`, including JavaScript glue and every worker snippet. On the
signing machine, after reviewing the built modules:

```bash
target/release/qnero-release sign \
  --root crates/qnero-prover-wasm/www \
  --private-key /protected/qnero.release-key \
  --revision <full-reviewed-commit> \
  --manifest crates/qnero-prover-wasm/www/wasm-prebuilt.release.json \
  --signature crates/qnero-prover-wasm/www/wasm-prebuilt.release.json.sig \
  pkg pkg-threaded
```

Copy both packages, the manifest and its signature to the staging machine.
Provision its trusted public key separately. Then, from the repository root:

```bash
QNERO_WASM_PREBUILT=1 \
QNERO_RELEASE_PUBLIC_KEY=/trusted/qnero-release.pub \
QNERO_RELEASE_REVISION=<full-reviewed-commit> \
  ./wallet-web/scripts/stage-wasm.sh --threaded
```

The default verifier is `target/release/qnero-release`; override its trusted
path with `QNERO_RELEASE_VERIFIER`. The default manifest is
`crates/qnero-prover-wasm/www/wasm-prebuilt.release.json` and its signature is
that path plus `.sig`. `QNERO_RELEASE_MANIFEST` and `QNERO_RELEASE_SIGNATURE`
override them. If `QNERO_RELEASE_REVISION` is absent, staging uses the local
checkout's `HEAD`; that checkout must itself be trusted.

Staging verifies the complete required trees, checks both export surfaces,
and copies from the authenticated snapshot. Missing keys, manifests,
signatures, mismatched revisions, omitted files or changed bytes stop staging
before `public/wasm/` is changed. Prebuilt packages require `--threaded` and
both modules. The previous unsigned SHA-256 manifest is no longer accepted
for this path. Local source builds without `QNERO_WASM_PREBUILT=1` continue
to use the locally built modules and their export checks.

The same environment variables pass through the `wallet` stage of
`scripts/deploy-testnet.sh`. Its SSH transport and the browser's HTTPS
transport remain independent boundaries; this gate does not change either.

## Validation

`cargo test --locked --release -p qnero-release` runs the artifact tests and,
on Unix, the real staging script against throwaway signed packages. It covers
key substitution, signature and manifest edits, domain separation, revision
pins, file coverage, glue and worker tampering, unsafe paths, snapshot cleanup,
key permissions and changes to original files after verification. The root
workspace CI runs these tests with the other Rust crates.
