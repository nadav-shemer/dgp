# DGP Web App — Pinned Interface Contract (AUTHORITATIVE)

**Date:** 2026-06-14
**Status:** Authoritative. This document is the single source of truth for every
cross-implementation shared format. Three implementation plans (crypto, server,
client) MUST conform to it byte-for-byte. A wrong constant silently breaks
cross-platform password compatibility — when this document and a prose summary
disagree, this document wins; when this document and live source
(`linux/dgp/*.py`) disagree, that is a **bug in this document** and must be fixed
here, not worked around in code.

**Authority note on argument naming.** Throughout `linux/dgp/`, the *positional*
parameter named `secret` (in `engine.generate(seed, name, entry_type, secret)` and
`engine.derive_aes_key(seed, name, secret)`) and the `account` argument elsewhere
are **the same value** — the per-identity account string. This is proven by the
call site `testvectors.py:117`:
`generate(tv.seed, tv.name, tv.type, tv.account)`. In this contract the identity
account string is always called **`account`**. Do not be misled by the source's
`secret` parameter name; it is the account, not a service secret.

---

## 0. Canonical terms and the one derivation primitive

Three user-controlled strings drive everything:

| Term | Meaning |
|---|---|
| `seed` | The master secret. Never persisted, never leaves the client, lives only in a module-scoped in-memory variable while unlocked. |
| `account` | A per-identity discriminator (often `""` or `"default"`). Part of the KDF *password*, NOT the salt. |
| `service` / `name` | The per-entry service name (e.g. `"github"`). Used as the KDF *salt*. |

**The single derivation primitive** (`engine.pbkdf2_raw`, used by passwords, the
vault aes-key, and the SSH key path):

```
pbkdf2_raw(seed, account, name, iters=42000, dklen=40):
    password = UTF8(seed + account)          # string concatenation, then UTF-8
    salt     = UTF8(name)                     # the service/entry name
    return PBKDF2_HMAC_SHA1(password, salt, iterations=42000, dklen=40)
```

Exact, verbatim constants (from `engine.py`):

| Constant | Value |
|---|---|
| KDF | PBKDF2 with **HMAC-SHA1** |
| Iterations | **42000** |
| Output length (`dklen`) | **40 bytes** |
| Salt | `UTF8(service_name)` (raw UTF-8 bytes of the service name; may be empty) |
| Password | `UTF8(seed + account)` (string concat first, then encode) |

WebCrypto port (`derive.ts`):

```js
const raw = new Uint8Array(await crypto.subtle.deriveBits(
  { name: "PBKDF2", hash: "SHA-1", salt: utf8(service), iterations: 42000 },
  await crypto.subtle.importKey("raw", utf8(seed + account), "PBKDF2", false, ["deriveBits"]),
  40 * 8                                     // deriveBits takes BITS → 320
));
```

`deriveBits` length is in **bits** (`320`), not bytes. Salt and service may be the
empty byte string — `subtle` accepts a zero-length salt.

---

## 1. Derivation and per-type byte→string mapping

`generate(seed, account, service, type)` computes `raw = pbkdf2_raw(seed, account,
service)` (40 bytes) once, then maps per `type`. **All slicing is on the 40-byte
`raw`. Hex/aeskey slice raw bytes; base58/alnum/xkcd convert the WHOLE 40 bytes to
a big-integer first, then map.**

### 1a. The base58 alphabet (verbatim)

```
123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
```

58 chars, Bitcoin order (no `0`, `O`, `I`, `l`). Index this string directly.

### 1b. Big-endian integer + base58 encode (`_to_base58`)

```
_to_base58(data):
    n = int.from_bytes(data, "big")          # BIG-ENDIAN over all 40 bytes
    result = []
    while n > 0:
        n, r = divmod(n, 58)
        result.append(ALPHABET[r])
    return "".join(result)                    # LEAST-significant digit FIRST
```

CRITICAL subtleties the port MUST reproduce exactly:
- Big-endian byte→int conversion over the full 40-byte buffer.
- Digits are appended **least-significant first** and the list is **NOT
  reversed**. The resulting string is therefore little-endian base58, which is
  unconventional but is exactly what the engine produces. The test vectors gate
  this.
- No leading-`1` zero padding (standard base58check padding is NOT applied).
- If `n == 0` the result is the empty string.

### 1c. xkcd word mapping (`_to_xkcd`)

```
_to_xkcd(data, count, words):
    n = int.from_bytes(data, "big")          # same big-endian int as base58
    result = []
    while n > 0 and len(result) < count:
        n, mod = divmod(n, 2048)             # consume 11 bits per word, LSB first
        word = words[mod]
        result.append(word[0].upper() + word[1:])   # capitalize first letter only
    return "".join(result)                    # words concatenated, no separator
```

- `words` is the BIP-39 English list (§1g), indexed 0..2047 by `mod`.
- Capitalization: **first character upper, rest unchanged** (`word[0].upper() +
  word[1:]`). BIP-39 words are already lowercase ASCII so this is plain
  TitleCase per word.
- Words are concatenated with **no separator**.
- Word order follows the divmod loop: least-significant 11-bit group first.

### 1d. alnum validity loop (`_grab_alnum`)

```
_grab_alnum(data, length):
    raw = _to_base58(data)                     # the base58 string from §1b
    for i in range(len(raw) - length + 1):     # sliding window, left to right
        candidate = raw[i : i+length]
        if (any ASCII digit in candidate)
           and (any ASCII lowercase in candidate)
           and (any ASCII uppercase in candidate):
            return candidate
    return raw[:length]                         # fallback: first `length` chars
```

- The validity rule: the chosen `length`-char window must contain **at least one
  ASCII digit, at least one ASCII lowercase letter, and at least one ASCII
  uppercase letter**.
- Use ASCII-only class checks (Python uses `c.isascii() and c.isdigit()` etc.).
  Since the base58 alphabet is pure ASCII this is equivalent to checking against
  `[0-9]`, `[a-z]`, `[A-Z]`, but the port MUST restrict to ASCII to be safe.
- Sliding window walks left→right; first qualifying window wins.
- Fallback when no window qualifies: the first `length` characters of the base58
  string (which may violate the upper/lower/digit rule — that is acceptable and
  intended).

### 1e. The eight password types (exact slicing/lengths)

| type | mapping | result |
|---|---|---|
| `hex` | `raw[:4].hex()` | 8 hex chars (lowercase) |
| `hexlong` | `raw[:8].hex()` | 16 hex chars (lowercase) |
| `alnum` | `_grab_alnum(raw, 8)` | 8-char base58 window, upper+lower+digit |
| `alnumlong` | `_grab_alnum(raw, 12)` | 12-char base58 window, upper+lower+digit |
| `base58` | `_to_base58(raw)[:8]` | first 8 chars of the base58 string |
| `base58long` | `_to_base58(raw)[:12]` | first 12 chars of the base58 string |
| `xkcd` | `_to_xkcd(raw, 4, words)` | 4 TitleCase words concatenated |
| `xkcdlong` | `_to_xkcd(raw, 6, words)` | 6 TitleCase words concatenated |

Plus the non-password helper type used by the SSH path / aes-key debugging:
- `aeskey` → `raw[:32].hex()` (64 hex chars). Not a UI password type.
- Any other type string → the literal string `"unknown type"`.

`hex`/`hexlong`/`aeskey` use Python `bytes.hex()` = lowercase, no separators.

### 1f. AES key derivation used by the vault (`derive_aes_key`)

```
derive_aes_key(seed, name, account) = pbkdf2_raw(seed, account, name)[:32]
```

i.e. the **first 32 bytes** of the same 40-byte SHA-1 derivation, with
`salt = name` (the vault entry's name) and `password = seed + account`. This is
the AES-256 key for the vault (§2). 42000 iterations, SHA-1, exactly as §0.

### 1g. The BIP-39 wordlist (`english.txt`)

- **2048 words**, the canonical BIP-39 English list.
- SHA-256 of `linux/dgp/data/english.txt`:
  `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`.
- One word per line, **LF** line endings, file ends with a trailing newline,
  ASCII only, all lowercase.
- Index 0 = `abandon`, index 1 = `ability`, index 2047 = `zoo`.
- The TS port bundles `english.txt` **verbatim** as an asset and parses it the
  same way `wordlist.py` does: split on `"\n"`, strip, drop empties, assert
  length == 2048.

### 1h. Worked test-vector anchors (from `testvectors.py`, all 103 must pass)

The TS suite ports **all 103** `VECTORS` verbatim. A few anchors for sanity:

| seed | account | service | type | expected |
|---|---|---|---|---|
| `a` | `` | `aa` | `alnum` | `oxToKKV2` |
| `a` | `` | `aa` | `base58` | `zWNoxToK` |
| `a` | `` | `aa` | `alnumlong` | `zWNoxToKKV2j` |
| `passwordPASSWORDpassword` | `` | `saltSALT…salt` | `hex` | `21934584` |
| `passwordPASSWORDpassword` | `` | `saltSALT…salt` | `xkcd` | `OrdinaryReadyIcePower` |
| `pass` | `word` | `salt` | `xkcd` | `StemDialSureHen` |
| `pass` | `word` | `salt` | `alnum` | `HUgR5fny` |

For `pass`/`word`/`salt` the full 40-byte `raw` is
`842b8a866ef6f789533059698674d4588a794d7110031d4afa2a895e0f69f9b50502f6b3b40f46aa`
(useful as an intermediate-value test fixture for the port).

The literal long test inputs (port these exactly):
`_A64 = "A"*64`, `_A65 = "A"*65`, `_B64 = "B"*64`, `_B65 = "B"*65`,
`_P = "passwordPASSWORDpassword"`,
`_S = "saltSALTsaltSALTsaltSALTsaltSALTsalt"`.

---

## 2. Vault blob format

For a per-entry externally-assigned secret (e.g. a non-derivable password).

| Field | Value |
|---|---|
| Key | `derive_aes_key(seed, name, account)` = `pbkdf2_raw(seed, account, name)[:32]` (§1f) — **32 bytes**, PBKDF2-HMAC-SHA1, 42000 iters, salt=`name`, password=`seed+account` |
| Cipher | **AES-256-GCM**, no AAD (`null` additional data) |
| IV | **12 random bytes** (`os.urandom(12)` / `crypto.getRandomValues`) |
| Tag | 16 bytes, appended to ciphertext by the AEAD (both `cryptography` AESGCM and WebCrypto AES-GCM put the tag immediately after the ciphertext) |
| Output | `base64( iv(12) ‖ ciphertext ‖ tag(16) )`, standard base64 with padding, ASCII |
| Plaintext | the secret string, UTF-8 |

Decrypt: base64-decode, `iv = data[:12]`, `rest = data[12:]` (ciphertext+tag),
AES-256-GCM decrypt. On any failure return null / "unrecoverable" (do not throw to
the user).

Param order pitfall (from `vault.py`): `encrypt_vault(plaintext, seed, name,
account)` → `derive_aes_key(seed, name, account)` → `pbkdf2_raw(seed, account,
name)`. So **salt = entry name, password = seed + account**.

**Rename-invalidation behavior (REQUIRED).** The key is salted by the entry
**name**. Renaming an entry changes `name` → changes the salt → changes the key →
**the previously stored ciphertext is undecryptable**. The client MUST warn the
user before renaming a vault entry that has a stored `encryptedSecret`, and treat a
post-rename decrypt failure as the explicit "secret unrecoverable" state, not a
generic error.

---

## 3. Export blob format (PIN-encrypted; wire-compatible with Android/Linux)

Source of truth: `exportcrypto.py`. This format is a **hard cross-platform
invariant** — a blob produced by any of web/Android/Linux must decrypt on the
others.

| Field | Value (verbatim) |
|---|---|
| KDF | **PBKDF2-HMAC-SHA256** |
| Iterations | **600000** (`EXPORT_ITERATIONS = 600_000`) |
| dklen | **32 bytes** |
| Salt | the ASCII byte string **`dgp-export-v1`** (`EXPORT_SALT = b"dgp-export-v1"`, 13 bytes, no null terminator) |
| KDF password | `UTF8(pin)` — the PIN string, UTF-8 encoded |
| Cipher | **AES-256-GCM**, no AAD |
| IV | **12 random bytes** |
| Tag | 16 bytes appended to ciphertext by the AEAD |
| Output | `base64( iv(12) ‖ ciphertext ‖ tag(16) )`, standard base64 with padding, ASCII |
| Plaintext | the **services JSON array** (§4b serialization, the same `serializeServices` shape) UTF-8 encoded |

Exact byte layout of the decoded blob: `[ iv: 12 bytes ][ ct: len(plaintext)
bytes ][ tag: 16 bytes ]`. Total = `12 + len(plaintext) + 16`. (Verified: an empty
`[]` payload → 30 bytes decoded; a 5-byte plaintext → 33 bytes decoded.)

TS port:
```js
const key = await crypto.subtle.deriveBits(
  { name:"PBKDF2", hash:"SHA-256", salt: utf8("dgp-export-v1"), iterations: 600000 },
  await crypto.subtle.importKey("raw", utf8(pin), "PBKDF2", false, ["deriveBits"]), 256);
// import key as AES-GCM, encrypt with iv(12); WebCrypto returns ct‖tag.
// blob = base64(iv ‖ result)
```

Acceptance: a Python-CLI export imports in the web app and vice-versa (the
cross-language fixture in the test plan).

---

## 4. Config sync blob format + config JSON schema

### 4a. Config blob crypto (the new zero-knowledge sync format)

The config blob is encrypted under a **seed-derived** key (so the server stays
zero-knowledge; the seed never reaches the server).

| Field | Value (verbatim) |
|---|---|
| KDF | **PBKDF2-HMAC-SHA256** |
| Iterations | **600000** |
| dklen | **32 bytes** |
| Salt | the ASCII byte string **`dgp-config-v1`** (13 bytes, no null terminator) |
| KDF password | `UTF8(seed + account)` (string concat, then UTF-8) |
| Cipher | **AES-256-GCM**, no AAD |
| IV | **12 random bytes** |
| Tag | 16 bytes appended to ciphertext by the AEAD |
| Output | `base64( iv(12) ‖ ciphertext ‖ tag(16) )`, standard base64 with padding, ASCII |
| Plaintext | the **services JSON array** (§4b), UTF-8 encoded |

Note the password is `seed + account` (the identity), NOT the PIN — this is the
key difference from the export blob (§3), which is PIN-derived. Both use
PBKDF2-HMAC-SHA256 / 600000 / 32, AES-256-GCM, `base64(iv‖ct‖tag)`.

This blob is the opaque `blob` field carried by `GET`/`PUT /config` (§7). The
server stores and returns it verbatim and never decrypts it.

### 4b. Config / services JSON schema (verbatim from `service.py` `serialize_services`)

The plaintext (inside both the config blob and the export blob) is a **JSON
array** of service objects. Serialized with **no whitespace**
(`json.dumps(arr, separators=(",", ":"))`).

Each `DgpService` serializes to an object with these keys, **in this order**:

| JSON key | Type | Always present? | Default | Notes |
|---|---|---|---|---|
| `id` | string | **yes** | — | stable UUIDv4 (`str(uuid.uuid4())`); the merge key on `409` |
| `name` | string | **yes** | — | service/entry name (the KDF salt) |
| `type` | string | **yes** | `"alnum"` | one of the §1e type strings |
| `comment` | string | **yes** | `""` | always emitted, even when empty |
| `archived` | bool | **yes** | `false` | always emitted |
| `pinned` | bool | **yes** | `false` | always emitted |
| `tags` | string[] | **omit when empty** | `[]` | included ONLY if the list is non-empty |
| `encryptedSecret` | string | **omit when null** | `null` | included ONLY if a vault secret is set; **camelCase** key, snake_case `encrypted_secret` internally |

Omit-when-empty rules (REQUIRED, exact):
- `tags`: emitted only when the list is truthy/non-empty (`if s.tags:`).
- `encryptedSecret`: emitted only when not `None` (`if s.encrypted_secret is not
  None:`). A present-but-empty string `""` would still be emitted; the gate is
  `is not None`.

Field-name casing (REQUIRED): all keys are **lowercase** except
`encryptedSecret`, which is **camelCase** on the wire while being
`encrypted_secret` in Python. `tags` is a JSON array of strings.

Parse tolerance (from `parse_services`, the port should match): unknown/missing
optional fields fall back to defaults; `tags` coerced to `[]` if not a list;
`encryptedSecret` of `""`/falsey → `None`; the whole array rejected (→ `[]`) only
if it is not a list, contains a non-object, or an entry lacks string `id`/`name`.

Example serialized array (canonical, no spaces):
```json
[{"id":"7c…uuid","name":"github","type":"alnum","comment":"","archived":false,"pinned":false,"tags":["dev"],"encryptedSecret":"<base64 vault blob>"}]
```

### 4c. Flag fingerprint (NOT in the synced config)

Per `2026-06-09-pride-flag-identity-fingerprint-design.md`, the pride-flag
identity fingerprint is a **separate, domain-separated derivation** and the
vanity `flag_nonce` is **deliberately NOT part of** the config/export payload
(adding a field would break Linux import wire-compatibility). It is per-device
local state.

Fingerprint derivation (for `flag.ts`):
- `fpBytes = PBKDF2-HMAC-SHA1(password = UTF8(seed + account), salt =
  "dgp-flag-fp:v1", iterations = 42000, length = 32 bytes)`. Distinct salt
  domain-separates it from all password/aes-key output.
- `word = two BIP-39 words` indexed from `fpBytes` (independent of the nonce).
- `flagIndex = SHA-256(fpBytes ‖ nonceBytes)[0] mod 10` — fast hash, cheap to
  mine.
- Flag gallery (fixed order, 10): index 0 `trans` (`TRANS_INDEX = 0`, the vanity
  target), then `rainbow`, `bi`, `pan`, `lesbian`, `nonbinary`, `ace`,
  `genderfluid`, `agender`, `genderqueer`.
- Mining: loop `nonce = 0,1,2,…` recomputing `flagIndex` until it equals
  `TRANS_INDEX`; store the integer nonce locally (per device). Runs in a Web
  Worker. The nonce is non-secret.

---

## 5. Auth signature scheme — **Ed25519** (chosen)

**Decision: Ed25519.** Rationale: deterministic from a 32-byte scalar (the design
spec's `KDF(...) → 32 bytes` maps directly to an Ed25519 private seed with no
"clamp the scalar" wrinkle), natively verifiable by the Python `cryptography` lib
(`Ed25519PrivateKey.from_private_bytes` round-trips — verified), and supported by
modern WebCrypto (Ed25519 reached broad browser support). If a target browser
lacks WebCrypto Ed25519, the client uses one small audited Ed25519 lib (e.g.
`@noble/ed25519`) over the same raw 32-byte key — the wire bytes are identical
either way.

### 5a. Deterministic private-key derivation

```
authSeed = PBKDF2-HMAC-SHA256(
    password = UTF8(seed + account),
    salt     = "dgp-auth-v1",          # ASCII, 11 bytes
    iterations = 600000,
    dklen      = 32)                    # 32 raw bytes = the Ed25519 private seed
```

Same KDF family/iterations as config/export (PBKDF2-HMAC-SHA256 / 600000 / 32);
the **salt `dgp-auth-v1` is what domain-separates it** from config (`dgp-config-v1`)
and export (`dgp-export-v1`). The 32-byte output IS the Ed25519 private key seed —
no clamping, no extra hashing.

The Ed25519 **public key** = the 32-byte raw public key derived from that private
seed. Only the public key is ever sent to / stored on the server (registration and
new-device enrollment).

### 5b. WebCrypto import (the PKCS8/JWK wrapping wrinkle)

Path A — native WebCrypto Ed25519 (preferred). WebCrypto `importKey("raw", …)` is
NOT defined for Ed25519 private keys, so wrap the 32-byte raw seed in a **fixed
PKCS8 template** and import as `"pkcs8"`:

```
PKCS8 prefix (16 bytes, constant for Ed25519):
  30 2e 02 01 00 30 05 06 03 2b 65 70 04 22 04 20
then the 32 raw private-seed bytes.   # total 48 bytes
```

```js
const pkcs8 = concat(ED25519_PKCS8_PREFIX /*16 bytes above*/, rawSeed /*32*/);
const priv = await crypto.subtle.importKey("pkcs8", pkcs8,
               { name: "Ed25519" }, false, ["sign"]);
```

To export the public key for registration, import the matching SPKI or derive via
the audited lib; send the **raw 32-byte** public key (base64url, §5d).

Path B — `@noble/ed25519` fallback: `getPublicKey(rawSeed)` and `sign(message,
rawSeed)` operate directly on the raw 32 bytes; no PKCS8 wrapping needed. Wire
bytes (signature, public key) are identical to Path A.

### 5c. What is signed, and Python verification

- The server issues a random **nonce of 32 bytes** (`POST /auth/login/challenge`),
  returned base64url (§5d).
- The client signs the **raw nonce bytes** (the decoded 32 bytes, NOT the base64url
  text) with Ed25519 → a **64-byte signature**.
- The client sends `{ nonce, signature }` (both base64url) to `POST
  /auth/login/seed`.
- Server verification (Python `cryptography`):

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
pub = Ed25519PublicKey.from_public_bytes(raw_pubkey_32)   # stored at registration
pub.verify(signature_64, nonce_32)   # raises InvalidSignature on failure
```

The nonce is single-use and short-lived (server-side TTL, e.g. 60s); consumed on
successful login.

### 5d. base64url encodings (auth)

All auth byte values on the wire use **base64url WITHOUT padding** (RFC 4648
§5: `-`/`_`, no `=`):
- server nonce (32 bytes → 43 chars),
- Ed25519 signature (64 bytes → 86 chars),
- Ed25519 public key (32 bytes → 43 chars).

(Distinct from the blob formats in §2–§4, which use **standard base64 WITH
padding** to match the Python `base64.b64encode` source.)

---

## 6. TOTP (2FA possession factor)

Standard **RFC 6238** TOTP, interoperable with Google Authenticator / Aegis / etc.

| Param | Value |
|---|---|
| Algorithm | **HMAC-SHA1** |
| Digits | **6** |
| Period | **30 seconds** |
| T0 | 0 (Unix epoch) |
| Counter | `floor(unix_time / 30)`, 8-byte big-endian |
| Verification window | ±1 step (accept previous/current/next), server-side rate-limited |

Secret:
- Server generates a random secret of **20 bytes** (160 bits, matching SHA-1
  block expectations) at enrollment.
- Encoded for display/enrollment as **base32** (RFC 4648, uppercase `A–Z2–7`).
  Padding is conventionally stripped in the URI.

Enrollment URI (`otpauth://`):
```
otpauth://totp/DGP:{account_label}?secret={BASE32}&issuer=DGP&algorithm=SHA1&digits=6&period=30
```
- `{account_label}` = the account username (URL-encoded); the label path is
  `DGP:{account_label}`.
- `issuer=DGP` is repeated as a query param (some apps read the path prefix, some
  the param).
- The client renders this URI as a QR for scanning; the user confirms one code to
  prove possession before the server marks the secret `confirmed`.

---

## 7. HTTP API

JSON over HTTP. All request and response bodies are `application/json` unless
noted. Authenticated endpoints require:

```
Authorization: Bearer <token>
```

The bearer `<token>` is an opaque server-issued session/device token (returned by
the login endpoints). All byte values inside auth JSON are base64url-unpadded
(§5d); the config/export `blob` is standard-base64 (§3/§4a).

### 7.1 `POST /auth/register`
Gated/single-tenant account setup.
- Request: `{ "username": str, "passphrase": str, "authPubkey": <b64url 32B Ed25519 pubkey> }`
- Response `201`: `{ "accountId": str }`
- `409` if username already exists: `{ "error": "username_taken" }`
- `403` if registration is disabled: `{ "error": "registration_closed" }`

### 7.2 `POST /auth/login/challenge`
- Request: `{ "username": str }`
- Response `200`: `{ "nonce": <b64url 32B> }`  (single-use, short TTL)
- `404`: `{ "error": "unknown_account" }`

### 7.3 `POST /auth/login/seed`  (seed path — one step, collapses login+unlock)
- Request: `{ "username": str, "nonce": <b64url 32B>, "signature": <b64url 64B Ed25519 sig over the raw nonce> }`
- Response `200`: `{ "token": str, "deviceId": str }`
- `401` on bad/expired nonce or bad signature: `{ "error": "auth_failed" }`

### 7.4 `POST /auth/login/password`  (2FA path — passphrase + TOTP)
- Request: `{ "username": str, "passphrase": str, "totp": "123456" }`
- Response `200`: `{ "token": str, "deviceId": str }`
- `401` on wrong passphrase or wrong/expired TOTP: `{ "error": "auth_failed" }` (generic, rate-limited)

### 7.5 `POST /auth/totp/enroll`  (authenticated)
- Request: `{ "label": str }`
- Response `200`: `{ "totpId": str, "secret": <BASE32>, "otpauthUri": "otpauth://totp/DGP:…" }`

### 7.6 `POST /auth/totp/confirm`  (authenticated)
- Request: `{ "totpId": str, "code": "123456" }`
- Response `200`: `{ "confirmed": true }`
- `400` on wrong code: `{ "error": "bad_code" }`

### 7.7 `GET /devices`  (authenticated)
- Response `200`: `{ "devices": [ { "id": str, "label": str, "createdAt": <ISO8601 UTC>, "lastSeen": <ISO8601 UTC> } ] }`

### 7.8 `DELETE /devices/{id}`  (authenticated)
- Response `200`: `{ "revoked": true }`
- `404`: `{ "error": "not_found" }`

### 7.9 `GET /config`  (authenticated)
- Response `200`: `{ "version": int, "blob": <standard-base64 config blob §4a> }`
- For a never-written account: `{ "version": 0, "blob": null }`

### 7.10 `PUT /config`  (authenticated; optimistic concurrency)
- Request: `{ "expectedVersion": int, "blob": <standard-base64 config blob §4a> }`
- Response `200` (match — server stored it and bumped the counter):
  `{ "version": <expectedVersion + 1> }`
- **Response `409` (version conflict — the authoritative conflict body):**
  ```json
  { "currentVersion": <int>, "blob": <standard-base64 current server blob> }
  ```
  On `409` the client decrypts both sides, **merges the service lists by entry
  `id` (UUID)**, re-encrypts at `currentVersion`, and retries the `PUT` with
  `expectedVersion = currentVersion`.

### Status-code summary
`200` ok · `201` created (register) · `400` bad request (TOTP confirm) · `401`
auth failed (both login paths) · `403` registration closed · `404` unknown
account / device / config target · `409` username taken (register) **and** config
version conflict (with the `{currentVersion, blob}` body) · `5xx` server error.

---

## Appendix A — base64 variant cheat-sheet (do not mix these up)

| Context | Variant |
|---|---|
| Vault blob (§2), Export blob (§3), Config blob (§4a) | **standard base64, WITH `=` padding** (matches Python `base64.b64encode`) |
| Auth nonce / signature / public key (§5) | **base64url, NO padding** (`-`/`_`) |
| TOTP secret (§6) | **base32** (RFC 4648, uppercase) |

## Appendix B — KDF salt registry (domain separation)

| Salt | KDF | Iters | dklen | Use |
|---|---|---|---|---|
| `UTF8(service name)` | PBKDF2-HMAC-**SHA1** | 42000 | 40 | password derivation (§1) |
| `UTF8(entry name)` | PBKDF2-HMAC-**SHA1** | 42000 | 40 (→[:32]) | vault aes-key (§1f, §2) |
| `dgp-export-v1` | PBKDF2-HMAC-**SHA256** | 600000 | 32 | export blob (§3) |
| `dgp-config-v1` | PBKDF2-HMAC-**SHA256** | 600000 | 32 | config sync blob (§4a) |
| `dgp-auth-v1` | PBKDF2-HMAC-**SHA256** | 600000 | 32 | Ed25519 auth private seed (§5a) |
| `dgp-flag-fp:v1` | PBKDF2-HMAC-**SHA1** | 42000 | 32 | pride-flag fingerprint (§4c) |
