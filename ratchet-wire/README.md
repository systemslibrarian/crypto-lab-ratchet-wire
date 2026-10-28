# Ratchet Wire - Double Ratchet Algorithm Interactive Demo

**[Live Demo →](https://systemslibrarian.github.io/crypto-lab-ratchet-wire/)**

An interactive browser-based visualization of the **Double Ratchet Algorithm**, a foundation of the Signal Protocol, with selectable classical or real ML-KEM-1024 hybrid session setup.

> ⚠️ **Educational demo — not for production.** This project teaches how the Double
> Ratchet works. It is unaudited, keeps no persistent state, uses a simplified
> identity model (separate Ed25519 + X25519 keys instead of XEdDSA), and does not
> address the side-channels and operational concerns a real messenger must. For
> genuine end-to-end encryption use a vetted library such as
> [libsignal](https://github.com/signalapp/libsignal).

See the [root README’s hybrid setup guide and scope](../README.md#hybrid-setup-and-its-limits). The top-of-page controls select the setup; the new hybrid mode follows PQXDH’s composition structure but does not implement Signal’s SPQR, ML-KEM Braid or Triple Ratchet, and is not Signal-compatible.

## What You'll Learn

Ratchet Wire demonstrates:

- **Forward Secrecy**: Old messages remain secure even if current keys are compromised
- **Classical Break-in Recovery**: Fresh uncompromised DH steps can exclude a passive attacker holding an earlier state
- **Key Ratcheting**: How ephemeral keys derive ever-changing encryption keys
- **Out-of-Order Delivery**: Handling messages that arrive in unexpected order

### Interactive views

- **Conversation** — send messages between Alice and Bob; each message has a
  collapsible *wire format* inspector showing the header the ratchet actually
  sends (ratchet key, message number Ns, previous-chain-length PN, IV).
- **Session Handshake** — the live signed-pre-key check and the four Diffie-Hellman
  terms combining via HKDF into the session root key. Plus a one-click
  *"Alter a pre-key without re-signing"* check, alongside the separate warning
  that the supplied identity fingerprint still needs trusted verification.
- **Out of Order** — deliver a batch of messages in any order and watch Bob's
  skipped-key store fill and drain.
- **Forward Secrecy** — steal Alice's chain key at any point and see the one-way
  ratchet expose every *future* message key while leaving *past* ones
  unrecoverable.
- **Break-In Recovery** — compromise Bob's keys, then watch a DH ratchet lock the
  attacker out.

## Running Locally

```bash
# Install dependencies
npm install

# Start dev server
npm run dev

# Open http://localhost:5173 in your browser
```

## Building for Production

```bash
npm run build
```

Output is in `dist/`. Cryptographic operations run locally; the bundled code requires no cryptographic service or remote fonts.

TypeScript 7 defaults ambient `types` to an empty list. The project explicitly includes Node types because the included integration tests import `node:fs`, `node:url`, `node:path` and `node:crypto`; DOM types remain enabled for the browser application. `@types/node` 26.0.0 is declared directly at the version already resolved by the previous lockfile.

The build also runs `npm run test:compiler-config`: real compiler controls retain integration-test coverage, compile Node and DOM declarations together, reject the existing Node imports when ambient types are removed, and reject an implicit-any fixture in ordinary and forced-colour environments. Probe diagnostics use `--pretty false`, so ANSI styling cannot change their assertions. These are compile-only synthetic inputs; no application or cryptographic behavior is changed.

## How It Works

### Two Ratchets, One Algorithm

The Double Ratchet combines:

1. **Symmetric-Key Ratchet** (KDF Chain)
   - Derives unique message keys from a chain key using HKDF
   - Provides forward secrecy: each message key is independent
   - Message keys leave protocol state after use and their demo buffers are best-effort cleared

2. **DH Ratchet** (Key Agreement Chain)
   - Uses X25519 ephemeral key pairs
   - Derives a new root key when the sender's key changes
   - Provides break-in recovery after a fresh uncompromised DH step excludes a passive attacker

### What this demo implements

- ✓ Full Double Ratchet encryption/decryption
- ✓ X25519 key exchange (with low-order public-key rejection)
- ✓ HKDF key derivation
- ✓ AES-256-GCM message encryption with the header bound as associated data
- ✓ Out-of-order message handling with a bounded skipped-key store
- ✓ **Signed-prekey-checked X3DH**: Ed25519-signed pre-keys (verified before use)
  plus a one-time pre-key for the fourth DH; identity verification remains external

### Simplified vs. Production

**Implemented here:**
- Signed pre-key signature verification — changing a pre-key without a matching
  signature is rejected. A fully substituted valid bundle is accepted unless the
  displayed identity is pinned or compared through a trusted channel.
- One-time pre-key contributing the 4th DH (`SK = HKDF(DH1‖DH2‖DH3‖DH4)`)
- Out-of-order delivery, skipped-key bounds, and AEAD-bound headers

**Known deviation — the X3DH `F` prefix is omitted:**
[X3DH §2.2](https://signal.org/docs/specifications/x3dh/#cryptographic-notation)
defines `KDF(KM) = HKDF(F ‖ KM, …)` where `F` is **32 bytes of `0xFF`** for
X25519 (57 for X448), present for cryptographic domain separation with XEdDSA.
Classical mode hashes the bare `DH1‖DH2‖DH3‖DH4` with no `F` prefix. The classical `SK` it
derives therefore differs from a conformant implementation's over the same keys,
and **this demo is not interoperable with real X3DH or libsignal**. The omission
is disclosed in the app's *How It Works* tab and left in place deliberately —
correcting it would move every pinned test vector and every key the UI displays.

**Production (Signal, WhatsApp) additionally has:**
- A single identity key for both DH and signing via **XEdDSA** (Web Crypto has
  no XEdDSA, so this demo uses a separate Ed25519 signing key + X25519 DH key)
- A pre-key server, periodic prekey rotation, and OPK-exhaustion handling
- Persistent state management

## Cryptographic Primitives

| Operation | Implementation | Standard |
|-----------|----------------|----------|
| Key Exchange | X25519 via [@noble/curves](https://github.com/paulmillr/noble-curves) | RFC 7748 |
| Identity Signatures | Ed25519 via @noble/curves | RFC 8032 |
| Key Derivation | HKDF-SHA256 via Web Crypto | RFC 5869 |
| Message Encryption | AES-256-GCM via Web Crypto | NIST |
| Session Init | Simplified X3DH or PQXDH-style hybrid | Signal X3DH / PQXDH structure; lab encodings |
| Hybrid KEM | ML-KEM-1024 via pinned @noble/post-quantum 0.7.1 | FIPS 203 |

> **Why `@noble/curves` for the curves?** Browser Web Crypto only gained X25519
> (Chrome 133, 2025) and Ed25519 (Chrome 137, 2025) very recently, so relying on
> it makes the demo fail to load on common, slightly-older browsers. The audited,
> pure-JS `@noble/curves` runs identically everywhere — and identically in Node,
> so the test suite exercises the exact code path the browser does. HKDF-SHA256
> and AES-256-GCM stay on Web Crypto, which every browser has supported for years.

## Architecture

```
src/
├── crypto/
│   ├── x25519.ts              # X25519 key agreement (+ low-order rejection)
│   ├── ed25519.ts             # Ed25519 signed-prekey integrity checks
│   ├── hkdf.ts                # HKDF key derivation + KDF_RK
│   ├── symmetric-ratchet.ts   # Message key derivation
│   ├── dh-ratchet.ts          # Root key derivation
│   ├── double-ratchet.ts      # Full encryption/decryption
│   └── session-init.ts        # Signed-prekey X3DH setup
├── __tests__/
│   ├── primitives.test.ts
│   ├── ed25519.test.ts
│   ├── symmetric-ratchet.test.ts
│   ├── dh-ratchet.test.ts
│   ├── double-ratchet.test.ts
│   └── session-init.test.ts
├── main.ts                    # UI and main application logic
└── style.css                  # Dark theme CSS
```

## Running Tests

```bash
npm run test
```

Tests verify:
- RFC 5869 HKDF test vectors pass (Appendix A.1 and A.2)
- X25519 key agreement produces matching shared secrets; low-order keys rejected
- Ed25519 signatures reject a changed pre-key under the supplied signing identity;
  tests also prove that replacing the whole valid bundle requires external identity verification
- Symmetric ratchet produces unique, non-recoverable keys
- Full end-to-end encryption with out-of-order delivery
- A forged message cannot corrupt receiver state; oversized/malformed headers
  are rejected before any key derivation
- Classical and hybrid setup produce independently matching session keys
- Hybrid KDF matches an independent Node HKDF reference including F and parameters
- Altered KEM ciphertext, identities, nonce and initial AEAD fail without consuming prekeys
- Accepted one-time prekeys are consumed; last-resort keys remain reusable
- Hybrid sessions preserve identity-associated data across DH and skipped-message paths
- An entirely substituted valid bundle is accepted without external identity verification, demonstrating why valid signatures do not authenticate an unpinned identity

## Key Insights

### Why Forward Secrecy Matters

If an attacker compromises a root key on Monday, they can read:
- Messages from Monday onward (until next DH ratchet)
- Messages from that moment forward in the conversation

But they **cannot** read:
- Messages from before the compromise (message keys were deleted)
- The next key after a DH ratchet step (requires ephemeral private key)

### Why Break-In Recovery Matters

The DH ratchet ensures that:
- Even with a compromised root key, the attacker is locked out after each ratchet step
- Recovery is automatic — no manual key exchange needed
- The protocol recovers after **one message** in the new direction

### Domain Separation

Different cryptographic operations use different HKDF labels:
- `'ratchet-wire-message'` → Message keys
- `'ratchet-wire-chain'` → Chain keys
- `'ratchet-wire-root'` → Root keys

This ensures keys derived for one purpose cannot be used for another.

## Specifications Referenced

- [Signal Double Ratchet Specification](https://signal.org/docs/specifications/doubleratchet/)
- [Signal X3DH Specification](https://signal.org/docs/specifications/x3dh/)
- [RFC 5869: HKDF](https://tools.ietf.org/html/rfc5869)
- [RFC 7748: X25519](https://tools.ietf.org/html/rfc7748)
- [NIST AES](https://csrc.nist.gov/publications/detail/fips/197/final)

## Credits

**Algorithm Designers:**
- Trevor Perrin and Moxie Marlinspike, Signal Protocol, 2016
- Building on OTR (Off-the-Record Messaging)

**Implementation:**
- Typescript + Vite + Web Crypto API
- Dark theme inspired by GitHub's color scheme

## License

[MIT](../LICENSE) — free to learn from and reuse. Note the educational disclaimer
above: this is not audited or production-ready crypto.

## Further Reading

Want to understand the cryptography deeper?

1. Start with [RFC 5869 (HKDF)](https://tools.ietf.org/html/rfc5869) — only 12 pages
2. Read the [Signal Double Ratchet Spec](https://signal.org/docs/specifications/doubleratchet/) — clear and complete
3. Explore [OTR Protocol](https://otr.im/) — precursor to Double Ratchet
4. See [TweetNaCl.js](https://tweetnacl.js.org/) for alternative crypto library

## Questions?

The code is heavily commented. Each crypto module includes:
- Specification references (URLs)
- Purpose of every function
- Examples and domain separation notes

Read through `src/crypto/double-ratchet.ts` to trace a message from sender to receiver.
