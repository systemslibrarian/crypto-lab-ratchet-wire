# Ratchet Wire - Double Ratchet Algorithm Interactive Demo

**[Live Demo →](https://systemslibrarian.github.io/crypto-lab-ratchet-wire/)**

An interactive browser-based visualization of the **Double Ratchet Algorithm**, the cryptographic protocol that powers **Signal, WhatsApp, and Google Messages**.

## What You'll Learn

Ratchet Wire demonstrates:

- **Forward Secrecy**: Old messages remain secure even if current keys are compromised
- **Break-in Recovery**: New messages become secure as soon as fresh keys are used
- **Key Ratcheting**: How ephemeral keys derive ever-changing encryption keys
- **Out-of-Order Delivery**: Handling messages that arrive in unexpected order

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

Output is in `dist/`. The app runs entirely offline with no external dependencies at runtime.

## How It Works

### Two Ratchets, One Algorithm

The Double Ratchet combines:

1. **Symmetric-Key Ratchet** (KDF Chain)
   - Derives unique message keys from a chain key using HKDF
   - Provides forward secrecy: each message key is independent
   - Message keys are deleted immediately after use

2. **DH Ratchet** (Key Agreement Chain)
   - Uses X25519 ephemeral key pairs
   - Derives a new root key when the sender's key changes
   - Provides break-in recovery: a compromised root key cannot produce future keys

### What this demo implements

- ✓ Full Double Ratchet encryption/decryption
- ✓ X25519 key exchange (with low-order public-key rejection)
- ✓ HKDF key derivation
- ✓ AES-256-GCM message encryption with the header bound as associated data
- ✓ Out-of-order message handling with a bounded skipped-key store
- ✓ **Authenticated X3DH**: Ed25519-signed pre-keys (verified before use) plus a
  one-time pre-key for the fourth DH

### Simplified vs. Production

**Faithful to the spec here:**
- Signed pre-key signature verification — a tampered/substituted pre-key is
  rejected (see the *"Simulate a tampered pre-key"* button in the app)
- One-time pre-key contributing the 4th DH (`SK = HKDF(DH1‖DH2‖DH3‖DH4)`)
- Out-of-order delivery, skipped-key bounds, and AEAD-bound headers

**Production (Signal, WhatsApp) additionally has:**
- A single identity key for both DH and signing via **XEdDSA** (Web Crypto has
  no XEdDSA, so this demo uses a separate Ed25519 signing key + X25519 DH key)
- A pre-key server, periodic prekey rotation, and OPK-exhaustion handling
- Persistent state management

## Cryptographic Primitives

| Operation | Implementation | Standard |
|-----------|----------------|----------|
| Key Exchange | X25519 via Web Crypto | RFC 7748 |
| Key Derivation | HKDF-SHA256 via Web Crypto | RFC 5869 |
| Message Encryption | AES-256-GCM via Web Crypto | NIST |
| Identity Signatures | Ed25519 via Web Crypto | RFC 8032 |
| Session Init | Authenticated X3DH | Signal X3DH Spec |

## Architecture

```
src/
├── crypto/
│   ├── x25519.ts              # X25519 key agreement (+ low-order rejection)
│   ├── ed25519.ts             # Ed25519 signatures (handshake authentication)
│   ├── hkdf.ts                # HKDF key derivation + KDF_RK
│   ├── symmetric-ratchet.ts   # Message key derivation
│   ├── dh-ratchet.ts          # Root key derivation
│   ├── double-ratchet.ts      # Full encryption/decryption
│   └── session-init.ts        # Authenticated X3DH setup
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
- Ed25519 signatures authenticate the handshake; tampered/substituted pre-keys
  and wrong-identity signatures are rejected
- Symmetric ratchet produces unique, non-recoverable keys
- Full end-to-end encryption with out-of-order delivery
- A forged message cannot corrupt receiver state; oversized/malformed headers
  are rejected before any key derivation
- Authenticated X3DH produces matching session keys

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

MIT

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
