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

### Simplified vs. Production

**This demo implements:**
- ✓ Full Double Ratchet encryption/decryption
- ✓ X25519 key exchange
- ✓ HKDF key derivation
- ✓ AES-256-GCM message encryption
- ✓ Out-of-order message handling
- ✓ Simplified X3DH session initialization

**Production (Signal, WhatsApp) adds:**
- Cryptographic signatures on pre-keys
- One-time pre-keys (OPK) in X3DH
- Persistent state management
- Server-assisted registration

## Cryptographic Primitives

| Operation | Implementation | Standard |
|-----------|----------------|----------|
| Key Exchange | X25519 via Web Crypto | RFC 7748 |
| Key Derivation | HKDF-SHA256 via Web Crypto | RFC 5869 |
| Message Encryption | AES-256-GCM via Web Crypto | NIST |
| Session Init | Simplified X3DH | Signal X3DH Spec |

## Architecture

```
src/
├── crypto/
│   ├── x25519.ts              # X25519 key agreement
│   ├── hkdf.ts                # HKDF key derivation
│   ├── symmetric-ratchet.ts   # Message key derivation
│   ├── dh-ratchet.ts          # Root key derivation
│   ├── double-ratchet.ts      # Full encryption/decryption
│   └── session-init.ts        # X3DH simplified setup
├── __tests__/
│   ├── primitives.test.ts
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
- RFC 5869 HKDF test vectors pass
- X25519 key agreement produces matching shared secrets
- Symmetric ratchet produces unique, non-recoverable keys
- Full end-to-end encryption with out-of-order delivery
- X3DH produces matching session keys

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
