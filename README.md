# crypto-lab-ratchet-wire

A comprehensive cryptographic education lab with the **Double Ratchet Algorithm** interactive visualizer.

**[Live Demo →](https://systemslibrarian.github.io/crypto-lab-ratchet-wire/)**

## What's Included

### Ratchet Wire — Double Ratchet Algorithm Demo

An interactive browser-based visualization of the Double Ratchet Algorithm, the cryptographic protocol at the heart of **Signal, WhatsApp, and Google Messages**.

**Key Features:**
- Live conversation between Alice and Bob with real-time key state visualization
- Demonstrates forward secrecy (old messages protected despite key leaks)
- Demonstrates break-in recovery (fast key ratchetting after compromise)
- Interactive DH ratchet teeth visualization
- Key compromise simulation with recovery demonstration
- Educational explanations of symmetric vs. DH ratchets

**Located in:** `ratchet-wire/`

**Quick Start:**
```bash
cd ratchet-wire
npm install
npm run dev
# Open http://localhost:5173
```

**Technologies:**
- Vite + TypeScript
- Web Crypto API (X25519, HKDF, AES-256-GCM)
- Vanilla CSS dark theme

**Specifications:**
- [Signal Double Ratchet](https://signal.org/docs/specifications/doubleratchet/)
- [Signal X3DH](https://signal.org/docs/specifications/x3dh/)
- [RFC 5869 HKDF](https://tools.ietf.org/html/rfc5869)
- [RFC 7748 X25519](https://tools.ietf.org/html/rfc7748)

---

## Catalog Entry

| Aspect | Value |
|--------|-------|
| **Protocol** | Double Ratchet Algorithm |
| **DH Primitive** | X25519 (Curve25519) |
| **KDF** | HKDF-SHA256 |
| **Message Encryption** | AES-256-GCM |
| **Properties** | Forward secrecy + Break-in recovery |
| **Session Init** | Simplified X3DH |
| **Authors** | Trevor Perrin, Moxie Marlinspike |
| **Year** | 2016 (Double Ratchet), 2013 (OTR lineage) |
| **Used In** | Signal, WhatsApp, Google Messages, Telegram |
| **Demo** | ✓ Interactive visualization with live state |

---

## Architecture

```
crypto-lab-ratchet-wire/
├── README.md                          # This file
└── ratchet-wire/
    ├── src/
    │   ├── crypto/
    │   │   ├── x25519.ts             # X25519 key exchange (RFC 7748)
    │   │   ├── hkdf.ts               # HKDF-SHA256 (RFC 5869)
    │   │   ├── symmetric-ratchet.ts  # Message key derivation chain
    │   │   ├── dh-ratchet.ts         # Root key derivation chain
    │   │   ├── double-ratchet.ts     # Full encryption/decryption
    │   │   └── session-init.ts       # Simplified X3DH setup
    │   ├── __tests__/
    │   │   ├── primitives.test.ts
    │   │   ├── symmetric-ratchet.test.ts
    │   │   ├── dh-ratchet.test.ts
    │   │   ├── double-ratchet.test.ts
    │   │   └── session-init.test.ts
    │   ├── main.ts
    │   └── style.css
    ├── package.json
    ├── vite.config.ts
    ├── tsconfig.json
    └── README.md                     # Detailed demo documentation
```

---

## Testing

Run test suite to verify cryptographic implementations:

```bash
cd ratchet-wire
npm run test
```

Tests include:
- ✓ RFC 5869 HKDF test vectors
- ✓ X25519 shared secret matching
- ✓ Symmetric ratchet one-wayness
- ✓ Full end-to-end encryption (10-message conversation)
- ✓ Out-of-order message handling
- ✓ X3DH session key matching

---

## Cipher Agnosticism

The Double Ratchet Algorithm is cipher-agnostic. This implementation uses **AES-256-GCM** for message encryption, but could substitute:

- **Serpent-256** (see [iron-serpent](../iron-serpent) demo) — offers wider 256-bit block size
- **ChaCha20-Poly1305** — streamable and constant-time
- Any AEAD cipher with 32-byte keys

The ratcheting mechanism (symmetric + DH) remains unchanged.

---

## Key Insights Demonstrated

### Forward Secrecy
Every message key is derived fresh and deleted immediately. Even if a root key leaks, past messages remain secure because their keys are gone.

### Break-In Recovery
The DH ratchet uses fresh ephemeral keys on each direction change. An attacker with a compromised root key **cannot** derive the next root key without the private keys. Recovery happens automatically after one message.

### Domain Separation
Different HKDF labels ensure keys are not confused:
- `'ratchet-wire-message'` → Message keys (encryption)
- `'ratchet-wire-chain'` → Chain keys (derivation)
- `'ratchet-wire-root'` → Root keys (master)

### Memory Safety
Message keys are ephemeral — stored only in function scope and cleared after use. No "key history" to leak.

---

## What This Demo Teaches

1. **Cryptographic primitives in practice**
   - X25519 key agreement (not just "DH is secure")
   - HKDF as a building block (not just HMAC)
   - Domain-separated labels (not just "use random salt")

2. **Protocol design for security**
   - Ratcheting for forward secrecy (not just "delete old keys")
   - Dual ratchets (not just "symmetric is enough")
   - Recovery from compromise (not just "prevention")

3. **Real-world messaging security**
   - How Signal/WhatsApp actually work (simplified but accurate)
   - Why casual SSL is insufficient (no forward secrecy)
   - Why perfect forward secrecy is hard (but possible)

---

## References

**Academic:**
- [Signal Protocol Specifications](https://signal.org/docs/specifications/) — Clear, authoritative
- [RFC 5869: HKDF](https://tools.ietf.org/html/rfc5869) — 12-page standard
- [RFC 7748: X25519](https://tools.ietf.org/html/rfc7748) — Elliptic curve definitions

**Implementation:**
- [TweetNaCl.js](https://tweetnacl.js.org/) — Reference crypto library
- [libsodium](https://doc.libsodium.org/) — Production-grade primitives
- [Signal protocol libraries](https://github.com/signalapp) — Reference implementations

**History:**
- Off-the-Record Messaging (OTR) — Precursor, 2004
- TextSecure (now Signal) — First mainstream deployment, 2010
- Signal Protocol Whitepaper — Full specification, 2016

---

## Building & Deployment

```bash
# Development
cd ratchet-wire
npm install
npm run dev

# Production build
npm run build
# Output in ./dist/

# Serve production build
npm run preview
```

The application is a single-page app with no external CDN dependencies at runtime. All cryptography uses native Web Crypto API.

---

## License

MIT

---

*"The best encryption is the encryption everyone gets by default." — Moxie Marlinspike*