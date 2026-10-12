# crypto-lab-ratchet-wire

## What It Is

Ratchet Wire is a browser-based demonstration of the classical Double Ratchet with selectable simplified X3DH or real ML-KEM-1024 hybrid session setup. It uses X25519 for key agreement, HKDF-SHA256 for key derivation, and AES-256-GCM for encryption. It shows how two parties keep deriving fresh keys while exchanging messages over an untrusted channel. The algorithm solves the problem of end-to-end message confidentiality with forward secrecy and break-in recovery after a state compromise. Its security model is hybrid: asymmetric key agreement establishes and refreshes shared secrets, while symmetric ratchets derive per-message encryption keys.

## When to Use It

- Use it for asynchronous end-to-end messaging systems where each message needs its own fresh encryption key, because the Double Ratchet Algorithm is designed to preserve confidentiality across long conversations.
- Use it when you need forward secrecy and break-in recovery in a chat protocol, because compromised current state should not expose old traffic and should stop helping an attacker after a ratchet step.
- Use it for educational or prototype work that needs to illustrate X25519, HKDF-SHA256, AES-256-GCM, and Simplified X3DH together, because this demo exposes those pieces directly in the UI and source.
- Do NOT use this demo as a production messenger, because the Simplified X3DH implementation models the identity as separate Ed25519 and X25519 keys instead of Signal's XEdDSA, omits the pre-key server and pre-key rotation, and has no persistent state management.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-ratchet-wire](https://systemslibrarian.github.io/crypto-lab-ratchet-wire/)**

The demo lets you switch between Conversation, Session Handshake, Out of Order, Ratchet State, Forward Secrecy, Break-In Recovery, How It Works, and Test Yourself tabs while sending messages as Alice or Bob and watching the live root-key and chain-key state update. The Key State panel includes a convergence check proving both parties independently derived identical chain keys, and the live message-key timeline marks every DH ratchet with the root key it replaced. A guided tour and a reactive coach narrate each cryptographic event, and the Test Yourself tab closes the loop with an instant-feedback quiz. The setup controls switch between classical and hybrid sessions and select a one-time or last-resort KEM prekey. Starting a selected setup resets the conversation and exercises. The Session Handshake tab exposes the real DH/KEM derivation and an altered-ciphertext rejection experiment.

## What Can Go Wrong

- **Unauthenticated identity keys.** The handshake here does verify Bob's signed pre-key against his Ed25519 identity key and aborts if that signature fails, but the identity key itself arrives in-band; without pinning or comparing it out-of-band, an active attacker who substitutes the whole bundle can still mount a man-in-the-middle on the initial session setup.
- **Skipped-message key growth.** Out-of-order or dropped messages force the receiver to store skipped message keys; without a cap, an attacker can flood gaps and exhaust memory (a denial-of-service vector).
- **AES-256-GCM nonce reuse.** If a per-message key and nonce pair ever repeats, GCM's confidentiality and tag-forgery resistance collapse, so each message key must be used exactly once.
- **No post-compromise recovery without a DH step.** Forward secrecy protects past messages, but healing after a state compromise only happens once a fresh DH ratchet step runs; until then a stolen chain key keeps decrypting new messages.
- **Weak randomness defeats the ratchet.** The whole construction depends on unpredictable X25519 key pairs; a broken RNG makes ratcheting cosmetic and exposes keys regardless of the math.

## Real-World Usage

- **Signal** — X3DH and the classical Double Ratchet are historical foundations of the Signal Protocol and the constructions this lab teaches. Signal added PQXDH for session establishment, then announced [SPQR and the Triple Ratchet](https://signal.org/blog/spqr/) on 2 October 2025, combining a continuing post-quantum ratchet with the Double Ratchet. See the [current ratchet specification](https://signal.org/docs/specifications/doubleratchet/) and [PQXDH Wire](https://systemslibrarian.github.io/crypto-lab-pqxdh-wire/) for that distinction. This lab now implements a **PQXDH-style hybrid handshake** composed with its classical Double Ratchet: real ML-KEM-1024 encapsulation/decapsulation, signed curve and KEM prekeys, an initial authenticated ciphertext, and identity-associated data on subsequent messages. Separate Ed25519/X25519 identities, lab-specific encodings and labels, and the standardized ML-KEM wire format make it **non-interoperable with Signal clients**. It does not implement SPQR, ML-KEM Braid or the Triple Ratchet, so its recovery exercise demonstrates classical DH recovery rather than quantum post-compromise healing.
- **WhatsApp** — uses the Signal Protocol for end-to-end encrypted messages and calls across billions of users.
- **Google Messages (RCS)** and **Facebook Messenger / Messenger secret conversations** — adopt the Signal Protocol's Double Ratchet for their end-to-end encryption.
- **Matrix (Olm/Megolm)** — uses a Double Ratchet-derived construction for encrypted Matrix conversations.

## Hybrid setup and its limits

At the top of the demo, select **Hybrid PQXDH-style (ML-KEM-1024)** and press **Start selected setup**. The live conversation, out-of-order exercise, forward-secrecy exercise and recovery exercise use that setup. Classical mode remains available for comparison.

- Alice verifies both signed prekeys before encapsulating. A supplied, valid identity key is not an authenticated person: pin or compare its fingerprint through a trusted channel. The banner makes this distinction explicit.
- The new hybrid KDF uses `F || DH1 || DH2 || DH3 || DH4 || SS`, where `F` is 32 bytes of `0xFF`, zero SHA-256 salt and `RatchetWire-v1_CURVE25519_SHA-256_ML-KEM-1024` as the parameter-specific info string. The legacy classical KDF and its pinned vectors are preserved.
- Bob independently decapsulates, derives SK and authenticates the initial AES-GCM confirmation before accepting. ML-KEM implicit rejection is confirmed by AEAD; a changed KEM ciphertext cannot silently establish a usable session.
- Identity-associated data binds the two DH identities, Bob’s separate signing identity and the KEM key. It is preserved through DH steps and bound with each message header, including skipped-message delivery.
- Accepted one-time curve/KEM private prekeys are marked consumed and best-effort overwritten. Failed setups retain them for an authentic retry. JavaScript and Web Crypto may retain copies; this is not a secure-erasure guarantee.
- Last-resort KEM prekeys are reusable and require rotation. Each UI reset generates fresh keys; there is no persistent prekey server or pool. The crypto API also tests the optional-curve-OPK branch. A last-resort setup without any one-time prekey needs replay handling, which this lab does not provide as a server protocol.

The KEM is [ML-KEM-1024 from FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), not an older Kyber-compatible wire implementation. Authentication remains classical. PQ setup does not heal a later stolen session state against a quantum adversary. Continuing post-quantum recovery requires a construction such as SPQR/Triple Ratchet; the visible **How It Works → How this compares with current Signal** section links the primary specifications and explains that missing layer.

The tests additionally check ML-KEM-1024 encapsulation and implicit-rejection decapsulation against independently published [NIST ACVP cases 51 and 96](https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-KEM-encapDecap-FIPS203/internalProjection.json), with the source commit, Git blob and corpus SHA-256 pinned in the fixture. These checks are not NIST validation or a Signal interoperability certification.

Sources: [PQXDH revision 3, updated 23 January 2024](https://signal.org/docs/specifications/pqxdh/), §§2–4; [Double Ratchet revision 4, 4 November 2025](https://signal.org/docs/specifications/doubleratchet/), §§5–7; [Signal’s SPQR announcement, 2 October 2025](https://signal.org/blog/spqr/). Reviewed 12 October 2026.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-ratchet-wire
cd crypto-lab-ratchet-wire/ratchet-wire
npm install
npm run dev
```

## Related Demos
- [crypto-lab-pqxdh-wire](https://systemslibrarian.github.io/crypto-lab-pqxdh-wire/) — isolate hybrid handshake steps, ciphertext tampering and classical versus quantum attack models.
- [crypto-lab-x3dh-wire](https://systemslibrarian.github.io/crypto-lab-x3dh-wire/) — the full X3DH initial key agreement that seeds a Double Ratchet session.
- [crypto-lab-mls-group](https://systemslibrarian.github.io/crypto-lab-mls-group/) — TreeKEM group messaging with forward secrecy, the multi-party counterpart to the two-party ratchet.
- [crypto-lab-noise-pipe](https://systemslibrarian.github.io/crypto-lab-noise-pipe/) — Noise handshake patterns over X25519 and HKDF, a related session-setup framework.
- [crypto-lab-key-exchange](https://systemslibrarian.github.io/crypto-lab-key-exchange/) — Diffie-Hellman, ECDH, and X25519 fundamentals underlying the DH ratchet.
- [crypto-lab-ssh-handshake](https://systemslibrarian.github.io/crypto-lab-ssh-handshake/) — X25519 + Ed25519 session establishment in a different transport protocol.

---

*Part of the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
