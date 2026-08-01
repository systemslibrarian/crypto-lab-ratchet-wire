# crypto-lab-ratchet-wire

## What It Is

Ratchet Wire is a browser-based demonstration of the Double Ratchet Algorithm with Simplified X3DH session setup, using X25519 for key agreement, HKDF-SHA256 for key derivation, and AES-256-GCM for message encryption. It shows how two parties keep deriving fresh keys while exchanging messages over an untrusted channel. The algorithm solves the problem of end-to-end message confidentiality with forward secrecy and break-in recovery after a state compromise. Its security model is hybrid: asymmetric key agreement establishes and refreshes shared secrets, while symmetric ratchets derive per-message encryption keys.

## When to Use It

- Use it for asynchronous end-to-end messaging systems where each message needs its own fresh encryption key, because the Double Ratchet Algorithm is designed to preserve confidentiality across long conversations.
- Use it when you need forward secrecy and break-in recovery in a chat protocol, because compromised current state should not expose old traffic and should stop helping an attacker after a ratchet step.
- Use it for educational or prototype work that needs to illustrate X25519, HKDF-SHA256, AES-256-GCM, and Simplified X3DH together, because this demo exposes those pieces directly in the UI and source.
- Do NOT use this demo as a production messenger, because the Simplified X3DH implementation models the identity as separate Ed25519 and X25519 keys instead of Signal's XEdDSA, omits the pre-key server and pre-key rotation, and has no persistent state management.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-ratchet-wire](https://systemslibrarian.github.io/crypto-lab-ratchet-wire/)**

The demo lets you switch between Conversation, X3DH Handshake, Out of Order, Ratchet State, Forward Secrecy, Break-In Recovery, How It Works, and Test Yourself tabs while sending messages as Alice or Bob and watching the live root-key and chain-key state update. The Key State panel includes a convergence check proving both parties independently derived identical chain keys, and the live message-key timeline marks every DH ratchet with the root key it replaced. A guided tour and a reactive coach narrate each cryptographic event, and the Test Yourself tab closes the loop with an instant-feedback quiz. There are no key-size or iteration controls in this demo; the interactive controls are the sender selector, message input, tabs, and per-demo buttons.

## What Can Go Wrong

- **Unauthenticated identity keys.** The handshake here does verify Bob's signed pre-key against his Ed25519 identity key and aborts if that signature fails, but the identity key itself arrives in-band; without pinning or comparing it out-of-band, an active attacker who substitutes the whole bundle can still mount a man-in-the-middle on the initial session setup.
- **Skipped-message key growth.** Out-of-order or dropped messages force the receiver to store skipped message keys; without a cap, an attacker can flood gaps and exhaust memory (a denial-of-service vector).
- **AES-256-GCM nonce reuse.** If a per-message key and nonce pair ever repeats, GCM's confidentiality and tag-forgery resistance collapse, so each message key must be used exactly once.
- **No post-compromise recovery without a DH step.** Forward secrecy protects past messages, but healing after a state compromise only happens once a fresh DH ratchet step runs; until then a stolen chain key keeps decrypting new messages.
- **Weak randomness defeats the ratchet.** The whole construction depends on unpredictable X25519 key pairs; a broken RNG makes ratcheting cosmetic and exposes keys regardless of the math.

## Real-World Usage

- **Signal** — the Double Ratchet plus X3DH originated in and powers the Signal messenger's end-to-end encryption.
- **WhatsApp** — uses the Signal Protocol for end-to-end encrypted messages and calls across billions of users.
- **Google Messages (RCS)** and **Facebook Messenger / Messenger secret conversations** — adopt the Signal Protocol's Double Ratchet for their end-to-end encryption.
- **Matrix (Olm/Megolm)** — uses a Double Ratchet-derived construction for encrypted Matrix conversations.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-ratchet-wire
cd crypto-lab-ratchet-wire/ratchet-wire
npm install
npm run dev
```

## Related Demos
- [crypto-lab-x3dh-wire](https://systemslibrarian.github.io/crypto-lab-x3dh-wire/) — the full X3DH initial key agreement that seeds a Double Ratchet session.
- [crypto-lab-mls-group](https://systemslibrarian.github.io/crypto-lab-mls-group/) — TreeKEM group messaging with forward secrecy, the multi-party counterpart to the two-party ratchet.
- [crypto-lab-noise-pipe](https://systemslibrarian.github.io/crypto-lab-noise-pipe/) — Noise handshake patterns over X25519 and HKDF, a related session-setup framework.
- [crypto-lab-key-exchange](https://systemslibrarian.github.io/crypto-lab-key-exchange/) — Diffie-Hellman, ECDH, and X25519 fundamentals underlying the DH ratchet.
- [crypto-lab-ssh-handshake](https://systemslibrarian.github.io/crypto-lab-ssh-handshake/) — X25519 + Ed25519 session establishment in a different transport protocol.

---

*One of 170+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
