# crypto-lab-ratchet-wire

## 1. What It Is

Ratchet Wire is a browser-based demonstration of the Double Ratchet Algorithm with Simplified X3DH session setup, using X25519 for key agreement, HKDF-SHA256 for key derivation, and AES-256-GCM for message encryption. It shows how two parties keep deriving fresh keys while exchanging messages over an untrusted channel. The algorithm solves the problem of end-to-end message confidentiality with forward secrecy and break-in recovery after a state compromise. Its security model is hybrid: asymmetric key agreement establishes and refreshes shared secrets, while symmetric ratchets derive per-message encryption keys.

## 2. When to Use It

- Use it for asynchronous end-to-end messaging systems where each message needs its own fresh encryption key, because the Double Ratchet Algorithm is designed to preserve confidentiality across long conversations.
- Use it when you need forward secrecy and break-in recovery in a chat protocol, because compromised current state should not expose old traffic and should stop helping an attacker after a ratchet step.
- Use it for educational or prototype work that needs to illustrate X25519, HKDF-SHA256, AES-256-GCM, and Simplified X3DH together, because this demo exposes those pieces directly in the UI and source.
- Do not use this demo as a production messenger, because the Simplified X3DH implementation explicitly omits signatures, one-time pre-keys, and persistent state management.

## 3. Live Demo

Live demo: https://systemslibrarian.github.io/crypto-lab-ratchet-wire/

The demo lets you switch between Conversation, Ratchet State, Break-In Recovery, and How It Works tabs while sending messages as Alice or Bob and watching the live root-key and chain-key state update. It also includes the Compromise Bob's Keys, Alice Sends Message, and Bob Receives (DH Ratchet) controls so you can step through break-in recovery behavior. There are no key-size or iteration controls in this demo; the interactive controls are the sender selector, message input, tabs, and recovery buttons.

## 4. How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-ratchet-wire.git
cd crypto-lab-ratchet-wire/ratchet-wire
npm install
npm run dev
```

No environment variables are required.

## 5. Part of the Crypto-Lab Suite

This demo is one entry in the broader Crypto-Lab collection at https://systemslibrarian.github.io/crypto-lab/.

Whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31