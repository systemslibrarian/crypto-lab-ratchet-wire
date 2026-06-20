/**
 * Ratchet Wire — Main Application
 * Double Ratchet Algorithm visualization.
 */

import './style.css';
import { RatchetState } from './crypto/dh-ratchet';
import { encrypt, decrypt, Message, SkippedKeys } from './crypto/double-ratchet';
import { ratchetStep, ChainState } from './crypto/symmetric-ratchet';
import { generateKeyPair } from './crypto/x25519';
import { generateSigningKeyPair } from './crypto/ed25519';
import {
  createBobPrekeyBundle,
  initiateSessionX3DH,
  acceptSessionX3DH,
  createAliceRatchetState,
  createBobRatchetState,
  describeAliceX3DH,
  BobPreSessionKeys,
  BobPrekeyBundle,
  X3DHBreakdown,
} from './crypto/session-init';

interface ConversationMessage {
  sender: 'Alice' | 'Bob';
  text: string;
  /** Fingerprint of the chain key (CK[Ns]) that produced this message's key. */
  chainKeyFp: string;
  /** Sending-chain generation (sender's DH-ratchet count) when this was sent. */
  chainGen: number;
  /** The on-the-wire header/IV, surfaced in the per-message inspector. */
  wire: {
    /** Sender's current ratchet public key (header.dhPublicKey), shortened. */
    ratchetKey: string;
    /** Message number within the current sending chain (header.messageNumber, Ns). */
    messageNumber: number;
    /** Length of the previous sending chain (header.previousChainLength, PN). */
    previousChainLength: number;
    /** AES-GCM IV, shortened. */
    iv: string;
  };
}

/**
 * The message numbers currently held in a skipped-key store, sorted ascending.
 * Store keys have the form `${senderRatchetKeyB64}:${messageNumber}` and base64
 * never contains a colon, so the number is the suffix after the last colon.
 */
function skippedNumbers(skipped: SkippedKeys): number[] {
  return Array.from(skipped.keys())
    .map((k) => Number(k.slice(k.lastIndexOf(':') + 1)))
    .filter((n) => Number.isFinite(n))
    .sort((a, b) => a - b);
}

/**
 * Walk a symmetric (chain-key) ratchet forward `count` steps from `chainKey0`,
 * returning each step's message-key fingerprint. This is exactly the operation
 * an attacker performs after stealing a chain key — and it only ever runs
 * forward, which is what makes earlier keys unrecoverable.
 */
async function chainMessageKeyFps(chainKey0: ArrayBuffer, count: number): Promise<string[]> {
  let chain: ChainState = { chainKey: chainKey0, messageNumber: 0 };
  const fps: string[] = [];
  for (let i = 0; i < count; i++) {
    const { newState, messageKey } = await ratchetStep(chain);
    fps.push(hex(messageKey.key));
    chain = newState;
  }
  return fps;
}

/** Extract the teaching-relevant wire fields from an encrypted message. */
function wireInfo(message: Message): ConversationMessage['wire'] {
  return {
    ratchetKey: `${message.header.dhPublicKey.slice(0, 16)}…`,
    messageNumber: message.header.messageNumber,
    previousChainLength: message.header.previousChainLength,
    iv: `${message.iv.slice(0, 16)}…`,
  };
}

/** Authentication outcome of the X3DH handshake, for display. */
interface HandshakeInfo {
  /** True once Bob's signed pre-key signature has been verified. */
  verified: boolean;
  /** Short fingerprint of Bob's Ed25519 identity key. */
  bobIdentityFingerprint: string;
  /** Short fingerprint of Alice's identity key. */
  aliceIdentityFingerprint: string;
  /** The four-DH X3DH derivation, for the handshake breakdown tab. */
  breakdown: X3DHBreakdown;
}

/** A fully-initialized Double Ratchet session (initiator + responder). */
interface Session {
  alice: RatchetState;
  bob: RatchetState;
  aliceSkipped: SkippedKeys;
  bobSkipped: SkippedKeys;
  handshake: HandshakeInfo;
}

type ThemeMode = 'dark' | 'light';

const THEME_STORAGE_KEY = 'theme';

function getThemeMode(): ThemeMode {
  return document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
}

function syncThemeToggle(button: HTMLButtonElement) {
  const isDark = getThemeMode() === 'dark';
  button.textContent = isDark ? '🌙' : '☀️';
  button.setAttribute('aria-label', isDark ? 'Switch to light mode' : 'Switch to dark mode');
}

/** Generate a fresh set of Bob's secret pre-session keys. */
async function generateBobKeys(): Promise<BobPreSessionKeys> {
  return {
    identityKeyPair: await generateKeyPair(),
    identitySigningKeyPair: await generateSigningKeyPair(),
    signedPreKeyPair: await generateKeyPair(),
    oneTimePreKeyPair: await generateKeyPair(),
  };
}

/** Run the authenticated X3DH handshake and initialize both ratchets. */
async function buildSession(): Promise<Session> {
  const aliceIK = await generateKeyPair();
  const aliceEK = await generateKeyPair();
  const aliceRatchet = await generateKeyPair();

  const bobKeys = await generateBobKeys();
  const bobBundle = await createBobPrekeyBundle(bobKeys);

  // initiateSessionX3DH verifies Bob's signed pre-key signature and THROWS if
  // it does not check out, so reaching the next line means authentication held.
  const aliceSession = await initiateSessionX3DH(
    { identityKeyPair: aliceIK, ephemeralKeyPair: aliceEK },
    bobBundle
  );
  const bobSession = await acceptSessionX3DH(bobKeys, aliceIK.publicKey, aliceEK.publicKey);

  const handshake: HandshakeInfo = {
    verified: true,
    bobIdentityFingerprint: await fingerprint(bobBundle.identitySigningKey),
    aliceIdentityFingerprint: await fingerprint(aliceIK.publicKey),
    breakdown: await describeAliceX3DH(
      { identityKeyPair: aliceIK, ephemeralKeyPair: aliceEK },
      bobBundle
    ),
  };

  return {
    // Bob's signed pre-key doubles as his initial ratchet key (as in Signal).
    alice: await createAliceRatchetState(aliceSession, aliceRatchet, bobKeys.signedPreKeyPair.publicKey),
    bob: createBobRatchetState(bobSession, bobKeys.signedPreKeyPair),
    aliceSkipped: new Map(),
    bobSkipped: new Map(),
    handshake,
  };
}

function hex(buffer: ArrayBuffer, bytes = 8): string {
  return Array.from(new Uint8Array(buffer).slice(0, bytes))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
}

/** A short, human-comparable fingerprint of a public key (SHA-256, 8 bytes). */
async function fingerprint(publicKey: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new Uint8Array(publicKey));
  return Array.from(new Uint8Array(digest).slice(0, 8))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join(' ')
    .toUpperCase();
}

export class RatchetWireApp {
  // Main conversation session.
  private session!: Session;
  private conversation: ConversationMessage[] = [];

  // Dedicated session for the break-in recovery simulation (kept separate so it
  // is deterministic regardless of what the user did in the main conversation).
  private recovery: Session | null = null;
  private recoverySnapshotRoot: string | null = null;
  private recoveryPending: Message | null = null;

  // Out-of-order delivery demo (separate session for determinism).
  private ooo: {
    session: Session;
    pending: { index: number; message: Message; text: string; delivered: boolean }[];
  } | null = null;
  private oooLog = '';

  // Forward-secrecy attacker demo.
  private static readonly FS_COUNT = 6;
  private fs: { messageKeyFps: string[]; compromiseAt: number } | null = null;

  // UI elements.
  private messagesContainer!: HTMLDivElement;
  private messageInput!: HTMLInputElement;
  private tabButtons!: NodeListOf<HTMLButtonElement>;
  private tabContents!: NodeListOf<HTMLDivElement>;
  private themeToggleButton!: HTMLButtonElement;

  async init() {
    this.session = await buildSession();
    this.setupUI();
    this.updateStateDisplay();
  }

  private setupUI() {
    this.messagesContainer = document.getElementById('messages') as HTMLDivElement;
    this.messageInput = document.getElementById('message-input') as HTMLInputElement;
    this.tabButtons = document.querySelectorAll('.tab-btn') as NodeListOf<HTMLButtonElement>;
    this.tabContents = document.querySelectorAll('.tab-content') as NodeListOf<HTMLDivElement>;
    this.themeToggleButton = document.getElementById('theme-toggle') as HTMLButtonElement;

    if (!document.documentElement.getAttribute('data-theme')) {
      document.documentElement.setAttribute('data-theme', 'dark');
    }
    syncThemeToggle(this.themeToggleButton);
    this.themeToggleButton.addEventListener('click', () => {
      const nextTheme: ThemeMode = getThemeMode() === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', nextTheme);
      localStorage.setItem(THEME_STORAGE_KEY, nextTheme);
      syncThemeToggle(this.themeToggleButton);
    });

    const form = document.getElementById('message-form') as HTMLFormElement;
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      void this.sendMessage();
    });

    this.tabButtons.forEach((btn) => {
      btn.addEventListener('click', () => this.switchTab(btn.dataset.tab!));
    });

    // Arrow-key navigation within the tablist (WCAG tabs pattern).
    const tablist = document.querySelector('[role="tablist"]') as HTMLElement;
    tablist.addEventListener('keydown', (e) => {
      const tabs = Array.from(this.tabButtons);
      const current = tabs.findIndex((b) => b.getAttribute('aria-selected') === 'true');
      let next = -1;
      if (e.key === 'ArrowRight' || e.key === 'ArrowDown') next = (current + 1) % tabs.length;
      else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') next = (current - 1 + tabs.length) % tabs.length;
      else if (e.key === 'Home') next = 0;
      else if (e.key === 'End') next = tabs.length - 1;
      if (next >= 0) {
        e.preventDefault();
        this.switchTab(tabs[next].dataset.tab!);
        tabs[next].focus();
      }
    });

    document.getElementById('mitm-demo-btn')?.addEventListener('click', () => {
      void this.demoTamperedPrekey();
    });

    document.getElementById('ooo-generate')?.addEventListener('click', () => {
      void this.oooGenerate();
    });
    document.getElementById('ooo-reset')?.addEventListener('click', () => {
      this.ooo = null;
      this.oooLog = '';
      this.renderOoo();
    });

    document.getElementById('fs-run')?.addEventListener('click', () => {
      void this.runForwardSecrecy();
    });

    document.getElementById('compromise-btn')?.addEventListener('click', () => {
      void this.startCompromise();
    });
    document.getElementById('recovery-send-btn')?.addEventListener('click', () => {
      void this.recoveryAliceSends();
    });
    document.getElementById('recovery-complete-btn')?.addEventListener('click', () => {
      void this.recoveryBobReceives();
    });

    this.renderHandshake();
    this.renderX3DH();
    this.renderRatchetViz();
  }

  /** Populate the X3DH handshake-breakdown tab from this session's derivation. */
  private renderX3DH() {
    const container = document.getElementById('x3dh-breakdown');
    if (!container) return;
    const bd = this.session.handshake.breakdown;
    container.innerHTML = '';

    const step = (cls: string, text: string) => {
      const el = document.createElement('div');
      el.className = `x3dh-step ${cls}`;
      el.textContent = text;
      return el;
    };

    container.appendChild(
      step(
        bd.signatureVerified ? 'x3dh-ok' : 'x3dh-bad',
        bd.signatureVerified
          ? "① Verify Bob's signed pre-key signature (Ed25519) — ✓ authenticated"
          : "① Verify Bob's signed pre-key signature — ✗ FAILED (would abort)"
      )
    );

    const grid = document.createElement('div');
    grid.className = 'x3dh-terms';
    for (const t of bd.terms) {
      const card = document.createElement('div');
      card.className = 'x3dh-term';

      const formula = document.createElement('code');
      formula.className = 'x3dh-formula';
      formula.textContent = `${t.name} = ${t.formula}`;

      const value = document.createElement('span');
      value.className = 'x3dh-value';
      value.textContent = t.value;

      card.append(formula, value);
      grid.appendChild(card);
    }
    container.appendChild(grid);

    container.appendChild(step('x3dh-sk', `② SK = HKDF(DH1 ‖ DH2 ‖ DH3 ‖ DH4) = ${bd.rootKey}`));
  }

  /** Show the authenticated-handshake banner (fingerprint + verified state). */
  private renderHandshake() {
    const { handshake } = this.session;
    const badge = document.getElementById('handshake-badge');
    const detail = document.getElementById('handshake-detail');
    if (badge) badge.textContent = handshake.verified ? '🔒 Identity verified' : '⚠️ Unverified';
    if (detail) {
      detail.textContent =
        `Bob's signed pre-key was checked against his Ed25519 identity ` +
        `(fingerprint ${handshake.bobIdentityFingerprint}).`;
    }
  }

  /**
   * Demonstrate that the handshake is authenticated: tamper with Bob's signed
   * pre-key signature (as a man-in-the-middle would have to) and show that X3DH
   * refuses to proceed.
   */
  private async demoTamperedPrekey() {
    const result = document.getElementById('mitm-result') as HTMLParagraphElement | null;
    const show = (text: string, blocked: boolean) => {
      if (!result) return;
      result.textContent = text;
      result.hidden = false;
      result.classList.toggle('mitm-blocked', blocked);
      result.classList.toggle('mitm-failed', !blocked);
    };

    try {
      const aliceIK = await generateKeyPair();
      const aliceEK = await generateKeyPair();
      const bobKeys = await generateBobKeys();
      const bundle = await createBobPrekeyBundle(bobKeys);

      // A man-in-the-middle can swap Bob's pre-key but cannot forge his identity
      // signature over it — model the resulting invalid signature by flipping a
      // byte, then watch Alice's X3DH reject the bundle.
      const forgedSig = bundle.signedPreKeySignature.slice(0);
      new Uint8Array(forgedSig)[0] ^= 0xff;
      const tampered: BobPrekeyBundle = { ...bundle, signedPreKeySignature: forgedSig };

      await initiateSessionX3DH({ identityKeyPair: aliceIK, ephemeralKeyPair: aliceEK }, tampered);
      show('Unexpected: the tampered pre-key was accepted — this should never happen.', false);
    } catch (err) {
      show(`✓ Blocked: ${(err as Error).message}`, true);
      this.announce('Man-in-the-middle attempt blocked: the tampered pre-key signature was rejected.');
    }
  }

  // --- Main conversation -----------------------------------------------------

  private async sendMessage() {
    const text = this.messageInput.value.trim();
    if (!text) return;

    const sender = (document.querySelector('input[name="sender"]:checked') as HTMLInputElement)
      ?.value as 'alice' | 'bob';

    if (sender === 'bob' && !this.session.bob.sendingChain) {
      // Bob is the responder: he has no sending chain until he receives Alice's
      // first message and performs his first DH ratchet. Explain it visibly
      // (role="status" is also a polite live region for screen readers).
      this.showComposerHint(
        "Bob can't send yet — as the responder he has no sending chain until he receives Alice's first message. Send as Alice to start."
      );
      return;
    }

    try {
      if (sender === 'alice') {
        await this.deliver('Alice', text);
      } else {
        await this.deliver('Bob', text);
      }
    } catch (err) {
      this.showComposerHint(`Encryption error: ${(err as Error).message}`);
      return;
    }

    this.messageInput.value = '';
    this.clearComposerHint();
    this.updateStateDisplay();
  }

  /** Lazily create the composer hint element (visible + announced). */
  private composerHint(): HTMLParagraphElement {
    let hint = document.getElementById('composer-hint') as HTMLParagraphElement | null;
    if (!hint) {
      hint = document.createElement('p');
      hint.id = 'composer-hint';
      hint.className = 'composer-hint';
      hint.setAttribute('role', 'status');
      hint.hidden = true;
      document.getElementById('message-form')?.insertAdjacentElement('afterend', hint);
    }
    return hint;
  }

  private showComposerHint(text: string) {
    const hint = this.composerHint();
    hint.textContent = text;
    hint.hidden = false;
  }

  private clearComposerHint() {
    const hint = document.getElementById('composer-hint');
    if (hint) {
      hint.hidden = true;
      hint.textContent = '';
    }
  }

  /** Encrypt from `from`, deliver to the peer, and record the decrypted result. */
  private async deliver(from: 'Alice' | 'Bob', text: string) {
    const s = this.session;
    if (from === 'Alice') {
      const chainKeyFp = hex(s.alice.sendingChain!.chainKey);
      const chainGen = s.alice.dhRatchetCount;
      const { message, newState } = await encrypt(s.alice, text);
      s.alice = newState;
      const r = await decrypt(s.bob, message, s.bobSkipped);
      s.bob = r.newState;
      s.bobSkipped = r.skippedKeys;
      this.conversation.push({ sender: 'Alice', text: r.plaintext, chainKeyFp, chainGen, wire: wireInfo(message) });
    } else {
      const chainKeyFp = hex(s.bob.sendingChain!.chainKey);
      const chainGen = s.bob.dhRatchetCount;
      const { message, newState } = await encrypt(s.bob, text);
      s.bob = newState;
      const r = await decrypt(s.alice, message, s.aliceSkipped);
      s.alice = r.newState;
      s.aliceSkipped = r.skippedKeys;
      this.conversation.push({ sender: 'Bob', text: r.plaintext, chainKeyFp, chainGen, wire: wireInfo(message) });
    }
    this.renderConversation();
  }

  private renderConversation() {
    this.messagesContainer.innerHTML = '';
    for (const msg of this.conversation) {
      const div = document.createElement('div');
      div.className = `message ${msg.sender.toLowerCase()}`;
      const bubble = document.createElement('div');
      bubble.className = 'message-bubble';
      bubble.textContent = msg.text;
      bubble.setAttribute('aria-label', `${msg.sender} says: ${msg.text}`);
      div.appendChild(bubble);

      div.appendChild(this.wireInspector(msg));
      this.messagesContainer.appendChild(div);
    }
    this.messagesContainer.scrollTop = this.messagesContainer.scrollHeight;

    const latest = this.conversation[this.conversation.length - 1];
    if (latest) this.announce(`${latest.sender} says: ${latest.text}`);
  }

  /**
   * Build the collapsible per-message "wire format" inspector. This is the core
   * teaching artifact: it shows that every message ships a header carrying the
   * sender's current ratchet public key plus the message-number (Ns) and
   * previous-chain-length (PN) counters the receiver uses to drive the ratchets.
   * Watch the key stay constant while N climbs within a run, then change and N
   * reset to 0 the moment the conversation switches direction.
   */
  private wireInspector(msg: ConversationMessage): HTMLDetailsElement {
    const details = document.createElement('details');
    details.className = 'wire-detail';

    const summary = document.createElement('summary');
    summary.textContent = 'wire format';
    details.appendChild(summary);

    const pre = document.createElement('pre');
    pre.className = 'wire-fields';
    pre.textContent =
      `header.dhPublicKey          ${msg.wire.ratchetKey}\n` +
      `header.messageNumber  (Ns)  ${msg.wire.messageNumber}\n` +
      `header.previousChainLength (PN)  ${msg.wire.previousChainLength}\n` +
      `iv                          ${msg.wire.iv}\n` +
      `ciphertext                  AES-256-GCM (header bound as AAD)`;
    details.appendChild(pre);

    return details;
  }

  private updateStateDisplay() {
    const { alice, bob, aliceSkipped, bobSkipped } = this.session;

    const set = (id: string, value: string) => {
      const el = document.getElementById(id);
      if (el) el.textContent = value;
    };

    set('alice-root-key', hex(alice.rootKey));
    set('alice-send-chain', alice.sendingChain ? hex(alice.sendingChain.chainKey) : '—');
    set('alice-msg-num', String(alice.sendingChain?.messageNumber ?? 0));
    set('alice-dh-count', String(alice.dhRatchetCount));

    set('bob-root-key', hex(bob.rootKey));
    set('bob-send-chain', bob.sendingChain ? hex(bob.sendingChain.chainKey) : '—');
    set('bob-msg-num', String(bob.sendingChain?.messageNumber ?? 0));
    set('bob-dh-count', String(bob.dhRatchetCount));

    set('stat-messages', String(this.conversation.length));
    set('stat-alice-dh', String(alice.dhRatchetCount));
    set('stat-bob-dh', String(bob.dhRatchetCount));
    set('stat-keys-memory', String(aliceSkipped.size + bobSkipped.size));

    this.renderMkTimeline();
    this.renderRatchetViz();
  }

  /**
   * Render the live message-key timeline: one row per message actually sent,
   * showing the chain key that produced it and that the resulting message key
   * was used once and deleted. This makes the symmetric ratchet and forward
   * secrecy concrete with real values from the conversation.
   */
  private renderMkTimeline() {
    const el = document.getElementById('mk-timeline');
    if (!el) return;
    if (!this.conversation.length) return; // keep the explanatory placeholder

    el.innerHTML = '';
    for (const msg of this.conversation) {
      const row = document.createElement('div');
      row.className = `mk-row ${msg.sender.toLowerCase()}`;

      const who = document.createElement('span');
      who.className = 'mk-who';
      who.textContent = msg.sender;

      const derivation = document.createElement('code');
      derivation.className = 'mk-derivation';
      // The chain generation distinguishes the fresh chain after each DH ratchet,
      // where the message number Ns resets back to 0.
      derivation.textContent =
        `chain ${msg.chainGen}: CK[${msg.wire.messageNumber}] ${msg.chainKeyFp} → MK[${msg.wire.messageNumber}]`;

      const fate = document.createElement('span');
      fate.className = 'mk-fate';
      fate.textContent = 'used once · deleted';

      row.append(who, derivation, fate);
      el.appendChild(row);
    }
    el.scrollTop = el.scrollHeight;
  }

  private renderRatchetViz() {
    const container = document.getElementById('ratchet-teeth') as HTMLDivElement | null;
    if (!container) return;
    container.innerHTML = '';

    const maxTeeth = 10;
    const steps = Math.min(
      Math.max(this.session.alice.dhRatchetCount, this.session.bob.dhRatchetCount),
      maxTeeth
    );

    for (let i = 0; i < maxTeeth; i++) {
      const tooth = document.createElement('div');
      tooth.className = 'tooth';
      let state: string;
      if (i < steps - 1) {
        tooth.classList.add('deleted');
        state = 'deleted';
      } else if (i === steps - 1) {
        tooth.classList.add('active');
        state = 'current';
      } else {
        tooth.classList.add('empty');
        state = 'future';
      }
      tooth.setAttribute('title', `Step ${i + 1}: ${state}`);
      container.appendChild(tooth);
    }
  }

  private switchTab(tabName: string) {
    this.tabButtons.forEach((btn) => {
      const isSelected = btn.dataset.tab === tabName;
      btn.classList.toggle('active', isSelected);
      btn.setAttribute('aria-selected', String(isSelected));
      btn.setAttribute('tabindex', isSelected ? '0' : '-1');
    });
    this.tabContents.forEach((content) => {
      const isActive = content.id === tabName;
      content.classList.toggle('active', isActive);
      if (isActive) content.removeAttribute('hidden');
      else content.setAttribute('hidden', '');
    });
    if (tabName === 'state') this.renderRatchetViz();
  }

  // --- Out-of-order delivery demo --------------------------------------------

  /** Build a fresh session and pre-encrypt a batch of Alice→Bob messages. */
  private async oooGenerate() {
    const session = await buildSession();
    const pending: NonNullable<typeof this.ooo>['pending'] = [];
    for (let i = 0; i < 5; i++) {
      const text = `Message ${i}`;
      const { message, newState } = await encrypt(session.alice, text);
      session.alice = newState;
      pending.push({ index: i, message, text, delivered: false });
    }
    this.ooo = { session, pending };
    this.oooLog = 'Generated 5 messages. Deliver them in any order.';
    this.renderOoo();
  }

  /** Deliver one pending message to Bob and report the skipped-store delta. */
  private async oooDeliver(index: number) {
    if (!this.ooo) return;
    const item = this.ooo.pending.find((p) => p.index === index);
    if (!item || item.delivered) return;

    const s = this.ooo.session;
    const before = skippedNumbers(s.bobSkipped);
    try {
      const r = await decrypt(s.bob, item.message, s.bobSkipped);
      s.bob = r.newState;
      s.bobSkipped = r.skippedKeys;
      item.delivered = true;

      const after = skippedNumbers(s.bobSkipped);
      const stored = after.filter((n) => !before.includes(n));
      const consumed = before.filter((n) => !after.includes(n));

      const parts = [`Delivered m${index} → "${item.text}".`];
      if (stored.length)
        parts.push(
          `Stored skipped key${stored.length > 1 ? 's' : ''} for ${stored.map((n) => `m${n}`).join(', ')}.`
        );
      if (consumed.length)
        parts.push(
          `Consumed the stored key${consumed.length > 1 ? 's' : ''} for ${consumed.map((n) => `m${n}`).join(', ')}.`
        );
      if (!stored.length && !consumed.length) parts.push('In-order — no skipped keys needed.');
      this.oooLog = parts.join(' ');
    } catch (err) {
      this.oooLog = `m${index} failed to decrypt: ${(err as Error).message}`;
    }
    this.renderOoo();
  }

  /** Render the pending-message queue and Bob's skipped-key store. */
  private renderOoo() {
    const pendingEl = document.getElementById('ooo-pending');
    const countEl = document.getElementById('ooo-store-count');
    const keysEl = document.getElementById('ooo-store-keys');
    const logEl = document.getElementById('ooo-log');
    if (!pendingEl || !countEl || !keysEl || !logEl) return;

    pendingEl.innerHTML = '';
    if (!this.ooo) {
      pendingEl.innerHTML = '<p class="empty-state">Generate a batch to begin.</p>';
      countEl.textContent = '0 keys held';
      keysEl.innerHTML = '';
      logEl.textContent = '';
      return;
    }

    for (const item of this.ooo.pending) {
      const card = document.createElement('div');
      card.className = `ooo-msg${item.delivered ? ' delivered' : ''}`;

      const label = document.createElement('span');
      label.className = 'ooo-msg-label';
      label.textContent = item.delivered ? `m${item.index} ✓` : `m${item.index}`;
      card.appendChild(label);

      if (item.delivered) {
        const text = document.createElement('span');
        text.className = 'ooo-msg-text';
        text.textContent = item.text;
        card.appendChild(text);
      } else {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'btn btn-success ooo-deliver';
        btn.textContent = 'Deliver';
        btn.addEventListener('click', () => void this.oooDeliver(item.index));
        card.appendChild(btn);
      }
      pendingEl.appendChild(card);
    }

    const held = skippedNumbers(this.ooo.session.bobSkipped);
    countEl.textContent = `${held.length} key${held.length === 1 ? '' : 's'} held`;
    keysEl.innerHTML = '';
    for (const n of held) {
      const chip = document.createElement('span');
      chip.className = 'ooo-key-chip';
      chip.textContent = `m${n}`;
      keysEl.appendChild(chip);
    }
    logEl.textContent = this.oooLog;
  }

  // --- Forward-secrecy attacker demo -----------------------------------------

  /** Derive a real chain of message keys, then visualize what a stolen chain key exposes. */
  private async runForwardSecrecy() {
    const session = await buildSession();
    // Use Alice's real initial sending chain key as CK[0].
    const messageKeyFps = await chainMessageKeyFps(
      session.alice.sendingChain!.chainKey,
      RatchetWireApp.FS_COUNT
    );
    this.fs = { messageKeyFps, compromiseAt: 3 };
    this.renderForwardSecrecy();
  }

  /**
   * Render the forward-secrecy table. Messages before the compromise point are
   * unrecoverable (their chain keys are gone and the KDF can't run backward);
   * messages from the compromise point onward are exposed, because the attacker
   * forward-ratchets the stolen chain key to reproduce exactly those keys —
   * until a DH ratchet replaces the chain key.
   */
  private renderForwardSecrecy() {
    const controls = document.getElementById('fs-compromise');
    const table = document.getElementById('fs-table');
    const summary = document.getElementById('fs-summary');
    if (!controls || !table || !summary) return;

    if (!this.fs) {
      controls.innerHTML = '';
      table.innerHTML = '<p class="empty-state">Run the demo to derive a chain of message keys.</p>';
      summary.textContent = '';
      return;
    }
    const { messageKeyFps, compromiseAt } = this.fs;
    const count = messageKeyFps.length;

    // Compromise-point selector (0 = steal before any send, count = steal after all).
    controls.innerHTML = '';
    const labelText = document.createElement('span');
    labelText.className = 'fs-control-label';
    labelText.textContent = 'Attacker steals the chain key after Alice has sent:';
    controls.appendChild(labelText);
    for (let k = 0; k <= count; k++) {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = `fs-point${k === compromiseAt ? ' active' : ''}`;
      btn.textContent = String(k);
      btn.setAttribute('aria-pressed', String(k === compromiseAt));
      btn.addEventListener('click', () => {
        if (this.fs) this.fs.compromiseAt = k;
        this.renderForwardSecrecy();
      });
      controls.appendChild(btn);
    }

    // Per-message rows, with the "steal" marker inserted at the compromise point.
    table.innerHTML = '';
    for (let i = 0; i < count; i++) {
      if (i === compromiseAt) table.appendChild(this.fsStealMarker(compromiseAt));

      const exposed = i >= compromiseAt;
      const row = document.createElement('div');
      row.className = `fs-row ${exposed ? 'exposed' : 'safe'}`;

      const msg = document.createElement('span');
      msg.className = 'fs-msg';
      msg.textContent = `m${i}`;

      const mk = document.createElement('code');
      mk.className = 'fs-mk';
      mk.textContent = exposed ? `MK[${i}] ${messageKeyFps[i]}` : `MK[${i}] — used once, deleted`;

      const verdict = document.createElement('span');
      verdict.className = 'fs-verdict';
      verdict.textContent = exposed
        ? `⚠ exposed — attacker derives ${messageKeyFps[i]}`
        : '🔒 safe — cannot derive (one-way KDF, chain key gone)';

      row.append(msg, mk, verdict);
      table.appendChild(row);
    }
    if (compromiseAt === count) table.appendChild(this.fsStealMarker(compromiseAt));

    const exposedCount = count - compromiseAt;
    const safeCount = compromiseAt;
    summary.textContent =
      `Stealing the chain key after ${compromiseAt} message${compromiseAt === 1 ? '' : 's'} exposes ` +
      `${exposedCount} future message${exposedCount === 1 ? '' : 's'} (m${compromiseAt}+) and leaves ` +
      `${safeCount} past message${safeCount === 1 ? '' : 's'} secret. ` +
      'A DH ratchet would replace the chain key and end the exposure — that is break-in recovery.';
  }

  /** The "attacker steals CK[n]" divider row. */
  private fsStealMarker(n: number): HTMLDivElement {
    const marker = document.createElement('div');
    marker.className = 'fs-steal';
    marker.textContent = `🦹 Attacker steals Alice's current chain key CK[${n}]`;
    return marker;
  }

  // --- Break-in recovery simulation -----------------------------------------

  /** Step 1: build a fresh synced session, then snapshot Bob's root key. */
  private async startCompromise() {
    // Fresh session, then a round trip so the last move was Bob -> Alice. This
    // leaves Alice holding a ratchet key Bob has not seen yet, which guarantees
    // the recovery ratchet fires in step 3.
    this.recovery = await buildSession();
    await this.recoveryDeliver('Alice', '🔑 Session handshake');
    await this.recoveryDeliver('Bob', '🔑 Acknowledged');

    this.recoverySnapshotRoot = hex(this.recovery.bob.rootKey, 16);
    this.setRecoveryDetail(
      'compromise-status',
      `Captured Bob's root key: ${this.recoverySnapshotRoot}…`
    );

    (document.getElementById('compromise-status') as HTMLDivElement).hidden = false;
    (document.getElementById('compromise-btn') as HTMLButtonElement).disabled = true;
    (document.getElementById('recovery-send-btn') as HTMLButtonElement).disabled = false;

    this.announce("Bob's keys are compromised. Proceed to step 2 to trigger recovery.");
  }

  /** Step 2: Alice sends, carrying her fresh (post-compromise) ratchet key. */
  private async recoveryAliceSends() {
    if (!this.recovery) return;

    const { message, newState } = await encrypt(this.recovery.alice, 'Recovered traffic 🔒');
    this.recovery.alice = newState;
    this.recoveryPending = message;

    this.setRecoveryDetail(
      'recovery-status',
      `Alice's new ratchet key: ${message.header.dhPublicKey.slice(0, 22)}…`
    );

    (document.getElementById('recovery-status') as HTMLDivElement).hidden = false;
    (document.getElementById('recovery-send-btn') as HTMLButtonElement).disabled = true;
    (document.getElementById('recovery-complete-btn') as HTMLButtonElement).disabled = false;

    this.announce('Alice sent a message with a new DH key. Proceed to step 3.');
  }

  /** Step 3: Bob receives, performs a DH ratchet, and the root key changes. */
  private async recoveryBobReceives() {
    if (!this.recovery || !this.recoveryPending) return;

    const r = await decrypt(this.recovery.bob, this.recoveryPending, this.recovery.bobSkipped);
    this.recovery.bob = r.newState;
    this.recovery.bobSkipped = r.skippedKeys;

    const newRoot = hex(this.recovery.bob.rootKey, 16);
    this.setRecoveryDetail(
      'recovery-complete-status',
      `Old root (attacker has): ${this.recoverySnapshotRoot}…\n` +
        `New root (safe):         ${newRoot}…\n` +
        `Decrypted: "${r.plaintext}" — the snapshot can no longer derive Bob's keys.`
    );

    (document.getElementById('recovery-complete-status') as HTMLDivElement).hidden = false;
    (document.getElementById('recovery-complete-btn') as HTMLButtonElement).disabled = true;

    this.announce('Break-in recovery complete. Bob\'s root key changed; the attacker is locked out.');
  }

  /** Deliver one message within the recovery session. */
  private async recoveryDeliver(from: 'Alice' | 'Bob', text: string) {
    const s = this.recovery!;
    if (from === 'Alice') {
      const { message, newState } = await encrypt(s.alice, text);
      s.alice = newState;
      const r = await decrypt(s.bob, message, s.bobSkipped);
      s.bob = r.newState;
      s.bobSkipped = r.skippedKeys;
    } else {
      const { message, newState } = await encrypt(s.bob, text);
      s.bob = newState;
      const r = await decrypt(s.alice, message, s.aliceSkipped);
      s.alice = r.newState;
      s.aliceSkipped = r.skippedKeys;
    }
  }

  /** Show a monospace key-detail line inside one of the simulation status boxes. */
  private setRecoveryDetail(statusId: string, text: string) {
    const container = document.getElementById(statusId);
    if (!container) return;
    let detail = container.querySelector('.key-reveal') as HTMLPreElement | null;
    if (!detail) {
      detail = document.createElement('pre');
      detail.className = 'key-reveal';
      container.appendChild(detail);
    }
    detail.textContent = text;
  }

  /** Push text to the live region so screen readers announce it. */
  private announce(text: string) {
    const region = document.getElementById('sr-announcements');
    if (region) region.textContent = text;
  }
}

document.addEventListener('DOMContentLoaded', () => {
  void new RatchetWireApp().init();
});
