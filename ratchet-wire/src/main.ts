/**
 * Ratchet Wire — Main Application
 * Double Ratchet Algorithm visualization.
 */

import './style.css';
import { RatchetState } from './crypto/dh-ratchet';
import { encrypt, decrypt, Message, SkippedKeys } from './crypto/double-ratchet';
import { generateKeyPair } from './crypto/x25519';
import {
  initiateSessionX3DH,
  acceptSessionX3DH,
  createAliceRatchetState,
  createBobRatchetState,
} from './crypto/session-init';

interface ConversationMessage {
  sender: 'Alice' | 'Bob';
  text: string;
}

/** A fully-initialized Double Ratchet session (initiator + responder). */
interface Session {
  alice: RatchetState;
  bob: RatchetState;
  aliceSkipped: SkippedKeys;
  bobSkipped: SkippedKeys;
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

/** Run the full X3DH handshake and initialize both ratchets. */
async function buildSession(): Promise<Session> {
  const aliceIK = await generateKeyPair();
  const aliceEK = await generateKeyPair();
  const bobIK = await generateKeyPair();
  const bobSPK = await generateKeyPair();
  const aliceRatchet = await generateKeyPair();
  const bobRatchet = await generateKeyPair();

  const aliceSession = await initiateSessionX3DH(
    { identityKeyPair: aliceIK, ephemeralKeyPair: aliceEK },
    bobIK.publicKey,
    bobSPK.publicKey
  );
  const bobSession = await acceptSessionX3DH(
    { identityKeyPair: bobIK, signedPreKeyPair: bobSPK },
    aliceIK.publicKey,
    aliceEK.publicKey
  );

  return {
    alice: await createAliceRatchetState(aliceSession, aliceRatchet, bobRatchet.publicKey),
    bob: createBobRatchetState(bobSession, bobRatchet),
    aliceSkipped: new Map(),
    bobSkipped: new Map(),
  };
}

function hex(buffer: ArrayBuffer, bytes = 8): string {
  return Array.from(new Uint8Array(buffer).slice(0, bytes))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
}

class RatchetWireApp {
  // Main conversation session.
  private session!: Session;
  private conversation: ConversationMessage[] = [];

  // Dedicated session for the break-in recovery simulation (kept separate so it
  // is deterministic regardless of what the user did in the main conversation).
  private recovery: Session | null = null;
  private recoverySnapshotRoot: string | null = null;
  private recoveryPending: Message | null = null;

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

    document.getElementById('compromise-btn')?.addEventListener('click', () => {
      void this.startCompromise();
    });
    document.getElementById('recovery-send-btn')?.addEventListener('click', () => {
      void this.recoveryAliceSends();
    });
    document.getElementById('recovery-complete-btn')?.addEventListener('click', () => {
      void this.recoveryBobReceives();
    });

    this.renderRatchetViz();
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
      const { message, newState } = await encrypt(s.alice, text);
      s.alice = newState;
      const r = await decrypt(s.bob, message, s.bobSkipped);
      s.bob = r.newState;
      s.bobSkipped = r.skippedKeys;
      this.conversation.push({ sender: 'Alice', text: r.plaintext });
    } else {
      const { message, newState } = await encrypt(s.bob, text);
      s.bob = newState;
      const r = await decrypt(s.alice, message, s.aliceSkipped);
      s.alice = r.newState;
      s.aliceSkipped = r.skippedKeys;
      this.conversation.push({ sender: 'Bob', text: r.plaintext });
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
      this.messagesContainer.appendChild(div);
    }
    this.messagesContainer.scrollTop = this.messagesContainer.scrollHeight;

    const latest = this.conversation[this.conversation.length - 1];
    if (latest) this.announce(`${latest.sender} says: ${latest.text}`);
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

    this.renderRatchetViz();
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
