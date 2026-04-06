/**
 * Ratchet Wire - Main Application
 * Double Ratchet Algorithm Visualization
 */

import '../style.css';
import { RatchetState } from './crypto/dh-ratchet';
import { Message, encrypt, decrypt } from './crypto/double-ratchet';
import { generateKeyPair } from './crypto/x25519';
import {
  AliceSessionInitKeys,
  BobPreSessionKeys,
  initiateSessionX3DH,
  acceptSessionX3DH,
  createAliceRatchetState,
  createBobRatchetState,
} from './crypto/session-init';

interface ConversationMessage {
  sender: 'Alice' | 'Bob';
  text: string;
  timestamp: number;
}

class RatchetWireApp {
  // Ratchet states
  private aliceState!: RatchetState;
  private bobState!: RatchetState;

  // Session keys
  private aliceSessionInitKeys!: AliceSessionInitKeys;
  private bobPreSessionKeys!: BobPreSessionKeys;

  // Alice and Bob DH key pairs
  private aliceDHKeyPair!: { publicKey: CryptoKey; privateKey: CryptoKey };
  private bobDHKeyPair!: { publicKey: CryptoKey; privateKey: CryptoKey };

  // Conversation state
  private conversation: ConversationMessage[] = [];
  private aliceSkippedKeys = new Map<string, ArrayBuffer>();
  private bobSkippedKeys = new Map<string, ArrayBuffer>();

  // Compromise simulation state
  private isBobCompromised = false;
  private bobCompromisedState: { rootKey: ArrayBuffer; chainKeys: any } | null = null;

  // UI Elements
  private messagesContainer!: HTMLDivElement;
  private messageInput!: HTMLInputElement;
  private sendBtn!: HTMLButtonElement;
  private senderRadios!: NodeListOf<HTMLInputElement>;
  private tabButtons!: NodeListOf<HTMLButtonElement>;
  private tabContents!: NodeListOf<HTMLDivElement>;

  async init() {
    console.log('Initializing Ratchet Wire...');

    // Initialize cryptographic session
    await this.initializeSession();

    // Setup UI
    this.setupUI();

    console.log('✓ Ratchet Wire initialized');
    this.updateStateDisplay();
  }

  private async initializeSession() {
    // Generate all required keys
    this.aliceSessionInitKeys = {
      identityKeyPair: await generateKeyPair(),
      ephemeralKeyPair: await generateKeyPair(),
    };

    this.bobPreSessionKeys = {
      identityKeyPair: await generateKeyPair(),
      signedPreKeyPair: await generateKeyPair(),
    };

    this.aliceDHKeyPair = await generateKeyPair();
    this.bobDHKeyPair = await generateKeyPair();

    // Run X3DH from both perspectives
    const aliceSessionResult = await initiateSessionX3DH(
      this.aliceSessionInitKeys,
      this.bobPreSessionKeys.identityKeyPair.publicKey,
      this.bobPreSessionKeys.signedPreKeyPair.publicKey,
      this.aliceDHKeyPair,
      this.bobDHKeyPair
    );

    const bobSessionResult = await acceptSessionX3DH(
      this.bobPreSessionKeys,
      this.aliceSessionInitKeys.identityKeyPair.publicKey,
      this.aliceSessionInitKeys.ephemeralKeyPair.publicKey,
      this.aliceDHKeyPair,
      this.bobDHKeyPair
    );

    // Create ratchet states
    this.aliceState = createAliceRatchetState(aliceSessionResult);
    this.bobState = createBobRatchetState(bobSessionResult);

    console.log('✓ X3DH key agreement complete');
  }

  private setupUI() {
    // Grab references
    this.messagesContainer = document.getElementById('messages') as HTMLDivElement;
    this.messageInput = document.getElementById('message-input') as HTMLInputElement;
    this.sendBtn = document.getElementById('send-btn') as HTMLButtonElement;
    this.senderRadios = document.querySelectorAll(
      'input[name="sender"]'
    ) as NodeListOf<HTMLInputElement>;
    this.tabButtons = document.querySelectorAll('.tab-btn') as NodeListOf<HTMLButtonElement>;
    this.tabContents = document.querySelectorAll('.tab-content') as NodeListOf<HTMLDivElement>;

    // Form submission (send message)
    const form = document.getElementById('message-form') as HTMLFormElement;
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      this.sendMessage();
    });

    // Tab switching (click + keyboard)
    this.tabButtons.forEach((btn) => {
      btn.addEventListener('click', () => this.switchTab(btn.dataset.tab!));
    });

    // Arrow-key navigation within tablist (WCAG pattern)
    const tablist = document.querySelector('[role="tablist"]') as HTMLElement;
    tablist.addEventListener('keydown', (e) => {
      const tabs = Array.from(this.tabButtons);
      const current = tabs.findIndex((b) => b.getAttribute('aria-selected') === 'true');
      let next = -1;

      if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
        next = (current + 1) % tabs.length;
      } else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
        next = (current - 1 + tabs.length) % tabs.length;
      } else if (e.key === 'Home') {
        next = 0;
      } else if (e.key === 'End') {
        next = tabs.length - 1;
      }

      if (next >= 0) {
        e.preventDefault();
        this.switchTab(tabs[next].dataset.tab!);
        tabs[next].focus();
      }
    });

    // Compromise buttons
    document.getElementById('compromise-btn')?.addEventListener('click', () => {
      this.simulateCompromise();
    });

    document.getElementById('recovery-send-btn')?.addEventListener('click', () => {
      this.recoveryDemo_AliceSends();
    });

    document.getElementById('recovery-complete-btn')?.addEventListener('click', () => {
      this.recoveryDemo_BobReceives();
    });

    // Render ratchet visualization
    this.renderRatchetViz();
  }

  private async sendMessage() {
    const text = this.messageInput.value.trim();
    if (!text) return;

    const sender = (document.querySelector('input[name="sender"]:checked') as HTMLInputElement)
      ?.value as 'alice' | 'bob';

    if (sender === 'alice') {
      await this.aliceSendMessage(text);
    } else {
      await this.bobSendMessage(text);
    }

    this.messageInput.value = '';
    this.updateStateDisplay();
  }

  private async aliceSendMessage(text: string) {
    // Encrypt from Alice
    const { message, newState } = await encrypt(this.aliceState, text);
    this.aliceState = newState;

    // Receive at Bob
    const { plaintext, newState: bobNewState, skippedKeys } = await decrypt(
      this.bobState,
      message,
      this.bobSkippedKeys
    );
    this.bobState = bobNewState;
    this.bobSkippedKeys = skippedKeys;

    // Add to conversation
    this.conversation.push({
      sender: 'Alice',
      text: plaintext,
      timestamp: Date.now(),
    });

    this.renderConversation();
  }

  private async bobSendMessage(text: string) {
    // Encrypt from Bob
    const { message, newState } = await encrypt(this.bobState, text);
    this.bobState = newState;

    // Receive at Alice
    const { plaintext, newState: aliceNewState, skippedKeys } = await decrypt(
      this.aliceState,
      message,
      this.aliceSkippedKeys
    );
    this.aliceState = aliceNewState;
    this.aliceSkippedKeys = skippedKeys;

    // Add to conversation
    this.conversation.push({
      sender: 'Bob',
      text: plaintext,
      timestamp: Date.now(),
    });

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
      // Screen readers: announce sender context
      bubble.setAttribute('aria-label', `${msg.sender} says: ${msg.text}`);

      div.appendChild(bubble);
      this.messagesContainer.appendChild(div);
    }

    // Scroll to bottom
    this.messagesContainer.scrollTop = this.messagesContainer.scrollHeight;

    // Announce latest message to screen readers
    const latest = this.conversation[this.conversation.length - 1];
    if (latest) {
      this.announce(`${latest.sender} says: ${latest.text}`);
    }
  }

  private updateStateDisplay() {
    // Convert keys to display strings
    const aliceRootKey = this.keyToString(this.aliceState.rootKey);
    const aliceSendChain = this.keyToString(this.aliceState.sendingChain.chainKey);
    const bobRootKey = this.keyToString(this.bobState.rootKey);
    const bobSendChain = this.keyToString(this.bobState.sendingChain.chainKey);

    // Update display
    (document.getElementById('alice-root-key') as HTMLDivElement).textContent = aliceRootKey;
    (document.getElementById('alice-send-chain') as HTMLDivElement).textContent = aliceSendChain;
    (document.getElementById('alice-msg-num') as HTMLDivElement).textContent =
      this.aliceState.sendingChain.messageNumber.toString();
    (document.getElementById('alice-dh-count') as HTMLDivElement).textContent =
      this.aliceState.dhRatchetCount.toString();

    (document.getElementById('bob-root-key') as HTMLDivElement).textContent = bobRootKey;
    (document.getElementById('bob-send-chain') as HTMLDivElement).textContent = bobSendChain;
    (document.getElementById('bob-msg-num') as HTMLDivElement).textContent =
      this.bobState.sendingChain.messageNumber.toString();
    (document.getElementById('bob-dh-count') as HTMLDivElement).textContent =
      this.bobState.dhRatchetCount.toString();

    // Update stats
    (document.getElementById('stat-messages') as HTMLDivElement).textContent =
      this.conversation.length.toString();
    (document.getElementById('stat-alice-dh') as HTMLDivElement).textContent =
      this.aliceState.dhRatchetCount.toString();
    (document.getElementById('stat-bob-dh') as HTMLDivElement).textContent =
      this.bobState.dhRatchetCount.toString();
    (document.getElementById('stat-keys-memory') as HTMLDivElement).textContent = '0';
  }

  private keyToString(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    return Array.from(bytes.slice(0, 8))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
      .toUpperCase();
  }

  private renderRatchetViz() {
    const container = document.getElementById('ratchet-teeth') as HTMLDivElement;
    container.innerHTML = '';

    const maxTeeth = 10;
    let currentCount = (this.aliceState.dhRatchetCount + this.bobState.dhRatchetCount) / 2;
    if (currentCount > maxTeeth) currentCount = maxTeeth;

    for (let i = 0; i < maxTeeth; i++) {
      const tooth = document.createElement('div');
      tooth.className = 'tooth';

      let state: string;
      if (i < Math.floor(currentCount)) {
        tooth.classList.add('deleted');
        state = 'deleted';
      } else if (i === Math.floor(currentCount)) {
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
    // Update ARIA on tab buttons
    this.tabButtons.forEach((btn) => {
      const isSelected = btn.dataset.tab === tabName;
      btn.classList.toggle('active', isSelected);
      btn.setAttribute('aria-selected', String(isSelected));
      btn.setAttribute('tabindex', isSelected ? '0' : '-1');
    });

    // Show/hide panels with hidden attribute
    this.tabContents.forEach((content) => {
      const isActive = content.id === tabName;
      content.classList.toggle('active', isActive);
      if (isActive) {
        content.removeAttribute('hidden');
      } else {
        content.setAttribute('hidden', '');
      }
    });

    // Re-render visualizations if needed
    if (tabName === 'state') {
      this.renderRatchetViz();
    }
  }

  private simulateCompromise() {
    this.isBobCompromised = true;
    this.bobCompromisedState = {
      rootKey: this.bobState.rootKey,
      chainKeys: {
        sending: this.bobState.sendingChain.chainKey,
        receiving: this.bobState.receivingChain.chainKey,
      },
    };

    const statusEl = document.getElementById('compromise-status') as HTMLDivElement;
    statusEl.hidden = false;

    const compromiseBtnEl = document.getElementById('compromise-btn') as HTMLButtonElement;
    compromiseBtnEl.disabled = true;

    const sendBtnEl = document.getElementById('recovery-send-btn') as HTMLButtonElement;
    sendBtnEl.disabled = false;

    this.announce('Bob\'s keys have been compromised. Proceed to step 2 to trigger recovery.');
    console.log('⚠️ Bob compromised! Attacker has root key and chain keys.');
  }

  private async recoveryDemo_AliceSends() {
    if (!this.isBobCompromised) return;

    // Alice sends a message (which advances her DH key)
    const text = 'Recovered message - attacker locked out!';
    await this.aliceSendMessage(text);

    const statusEl = document.getElementById('recovery-status') as HTMLDivElement;
    statusEl.hidden = false;

    const sendBtnEl = document.getElementById('recovery-send-btn') as HTMLButtonElement;
    sendBtnEl.disabled = true;

    const completeBtnEl = document.getElementById('recovery-complete-btn') as HTMLButtonElement;
    completeBtnEl.disabled = false;

    this.announce('Alice sent a message with a new DH key. Proceed to step 3.');
  }

  private recoveryDemo_BobReceives() {
    if (!this.isBobCompromised) return;

    // The key property: Bob's root key has changed due to DH ratchet
    // The attacker cannot compute the new root key because they don't have the private keys

    const statusEl = document.getElementById('recovery-complete-status') as HTMLDivElement;
    statusEl.hidden = false;

    const completeBtnEl = document.getElementById('recovery-complete-btn') as HTMLButtonElement;
    completeBtnEl.disabled = true;

    // Show comparison
    const oldRootKey = this.keyToString(this.bobCompromisedState!.rootKey);
    const newRootKey = this.keyToString(this.bobState.rootKey);

    this.announce('Break-in recovery complete. The attacker has been locked out.');
    console.log(`✓ Bob's root key changed:`);
    console.log(`  Old (compromised): ${oldRootKey}`);
    console.log(`  New (safe): ${newRootKey}`);
    console.log(`✓ Attack failed - attacker cannot derive new key`);
  }

  /** Push a message to the live region so screen readers announce it */
  private announce(text: string) {
    const region = document.getElementById('sr-announcements');
    if (region) {
      region.textContent = text;
    }
  }
}

// Initialize on load
document.addEventListener('DOMContentLoaded', async () => {
  const app = new RatchetWireApp();
  await app.init();
});
