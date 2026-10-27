# GuardByte

Zero-Knowledge, Ephemeral Secret Sharing Application

GuardByte provides client-side encrypted credential sharing with atomic burn-on-read destruction, PBKDF2-based brute-force mitigation, and Wi-Fi credential parsing via dynamic QR encoding.

---

## Security Architecture and Threat Model

GuardByte implements an end-to-end zero-knowledge protocol designed to eliminate third-party server trust by ensuring plaintext secrets and cryptographic keys are strictly confined to the client runtime and are never transmitted across network boundaries in an unencrypted state. Data encryption occurs locally in the user's browser using the native Web Crypto API (`SubtleCrypto`) via AES-256-GCM paired with a cryptographically random 96-bit Initialization Vector (IV) generated per secret. Decryption keys, IVs, and derivation salts are encoded exclusively within the URI fragment identifier (`#id=...&key=...&iv=...`), which, under RFC 3986 standards, is processed purely by the client and is never transmitted in HTTP request headers, intermediate proxies, or server access logs. For additional protection, user passphrases derive a secondary key using PBKDF2 with SHA-256 over 250,000 iterations and a 16-byte cryptographically secure salt, combining with the master AES key via SHA-256 before decryption can proceed. At the database tier, Google Cloud Firestore security rules enforce a hard limit of three failed passphrase attempts, triggering an atomic transaction that sets the ciphertext to null and permanently locks the document upon the third incorrect guess. Successful retrieval executes an atomic burn-on-read transaction that purges the ciphertext field to null while updating metadata status, preventing payload recovery, while creators retain the ability to manually trigger instant client-side revocation before recipient access.

---

## Key Features and Specifications

GuardByte is built using vanilla ECMAScript (ES6+), semantic HTML5, and CSS3, relying on the native Web Crypto API for cryptographic operations, Google Cloud Firestore for transactional state synchronization, and QRCode.js for client-side barcode synthesis. The platform provides an ephemeral vault for arbitrary credentials, API tokens, and private keys with client-enforced time-to-live expiration bounds, alongside an integrated Wi-Fi onboarding mechanism that formats network SSIDs, protocol types, and pre-shared passwords directly into local scan-to-connect QR codes. Real-time Firestore snapshot listeners maintain live status synchronization across clients, reflecting state changes across waiting, opened, locked, revoked, and expired phases, while the sender dashboard incorporates a double-action confirmation pattern to prevent accidental cancellation during manual revocations.

---

## Local Development and Configuration

### Prerequisites

* A standard static web server (such as Python's `http.server` or Node's `http-server`).
* A Google Cloud project with Cloud Firestore initialized in Production Mode.

### 1. Clone the Repository

```bash
git clone https://github.com/AditiGigabyte/guardbyte.git
cd guardbyte

```

### 2. Configure Firebase Environment

Duplicate the example configuration file:

```bash
cp firebase-config.example.js firebase-config.js

```

Populate `firebase-config.js` with your application credentials:

```javascript
const firebaseConfig = {
  apiKey: "YOUR_API_KEY",
  authDomain: "YOUR_PROJECT.firebaseapp.com",
  projectId: "YOUR_PROJECT_ID",
  storageBucket: "YOUR_PROJECT.appspot.com",
  messagingSenderId: "YOUR_SENDER_ID",
  appId: "YOUR_APP_ID"
};

```

### 3. Deploy Firestore Security Rules

To enforce server-side validation and atomic payload destruction, apply the following configuration in the Firebase Console under **Firestore Database -> Rules**:

```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /secrets/{id} {
      allow get: if true;
      allow list, delete: if false;

      allow create: if request.resource.data.status == 'waiting'
                    && request.resource.data.attempts == 0
                    && request.resource.data.ciphertext is string
                    && request.resource.data.ciphertext.size() < 20000;

      allow update: if resource.data.status == 'waiting' && (

        ( request.resource.data.diff(resource.data).affectedKeys().hasOnly(['attempts'])
          && request.resource.data.attempts == resource.data.attempts + 1
          && request.resource.data.attempts < 3 )

        || ( request.resource.data.diff(resource.data).affectedKeys().hasOnly(['ciphertext','status','openedAt'])
          && request.resource.data.status == 'opened'
          && request.resource.data.ciphertext == null
          && request.resource.data.openedAt == request.time )

        || ( request.resource.data.diff(resource.data).affectedKeys().hasOnly(['ciphertext','status','attempts'])
          && request.resource.data.status == 'locked'
          && request.resource.data.ciphertext == null
          && request.resource.data.attempts == resource.data.attempts + 1
          && request.resource.data.attempts >= 3 )

        || ( request.resource.data.diff(resource.data).affectedKeys().hasOnly(['ciphertext','status','revokedAt'])
          && request.resource.data.status == 'revoked'
          && request.resource.data.ciphertext == null
          && request.resource.data.revokedAt == request.time )

        || ( request.resource.data.diff(resource.data).affectedKeys().hasOnly(['ciphertext','status'])
          && request.resource.data.status == 'expired'
          && request.resource.data.ciphertext == null
          && resource.data.expiresAt < request.time.toMillis() )
      );
    }
  }
}

```

### 4. Serve the Application

Run a static server from the project root:

```bash
# Python 3
python3 -m http.server 8000

# Node.js
npx http-server -p 8000

```

Navigate to `http://localhost:8000` in a standards-compliant browser.

---

## Roadmap

Future developments focus on implementing client-side derived author tokens stored via cryptographic hash in Firestore to cryptographically authorize revocation actions, integrating WebAuthn primitives for hardware-bound multi-party verification, and introducing chunked Web Crypto memory streams to enable zero-knowledge ephemeral sharing of binary files.
