# 🛡️ GuardByte

> **Zero-Knowledge, Burn-on-Read Secret Sharing Application**  
> Client-side encrypted credential sharing with atomic burn-on-read destruction, PBKDF2 brute-force mitigation, and Wi-Fi QR integration.

---

## 🔒 Security Architecture

GuardByte implements an end-to-end zero-knowledge protocol. Sensitive plaintext and cryptographic keys never reach external servers unencrypted:

* **Client-Side Cryptography:** Data is encrypted locally in the user's browser using the native Web Crypto API (`AES-256-GCM` with a fresh 96-bit IV per secret)[cite: 1].
* **Key Isolation (URL Fragment):** The symmetric decryption key, IV, and optional salt reside exclusively in the URL fragment (`#id=...&key=...&iv=...`)[cite: 1]. Under RFC 3986 standards, URL fragments are never transmitted over HTTP requests or stored in server access logs[cite: 1].
* **Two-Factor Key Derivation:** Optional passphrases derive a secondary key via `PBKDF2` (SHA-256, 250,000 iterations, 16-byte cryptographically secure salt) and combine with the master key using SHA-256[cite: 1].
* **Brute-Force Lockout:** Protected secrets enforce a hard limit of 3 incorrect passphrase attempts[cite: 1]. Upon the third failed attempt, an atomic transaction permanently purges the ciphertext and locks the document[cite: 1].
* **Atomic Burn-on-Read:** Decryption triggers an atomic Firestore transaction that wipes `ciphertext` to `null` while retaining audit metadata (`status: "opened"`, `openedAt`)[cite: 1].
* **Sender Revocation:** The creator can revoke active secrets directly from their device before access[cite: 1]. A two-step confirmation prevents accidental cancellation and immediately purges the remote payload[cite: 1].

---

## 🚀 Key Features

* 🔑 **Text & API Token Vault:** Share API credentials, private keys, and passwords with automatic expiry limits (1 hour, 24 hours, 7 days)[cite: 1].
* 📶 **Wi-Fi Quick Connect:** Encrypts SSID, security protocol, and network passwords into an interactive, scan-to-connect Wi-Fi QR code (`WIFI:T:...;S:...;P:...;;`)[cite: 1].
* 🛑 **Double-Tap Revocation:** Double-tap confirmation pattern prevents accidental cancellation while maintaining instant revocation capabilities[cite: 1].
* 📜 **Live Status Dashboard:** Real-time Firestore snapshot listeners update the creator on whether links are waiting, opened, revoked, or locked[cite: 1].
* 🌓 **Adaptive Interface:** Responsive dark and light theme built with accessible semantic tokens[cite: 1].

---

## 🛠️ Tech Stack

* **Frontend:** Vanilla HTML5, CSS3, JavaScript (ES6+)[cite: 1]
* **Cryptography:** Native Web Crypto API (`SubtleCrypto` — AES-GCM, PBKDF2, SHA-256)[cite: 1]
* **Database & Synchronization:** Google Cloud Firestore[cite: 1]
* **QR Generation:** QRCode.js[cite: 1]

---

## 💻 Local Setup & Development

### 1. Clone the Repository
```bash
git clone https://github.com/<your-username>/guardbyte.git
cd guardbyte
```

### 2. Configure Firebase
1. Create a project in the [Firebase Console](https://console.firebase.google.com/).
2. Enable **Firestore Database** in production mode.
3. Copy `firebase-config.example.js` to `firebase-config.js`:
```bash
cp firebase-config.example.js firebase-config.js
```
4. Insert your Firebase web app keys into `firebase-config.js`:
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
Paste these rules into **Firebase Console → Firestore Database → Rules**:

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

      // Only documents that are currently 'waiting' can change at all
      allow update: if resource.data.status == 'waiting' && (

        // Wrong passphrase: bump the counter by one, nothing else
        ( request.resource.data.diff(resource.data).affectedKeys().hasOnly(['attempts'])
          && request.resource.data.attempts == resource.data.attempts + 1
          && request.resource.data.attempts < 3 )

        // Opened
        || ( request.resource.data.diff(resource.data).affectedKeys().hasOnly(['ciphertext','status','openedAt'])
          && request.resource.data.status == 'opened'
          && request.resource.data.ciphertext == null
          && request.resource.data.openedAt == request.time )

        // Locked after the third wrong passphrase
        || ( request.resource.data.diff(resource.data).affectedKeys().hasOnly(['ciphertext','status','attempts'])
          && request.resource.data.status == 'locked'
          && request.resource.data.ciphertext == null
          && request.resource.data.attempts == resource.data.attempts + 1
          && request.resource.data.attempts >= 3 )

        // Revoked by the creator
        || ( request.resource.data.diff(resource.data).affectedKeys().hasOnly(['ciphertext','status','revokedAt'])
          && request.resource.data.status == 'revoked'
          && request.resource.data.ciphertext == null
          && request.resource.data.revokedAt == request.time )

        // Expired, only once the expiry time has passed
        || ( request.resource.data.diff(resource.data).affectedKeys().hasOnly(['ciphertext','status'])
          && request.resource.data.status == 'expired'
          && request.resource.data.ciphertext == null
          && resource.data.expiresAt < request.time.toMillis() )
      );
    }
  }
}
```

### 4. Run Locally
Serve the application locally with a static server:

```bash
# Using Python
python -m http.server 8000

# Or using Node.js npx
npx http-server -p 8000
```
Open `http://localhost:8000` in your browser.

---

## 🔮 Roadmap / Future Enhancements

* **Creator Token Authorization:** Implement client-side generated creator tokens hashed in Firestore to enforce cryptographic ownership over revocation requests.
* **Hardware-Bound Authentication:** Introduce WebAuthn / Passkey support for hardware-level access verification.
* **In-Memory Binary Chunking:** Support client-side AES-GCM chunked streaming for secure, burn-on-read PDF and image sharing.