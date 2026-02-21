---

````md
# VaultQ: Post-Quantum Secure Medical Record Vault

VaultQ is a next-generation, highly secure client-server medical record management system. Built from the ground up to withstand both modern cyber threats and future quantum computing attacks, VaultQ implements a hybrid cryptographic architecture that pairs classical algorithms (AES-GCM, ECDSA) with NIST-standardized Post-Quantum Cryptography (ML-DSA).

---

## ⚠️ The Problem: Market Vulnerabilities in Healthcare

Current medical record systems suffer from critical security blind spots:

### The Quantum Threat ("Store Now, Decrypt Later")
Adversaries are harvesting encrypted medical data today. When fault-tolerant quantum computers become available, classical public-key cryptography (RSA, ECC) will be broken via Shor’s Algorithm, exposing decades of sensitive patient data.

### Weak Transport Security
Many systems rely on standard TLS without strict mutual authentication, leaving them vulnerable to Man-In-The-Middle (MITM) attacks or unauthorized API access via stolen bearer tokens.

### Implicit Trust & Poor Data-at-Rest
Healthcare APIs often implicitly trust payloads from authenticated users without verifying payload integrity. Data is often encrypted at rest using a single database key, meaning a single breach compromises all patient records.

---

## 🛡️ The Solution: VaultQ Architecture

VaultQ addresses these risks through layered cryptographic controls:

- Mutual TLS (mTLS) for cryptographic identity verification  
- Post-Quantum Digital Signatures (ML-DSA-65) for integrity and non-repudiation  
- Application-layer envelope encryption for strong data-at-rest security  

---

## 🔄 System Workflows

### Doctor Provisioning & PQC Enrollment

```mermaid
sequenceDiagram
    autonumber
    participant Admin
    participant Server
    participant Doctor
    participant Client

    Admin->>Server: Provision doctor
    Server-->>Admin: Temporary ID and password hash
    Admin->>Doctor: Share credentials offline

    Doctor->>Client: Enter credentials
    Client->>Client: Generate ML-DSA keypair
    Client->>Client: Generate ECDSA keypair
    Client->>Server: Submit public keys

    Admin->>Server: Approve certificate
    Server->>Server: Issue X.509 certificate

    Client->>Server: Poll for certificate
    Server-->>Client: Deliver doctor certificate
    Client->>Client: Store credentials securely
````

---

### Authentication & Secure Network Transport

VaultQ uses Mutual TLS (mTLS):

* Client presents X.509 certificate
* Server validates certificate chain
* Connection is terminated immediately if validation fails

---

### Secure Record Upload (Double Envelope Encryption)

```mermaid
sequenceDiagram
    autonumber
    participant App
    participant Network
    participant Server
    participant Storage

    App->>App: Generate AES DEK
    App->>App: Encrypt patient file
    App->>App: Wrap DEK with server vault key
    App->>App: Sign payload with ML-DSA
    App->>Network: POST /api/doctor/upload

    Network->>Server: Decrypt mTLS layer
    Server->>Server: Verify X.509 certificate
    Server->>Server: Verify ML-DSA signature

    alt Invalid
        Server-->>App: Reject upload
    else Valid
        Server->>Server: Re-encrypt with server master key
        Server->>Storage: Store encrypted record
        Server-->>App: Upload successful
    end
```

---

## 🗄️ Data Storage Architecture

### Server Master Key

* AES-256 key generated at first boot
* Used to encrypt all data at rest

### Hospital Vault Database

* Stores doctor identities
* Stores hashed credentials
* Stores PQC public keys
* Stores certificate status

### Patient Vaults

* One directory per patient
* Encrypted JSON records
* Includes ciphertext, nonces, and hashes
* Tamper detection via record hash

---

## 🛠️ Technology Stack

* Backend: FastAPI, Uvicorn
* Desktop Client: CustomTkinter
* Crypto: cryptography (AES-GCM, ECDSA, X.509)
* Post-Quantum Crypto: dilithium-py (ML-DSA-65)
* Password Hashing: passlib[bcrypt]
* Admin UI: HTML5, TailwindCSS, Alpine.js

---

## ✅ Security Guarantees

* Cryptographic identity (mTLS)
* Post-quantum integrity protection
* Envelope encryption for stored data
* Tamper detection
* Patient-level data isolation

---

VaultQ is designed to keep medical data confidential today and resilient against tomorrow’s quantum threats.

```

---

### Why this version will render properly

This avoids:
- Mermaid `id=` attributes (breaks GitHub)  
- Actor syntax (breaks some renderers)  
- Mermaid class syntax  
- HTML inside Mermaid  
- Emoji inside Mermaid labels  
- Nested parentheses in participant names  

---

If you tell me **where you’re rendering this** (GitHub README, MkDocs, Obsidian, Notion, GitBook, etc.), I can tailor the Markdown *exactly* to that renderer’s quirks so it shows perfectly first try.
```
