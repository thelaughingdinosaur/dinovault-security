# DinoVault Security Implementation

**Security Transparency Repository**

This repository contains security-related source code used by **DinoVault**, the password and card storage feature within the **DinoMind** application.

The purpose of this repository is to provide visibility into the general security design and cryptographic approach used by DinoVault.

---

## Purpose and Scope

This repository is provided for transparency and educational review.

It includes selected security-relevant components related to encryption, key handling, lockout logic, and in-memory data handling.  
It does **not** represent the complete application source code.

The information here describes the intended design and implementation at the time of publication.

---

## High-Level Security Design

DinoVault is designed with the following principles:

- Encryption is performed locally on the user’s device  
- Sensitive data is encrypted before being stored or transmitted  
- Cloud services are intended to store encrypted data only  
- The master password is not intentionally transmitted to backend services  
- The system is designed to follow a **zero-knowledge style architecture**

Actual security depends on correct usage, device integrity, and platform security.

---

## Encryption Overview

DinoVault uses modern cryptographic primitives through established libraries.

The current implementation uses:

- Encryption algorithm: **XChaCha20-Poly1305**  
- Cryptographic library: **Google Tink**  
- Intended key length: **256-bit**  
- Nonce size: **192-bit**  
- Authenticated encryption with integrity protection  

XChaCha20-Poly1305 is a widely used authenticated encryption scheme designed to provide confidentiality and integrity when implemented correctly.

---

## Key Derivation Approach

The master password is not stored directly.

Instead, it is used as input to a key derivation function:

- Algorithm: **PBKDF2 with HMAC-SHA256**  
- Iteration count for vault data: approximately **100,000**  
- Iteration count for exported data: approximately **310,000**  
- Random salt generated per user  
- Output key length: **256-bit**  

Higher iteration counts are used for exported data to reduce offline brute-force risk.

---

## Zero-Knowledge Style Design (v2)

DinoVault is designed to avoid storing password verifiers such as hashes.

Instead:

1. The master password is used locally to derive an encryption key  
2. A verification value is encrypted using that derived key  
3. Only encrypted verification data is stored  
4. Password validation is performed by attempting local decryption  

Backend services are not designed to validate or recover the master password.

This design is intended to reduce server-side knowledge of user secrets.  
It does not claim absolute immunity to all attack scenarios.

---

## Encrypted Data Coverage

The application is designed to encrypt sensitive user data, including:

- Stored passwords  
- Card numbers  
- CVV and PIN values  
- Entry titles  
- Usernames and email addresses  
- Custom user-defined fields  

Non-sensitive metadata such as timestamps may be stored unencrypted where required for functionality.

---

## Server-Side Data Visibility

Backend services are intended to receive encrypted values and basic metadata.


## Brute-Force Mitigation Measures

DinoVault includes local mechanisms intended to slow repeated access attempts:

- Artificial delays between failed attempts  
- Temporary lockouts after repeated failures  
- Increasing lockout durations for continued failures  
- Encrypted local storage of attempt counters  
- Use of a monotonic clock to reduce simple time manipulation  

These mechanisms are intended as **risk-reduction measures** and should not be considered absolute protection.

---

## Memory Handling Practices

The application attempts to reduce exposure of sensitive data in memory.

Examples include:

- Clearing password character arrays after use  
- Clearing derived keys when no longer required  
- Removing decrypted data from in-memory caches on vault lock  

Automatic locking after inactivity is used to limit the duration that decrypted data remains accessible.

---

## Repository Contents

This repository contains selected security-related components, including:

- Encryption and key handling logic  
- Encrypted data models  
- Local lockout and attempt tracking logic  
- In-memory cache handling  

User interface code, analytics, backend logic, and unrelated application components are intentionally excluded.

---

## Frequently Asked Questions

### Can this repository be used to assess DinoVault security?

It can provide insight into the intended cryptographic design and implementation, but it does not represent a complete security audit or guarantee.

### Can lost master passwords be recovered?

No recovery mechanism is provided. Users are responsible for retaining their master password.

### Is this repository the full application source code?

No. It contains only selected security-related components.

---

## Industry Context

The design principles used by DinoVault are similar to those commonly found in modern password management applications, including:

- Client-side encryption  
- Zero-knowledge-oriented design  
- Strong key derivation  
- Memory safety practices  

---

## Security Reporting

Potential security issues may be reported responsibly via email.

Contact: **TheLaughingDinosaurHere@gmail.com**

---

## Links

DinoMind on Google Play  
https://play.google.com/store/apps/details?id=com.techmania.pocketmind  

Website  
https://thelaughingdinosaur.blogspot.com  

---

## Legal Notice

This repository is shared in the spirit of transparency and to help users and reviewers understand the security approach used in DinoVault.

While strong security practices and industry-standard cryptography are used, no software can guarantee absolute security. The level of protection also depends on correct usage, device security, platform safeguards, and external factors outside the developer’s control.
