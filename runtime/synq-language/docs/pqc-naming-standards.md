# Post-Quantum Cryptography Naming and Formatting Standards

This document defines **mandatory naming and formatting standards** for post-quantum cryptographic algorithms, aligned with NIST standardization. These rules apply uniformly across **documentation, code comments, source code, and file naming**.

Consistency here is not optional—it is a governance requirement.

---

## Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)

**Formerly:** CRYSTALS-Kyber

### Formal ML-KEM Naming Rules

**In documentation and code comments**, ML-KEM must be written as one of the following:

- ML-KEM
- ML-KEM-512
- ML-KEM-768
- ML-KEM-1024
- Module-Lattice-Based Key-Encapsulation Mechanism

**In file names and actual code**, ML-KEM must be written as:

- mlkem
- mlkem512
- mlkem768
- mlkem1024

### NIST Security Level Mapping - ML-KEM

| Variant    | Security Level | Recommended Use Case                                                                                                                           |
|------------|----------------|------------------------------------------------------------------------------------------------------------------------------------------------|
| ML-KEM-512 | Level 1        | Optimized for resource-constrained devices and IoT environments requiring efficient key exchange with strong baseline post-quantum protection. |
| ML-KEM-768 | Level 3        | Standard enterprise-grade configuration for general-purpose encryption and secure channel establishment.                                       |
| ML-KEM-1024| Level 5        | Highest-security configuration for critical infrastructure, national-security, or long-term data confidentiality applications.                 |

---

## Module-Lattice-Based Digital Signature Algorithm (ML-DSA)

**Formerly:** CRYSTALS-Dilithium

### Formal ML-DSA Naming Rules

**In documentation and code comments**, ML-DSA must be written as:

- ML-DSA
- ML-DSA-44
- ML-DSA-65
- ML-DSA-87
- Module-Lattice-Based Digital Signature Algorithm

**In file names and actual code**, ML-DSA must be written as:

- mldsa
- mldsa44
- mldsa65
- mldsa87

### NIST Security Level Mapping - ML-DSA

| Variant   | Security Level | Recommended Use Case                                                                                                             |
|-----------|----------------|----------------------------------------------------------------------------------------------------------------------------------|
| ML-DSA-44 | Level 2        | Suitable for embedded systems, firmware signing, or applications requiring compact signatures with moderate security.            |
| ML-DSA-65 | Level 3        | Balanced performance for most production environments, including blockchain smart-contract signing and digital identity systems. |
| ML-DSA-87 | Level 5        | Maximum-security configuration ideal for root certificate authorities, secure boot chains, and long-term signature validation.   |

---

## Stateless Hash-Based Digital Signature Algorithm (SLH-DSA)

**Formerly:** SPHINCS+

### Formal SLH-DSA Naming Rules

**In documentation and code comments**, SLH-DSA must be written as:

- Stateless Hash-Based Digital Signature Algorithm
- SLH-DSA
- Explicit variant names as standardized by NIST

**In file names and actual code**, SLH-DSA must be written as lowercase `slhdsa` with the full parameter suffix.

### NIST Security Level Mapping - SLH-DSA

| Variant Group | Security Level | Recommended Use Case |
|---------------|----------------|----------------------|
| 128f / 128s   | Level 1        | Fast or compact variants for constrained or bandwidth-sensitive systems. |
| 192f / 192s   | Level 3        | Balanced trade-offs for enterprise authentication or firmware signing. |
| 256f / 256s   | Level 5        | High-assurance signatures for critical security and archival trust anchors. |

---

## FFT (Fast-Fourier Transform) over NTRU-Lattice-Based Digital Signature Algorithm (FN-DSA)

**Formerly:** Falcon

### Formal FN-DSA Naming Rules

**In documentation and code comments**, FN-DSA must be written as:

- FN-DSA
- FN-DSA-512
- FN-DSA-1024
- FFT (Fast-Fourier Transform) over NTRU-Lattice-Based Digital Signature Algorithm

**In file names and actual code**, FN-DSA must be written as:

- fndsa
- fndsa512
- fndsa1024

### NIST Security Level Mapping - FN-DSA

| Variant | Security Level | Recommended Use Case |
|--------|----------------|----------------------|
| FN-DSA-512 | Level 1 | High-speed, compact signature scheme for performance-critical applications. |
| FN-DSA-1024 | Level 5 | Enhanced-security configuration for blockchain, firmware integrity, and secure software distribution. |

---

## Hamming Quasi-Cyclic Key Encapsulation Mechanism (HQC-KEM)

### Formal HQC-KEM Naming Rules

**In documentation and code comments**, HQC-KEM must be written as:

- HQC-KEM
- HQC-KEM-128
- HQC-KEM-192
- HQC-KEM-256
- Hamming Quasi-Cyclic Key Encapsulation Mechanism

**In file names and actual code**, HQC-KEM must be written as:

- hqckem
- hqckem128
- hqckem192
- hqckem256

### NIST Security Level Mapping - HQC-KEM

| Variant | Security Level | Recommended Use Case |
|--------|----------------|----------------------|
| HQC-KEM-128 | Level 1 | Lightweight configuration for constrained devices and fast ephemeral key exchange. |
| HQC-KEM-192 | Level 3 | Robust post-quantum protection for enterprise systems and distributed ledgers. |
| HQC-KEM-256 | Level 5 | Maximum-security configuration for classified or high-sensitivity data. |

---

## Classic McEliece Key Encapsulation Mechanism

### Formal Naming Rules

**In documentation and code comments**, Classic McEliece must be written as:

- Classic-McEliece
- Classic-McEliece-348864
- Classic-McEliece-460896
- Classic-McEliece-6688128
- Classic-McEliece-6960119
- Classic-McEliece-8192128
- Classic McEliece Key Encapsulation Mechanism

**In file names and actual code**, Classic McEliece must be written as:

- cmce
- cmce348864
- cmce460896
- cmce6688128
- cmce6960119
- cmce8192128

### NIST Security Level Mapping

| Variant | Security Level | Recommended Use Case |
|--------|----------------|----------------------|
| Classic-McEliece-348864 | Level 1 | Lightweight applications and constrained environments. |
| Classic-McEliece-460896 | Level 3 | Balanced performance and security for production KEM operations. |
| Classic-McEliece-6688128 | Level 5 | Maximum-security configuration for long-term archival protection. |
| Classic-McEliece-6960119 | Level 5 | Alternative high-security variant for cryptanalytic diversity. |
| Classic-McEliece-8192128 | Level 5 | Ultra-high-security configuration for root-of-trust deployments. |
