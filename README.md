# Decentralized Identity Verification System

## Overview

This smart contract implements a privacy-preserving decentralized identity verification system on the Stacks blockchain. It enables users to create and manage digital identities, issue verifiable credentials, and perform selective disclosure of identity attributes while maintaining privacy.

## Key Features

- **Self-Sovereign Identity**: Users create and control their own digital identities
- **Verifiable Credentials**: Trusted issuers can issue credentials to identities
- **Zero-Knowledge Proofs**: Verify attributes without revealing actual data
- **Selective Disclosure**: Users control exactly what information to share
- **Reputation System**: Context-specific reputation scores from multiple attestations
- **Age Verification**: Privacy-preserving age verification (over 18/21/65)
- **Credential Revocation**: Issuers can revoke credentials when needed
- **Trusted Issuers**: Only authorized identity providers can issue credentials

## Contract Details

### Constants

- **Error Codes**: Standardized error messages for all operations
- **Credential Types**: Identity, age, address, education, employment, financial, etc.
- **Verification Statuses**: Pending, approved, rejected, revoked

### Data Structures

- **Identity Providers**: Trusted organizations that issue credentials
- **Digital Identities**: User-controlled identity records
- **Credentials**: Verifiable claims about an identity
- **Verifications**: Attestations of credential validity
- **Disclosure Authorizations**: Permissions for selective data sharing
- **Reputation Scores**: Context-specific reputation metrics
- **Committed Attributes**: Hashed attributes for zero-knowledge verification
- **Age Proofs**: Privacy-preserving age verification records

### Main Functions

1. **Identity Management**:
   - `create-identity`: Create a new digital identity
   - `get-identity`: Retrieve identity details

2. **Credential Management**:
   - `issue-credential`: Issue a verifiable credential
   - `revoke-credential`: Revoke an issued credential
   - `verify-credential`: Verify a credential's validity

3. **Privacy Features**:
   - `commit-attribute`: Store hashed attributes for ZK verification
   - `issue-age-proof`: Create privacy-preserving age verification
   - `authorize-disclosure`: Grant selective data access
   - `revoke-disclosure-authorization`: Remove data access

4. **Reputation System**:
   - `submit-reputation-attestation`: Add reputation attestation
   - `get-reputation`: Retrieve reputation score

5. **Provider Management**:
   - `register-provider`: Add new identity provider (admin only)
   - `transfer-ownership`: Change contract owner (admin only)

## Usage Examples

### Creating an Identity

```clarity
(create-identity 
  0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef ;; identity-hash
  (some "https://metadata.example.com/identity/1") ;; Optional metadata URI
)
```

### Issuing a Credential

```clarity
(issue-credential 
  u1                  ;; identity-id
  CREDENTIAL-TYPE-AGE ;; credential-type
  0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890 ;; credential-hash
  0x1234567890...     ;; verification-proof (512 bytes)
  (some u10950)       ;; expires in ~3 months (optional)
)
```

### Creating an Age Proof

```clarity
(issue-age-proof
  u1                  ;; identity-id
  true                ;; age-over-18
  false               ;; age-over-21
  false               ;; age-over-65
  0x1234567890...     ;; proof-hash (32 bytes)
  (some u10950)       ;; expires in ~3 months (optional)
)
```

### Verifying Age Without Revealing Exact Age

```clarity
(verify-age-over u1 u18) ;; Returns true if identity is over 18
```

### Authorizing Selective Disclosure

```clarity
(authorize-disclosure
  u1                  ;; identity-id
  'SP3ABC123...       ;; authorized principal
  (list CREDENTIAL-TYPE-AGE CREDENTIAL-TYPE-ADDRESS) ;; authorized types
  (some u10950)       ;; expires in ~3 months (optional)
  0x1234567890...     ;; authorization-proof (128 bytes)
)
```

## Security and Privacy Features

1. **Zero-Knowledge Verification**:
   - Verify attributes like age without revealing exact values
   - Check attribute hashes against committed values

2. **Selective Disclosure**:
   - Granular control over which credentials to share
   - Time-limited access grants

3. **Credential Revocation**:
   - Issuers can revoke credentials when needed
   - Automatic expiration of credentials

4. **Reputation System**:
   - Context-specific scores (e.g., "financial", "social")
   - Confidence scores based on attestation count

5. **Immutable Audit Trail**:
   - All credential issuances and verifications recorded on-chain
   - Cryptographic proofs of all operations

## Integration Guide

To integrate with this identity system:

1. **For Applications**:
   - Use `verify-age-over` for age-gated content
   - Check `is-disclosure-authorized` before requesting data
   - Use `get-reputation` for reputation-based access

2. **For Identity Providers**:
   - Register as a provider (admin approval required)
   - Issue credentials to verified identities
   - Submit reputation attestations

3. **For Users**:
   - Create your identity once
   - Obtain credentials from trusted providers
   - Manage disclosure authorizations carefully

## License

This contract is provided as-is under the MIT License. Use at your own risk. For production use, thorough security audits are recommended.

## Future Enhancements

1. Support for more complex zero-knowledge proofs
2. Decentralized provider reputation system
3. Identity recovery mechanisms
4. Cross-chain verification capabilities
5. Standard compliance (W3C Verifiable Credentials, DID standards)