;; Decentralized Identity Verification
;; A privacy-preserving identity verification system

;; Error Codes
(define-constant ERR-NOT-AUTHORIZED u1)
(define-constant ERR-IDENTITY-NOT-FOUND u2)
(define-constant ERR-PROVIDER-NOT-FOUND u3)
(define-constant ERR-CREDENTIAL-NOT-FOUND u4)
(define-constant ERR-INVALID-PROOF u5)
(define-constant ERR-EXPIRED-CREDENTIAL u6)
(define-constant ERR-ALREADY-EXISTS u7)
(define-constant ERR-REVOKED-CREDENTIAL u8)
(define-constant ERR-INVALID-SIGNATURE u9)
(define-constant ERR-INVALID-PARAMETERS u10)
(define-constant ERR-VERIFICATION-FAILED u11)
(define-constant ERR-DISCLOSURE-NOT-AUTHORIZED u12)
(define-constant ERR-REPUTATION-NOT-FOUND u13)

;; Data Variables
(define-data-var contract-owner principal tx-sender)
(define-data-var next-identity-id uint u1)
(define-data-var next-provider-id uint u1)
(define-data-var next-credential-id uint u1)
(define-data-var next-verification-id uint u1)

;; Constants for credential types
(define-constant CREDENTIAL-TYPE-IDENTITY u1)
(define-constant CREDENTIAL-TYPE-AGE u2)
(define-constant CREDENTIAL-TYPE-ADDRESS u3)
(define-constant CREDENTIAL-TYPE-EDUCATION u4)
(define-constant CREDENTIAL-TYPE-EMPLOYMENT u5)
(define-constant CREDENTIAL-TYPE-FINANCIAL u6)
(define-constant CREDENTIAL-TYPE-GOVERNMENT-ID u7)
(define-constant CREDENTIAL-TYPE-HEALTH u8)
(define-constant CREDENTIAL-TYPE-REPUTATION u9)

;; Constants for verification status
(define-constant VERIFICATION-STATUS-PENDING u1)
(define-constant VERIFICATION-STATUS-APPROVED u2)
(define-constant VERIFICATION-STATUS-REJECTED u3)
(define-constant VERIFICATION-STATUS-REVOKED u4)

;; Mapping for identity providers (issuers)
(define-map identity-providers
  { provider-id: uint }
  {
    name: (string-utf8 100),
    provider-principal: principal,
    provider-public-key: (buff 33),
    provider-url: (string-utf8 255),
    trust-score: uint, ;; 0-100 scale
    provider-type: (string-utf8 50),
    is-active: bool,
    registered-at: uint
  }
)

;; Mapping for provider principals to provider IDs
(define-map provider-principals
  { principal: principal }
  { provider-id: uint }
)

;; Mapping for digital identities
(define-map identities
  { identity-id: uint }
  {
    owner: principal,
    identity-hash: (buff 32), ;; Hash of off-chain full identity data
    created-at: uint,
    updated-at: uint,
    is-active: bool,
    verification-level: uint, ;; 1-5 scale
    metadata-uri: (optional (string-utf8 255)) ;; Optional URI to additional metadata
  }
)
;; Mapping principal to identity ID
(define-map principal-to-identity
  { principal: principal }
  { identity-id: uint }
)

;; Mapping for identity credentials
(define-map credentials
  { credential-id: uint }
  {
    identity-id: uint,
    credential-type: uint,
    issuer-id: uint,
    issued-at: uint,
    expires-at: (optional uint),
    revoked-at: (optional uint),
    credential-hash: (buff 32), ;; Hash of the actual credential data (stored off-chain)
    verification-proof: (buff 512), ;; ZK proof or signature
    status: uint
  }
)

;; Mapping for identity credentials by type
(define-map identity-credentials-by-type
  { identity-id: uint, credential-type: uint, index: uint }
  { credential-id: uint }
)

;; Mapping for credential count by type for an identity
(define-map identity-credential-counts
  { identity-id: uint, credential-type: uint }
  { count: uint }
)

;; Mapping for credential verifications (attestations)
(define-map verifications
  { verification-id: uint }
  {
    credential-id: uint,
    verifier-id: uint, ;; provider ID who verified
    verified-at: uint,
    verification-proof: (buff 512),
    verification-status: uint,
    verification-expiry: (optional uint)
  }
)

;; Mapping for disclosure authorizations
(define-map disclosure-authorizations
  { identity-id: uint, authorized-principal: principal }
  {
    authorized-at: uint,
    expires-at: (optional uint),
    authorized-types: (list 10 uint), ;; List of credential types authorized for disclosure
    authorization-proof: (buff 128) ;; Signature by identity owner
  }
)

;; Mapping for reputation scores
(define-map reputation-scores
  { identity-id: uint, context: (string-utf8 50) }
  {
    score: uint, ;; 0-100 scale
    updated-at: uint,
    attestation-count: uint,
    confidence-score: uint, ;; 0-100 scale
    proof-hash: (buff 32) ;; Hash of all attestations that contributed to score
  }
)

;; Mapping for committed attributes (hashed)
;; Allows verification without revealing the actual data
(define-map committed-attributes
  { identity-id: uint, attribute-name: (string-ascii 64) }
  {
    attribute-hash: (buff 32),
    commitment: (buff 64),
    salt: (buff 32),
    updated-at: uint
  }
)

;; Mapping for age proofs
(define-map age-proofs
  { identity-id: uint }
  {
    age-over-18: bool,
    age-over-21: bool,
    age-over-65: bool,
    proof-issuer: uint,
    issued-at: uint,
    expires-at: (optional uint),
    proof-hash: (buff 32)
  }
)
