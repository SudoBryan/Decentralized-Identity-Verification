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