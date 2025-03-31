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
;; Read-only functions

;; Get identity details
(define-read-only (get-identity (identity-id uint))
  (map-get? identities { identity-id: identity-id })
)

;; Get identity by principal
(define-read-only (get-identity-by-principal (user-principal principal))
  (match (map-get? principal-to-identity { principal: user-principal })
    identity-mapping (map-get? identities { identity-id: (get identity-id identity-mapping) })
    none
  )
)

;; Get provider details
(define-read-only (get-provider (provider-id uint))
  (map-get? identity-providers { provider-id: provider-id })
)

;; Get provider by principal
(define-read-only (get-provider-by-principal (provider-principal principal))
  (match (map-get? provider-principals { principal: provider-principal })
    provider-mapping (map-get? identity-providers { provider-id: (get provider-id provider-mapping) })
    none
  )
)

;; Get credential details
(define-read-only (get-credential (credential-id uint))
  (map-get? credentials { credential-id: credential-id })
)

;; Check if a credential is valid
(define-read-only (is-credential-valid (credential-id uint))
  (match (map-get? credentials { credential-id: credential-id })
    credential
    (and
      (is-eq (get status credential) VERIFICATION-STATUS-APPROVED)
      (is-none (get revoked-at credential))
      (match (get expires-at credential)
        expiry (< block-height expiry)
        true ;; No expiry set, still valid
      )
    )
    false
  )
)

;; Verify age without revealing exact age
(define-read-only (verify-age-over (identity-id uint) (age-threshold uint))
  (match (map-get? age-proofs { identity-id: identity-id })
    age-proof
    (cond
      ((and (is-eq age-threshold u18) (get age-over-18 age-proof)) (ok true))
      ((and (is-eq age-threshold u21) (get age-over-21 age-proof)) (ok true))
      ((and (is-eq age-threshold u65) (get age-over-65 age-proof)) (ok true))
      (true (ok false))
    )
    (err ERR-CREDENTIAL-NOT-FOUND)
  )
)

;; Get reputation score in a specific context
(define-read-only (get-reputation (identity-id uint) (context (string-utf8 50)))
  (map-get? reputation-scores { identity-id: identity-id, context: context })
)

;; Check if disclosure is authorized for a specific credential type
(define-read-only (is-disclosure-authorized (identity-id uint) (requestor principal) (credential-type uint))
  (match (map-get? disclosure-authorizations { identity-id: identity-id, authorized-principal: requestor })
    auth
    (and
      ;; Check if authorization hasn't expired
      (match (get expires-at auth)
        expiry (< block-height expiry)
        true ;; No expiry set
      )
      ;; Check if credential type is in authorized list
      (is-some (index-of (get authorized-types auth) credential-type))
    )
    false
  )
)

;; Verify an attribute without revealing it (zero-knowledge)
(define-read-only (verify-attribute-match 
  (identity-id uint) 
  (attribute-name (string-ascii 64)) 
  (expected-hash (buff 32))
)
  (match (map-get? committed-attributes { identity-id: identity-id, attribute-name: attribute-name })
    attribute (is-eq (get attribute-hash attribute) expected-hash)
    false
  )
)
;; Public functions

;; Register a new identity provider
(define-public (register-provider
  (name (string-utf8 100))
  (provider-public-key (buff 33))
  (provider-url (string-utf8 255))
  (provider-type (string-utf8 50))
)
  (let
    (
      (provider-id (var-get next-provider-id))
    )
    
    ;; Only contract owner can register providers
    (asserts! (is-eq tx-sender (var-get contract-owner)) (err ERR-NOT-AUTHORIZED))
    
    ;; Create provider record
    (map-set identity-providers
      { provider-id: provider-id }
      {
        name: name,
        provider-principal: tx-sender,
        provider-public-key: provider-public-key,
        provider-url: provider-url,
        trust-score: u50, ;; Default initial score
        provider-type: provider-type,
        is-active: true,
        registered-at: block-height
      }
    )
    
    ;; Map provider principal to ID
    (map-set provider-principals
      { principal: tx-sender }
      { provider-id: provider-id }
    )
    
    ;; Increment provider ID
    (var-set next-provider-id (+ provider-id u1))
    
    (ok provider-id)
  )
)

;; Create a new digital identity
(define-public (create-identity (identity-hash (buff 32)) (metadata-uri (optional (string-utf8 255))))
  (let
    (
      (identity-id (var-get next-identity-id))
    )
    
    ;; Check if principal already has an identity
    (asserts! (is-none (map-get? principal-to-identity { principal: tx-sender })) (err ERR-ALREADY-EXISTS))
    
    ;; Create identity
    (map-set identities
      { identity-id: identity-id }
      {
        owner: tx-sender,
        identity-hash: identity-hash,
        created-at: block-height,
        updated-at: block-height,
        is-active: true,
        verification-level: u1, ;; Initial level
        metadata-uri: metadata-uri
      }
    )
    
    ;; Map principal to identity
    (map-set principal-to-identity
      { principal: tx-sender }
      { identity-id: identity-id }
    )
    
    ;; Increment identity ID
    (var-set next-identity-id (+ identity-id u1))
    
    (ok identity-id)
  )
)

;; Issue a credential to an identity
(define-public (issue-credential
  (identity-id uint)
  (credential-type uint)
  (credential-hash (buff 32))
  (verification-proof (buff 512))
  (expires-at (optional uint))
)
  (let
    (
      (credential-id (var-get next-credential-id))
      (identity (unwrap! (get-identity identity-id) (err ERR-IDENTITY-NOT-FOUND)))
      (provider-mapping (unwrap! (map-get? provider-principals { principal: tx-sender }) (err ERR-PROVIDER-NOT-FOUND)))
      (provider-id (get provider-id provider-mapping))
      (provider (unwrap! (get-provider provider-id) (err ERR-PROVIDER-NOT-FOUND)))
    )
    
    ;; Check if provider is active
    (asserts! (get is-active provider) (err ERR-NOT-AUTHORIZED))
    
    ;; Create credential
    (map-set credentials
      { credential-id: credential-id }
      {
        identity-id: identity-id,
        credential-type: credential-type,
        issuer-id: provider-id,
        issued-at: block-height,
        expires-at: expires-at,
        revoked-at: none,
        credential-hash: credential-hash,
        verification-proof: verification-proof,
        status: VERIFICATION-STATUS-APPROVED
      }
    )
    
    ;; Update credential count and index
    (match (map-get? identity-credential-counts { identity-id: identity-id, credential-type: credential-type })
      existing-count
      (let
        (
          (new-count (+ (get count existing-count) u1))
        )
        ;; Update count
        (map-set identity-credential-counts
          { identity-id: identity-id, credential-type: credential-type }
          { count: new-count }
        )
        
        ;; Add to index
        (map-set identity-credentials-by-type
          { identity-id: identity-id, credential-type: credential-type, index: (- new-count u1) }
          { credential-id: credential-id }
        )
      )
      ;; First credential of this type
      (begin
        (map-set identity-credential-counts
          { identity-id: identity-id, credential-type: credential-type }
          { count: u1 }
        )
        
        (map-set identity-credentials-by-type
          { identity-id: identity-id, credential-type: credential-type, index: u0 }
          { credential-id: credential-id }
        )
      )
    )
    
    ;; Increment credential ID
    (var-set next-credential-id (+ credential-id u1))
    
    (ok credential-id)
  )
)
;; Issue a zero-knowledge age proof
(define-public (issue-age-proof
  (identity-id uint)
  (age-over-18 bool)
  (age-over-21 bool)
  (age-over-65 bool)
  (proof-hash (buff 32))
  (expires-at (optional uint))
)
  (let
    (
      (identity (unwrap! (get-identity identity-id) (err ERR-IDENTITY-NOT-FOUND)))
      (provider-mapping (unwrap! (map-get? provider-principals { principal: tx-sender }) (err ERR-PROVIDER-NOT-FOUND)))
      (provider-id (get provider-id provider-mapping))
      (provider (unwrap! (get-provider provider-id) (err ERR-PROVIDER-NOT-FOUND)))
    )
    
    ;; Check if provider is active
    (asserts! (get is-active provider) (err ERR-NOT-AUTHORIZED))
    
    ;; Create or update age proof
    (map-set age-proofs
      { identity-id: identity-id }
      {
        age-over-18: age-over-18,
        age-over-21: age-over-21,
        age-over-65: age-over-65,
        proof-issuer: provider-id,
        issued-at: block-height,
        expires-at: expires-at,
        proof-hash: proof-hash
      }
    )
    
    (ok true)
  )
)

;; Revoke a credential
(define-public (revoke-credential (credential-id uint))
  (let
    (
      (credential (unwrap! (map-get? credentials { credential-id: credential-id }) (err ERR-CREDENTIAL-NOT-FOUND)))
      (provider-mapping (unwrap! (map-get? provider-principals { principal: tx-sender }) (err ERR-PROVIDER-NOT-FOUND)))
      (provider-id (get provider-id provider-mapping))
    )
    
    ;; Check if caller is the issuer of the credential
    (asserts! (is-eq (get issuer-id credential) provider-id) (err ERR-NOT-AUTHORIZED))
    
    ;; Update credential status
    (map-set credentials
      { credential-id: credential-id }
      (merge credential {
        status: VERIFICATION-STATUS-REVOKED,
        revoked-at: (some block-height)
      })
    )
    
    (ok true)
  )
)

;; Commit an attribute for zero-knowledge verification
(define-public (commit-attribute
  (identity-id uint)
  (attribute-name (string-ascii 64))
  (attribute-hash (buff 32))
  (commitment (buff 64))
  (salt (buff 32))
)
  (let
    (
      (identity (unwrap! (get-identity identity-id) (err ERR-IDENTITY-NOT-FOUND)))
    )
    
    ;; Check if caller is the identity owner
    (asserts! (is-eq tx-sender (get owner identity)) (err ERR-NOT-AUTHORIZED))
    
    ;; Set or update committed attribute
    (map-set committed-attributes
      { identity-id: identity-id, attribute-name: attribute-name }
      {
        attribute-hash: attribute-hash,
        commitment: commitment,
        salt: salt,
        updated-at: block-height
      }
    )
    
    (ok true)
  )
)

;; Authorize selective disclosure to a specific party
(define-public (authorize-disclosure
  (identity-id uint)
  (authorized-principal principal)
  (authorized-types (list 10 uint))
  (expires-at (optional uint))
  (authorization-proof (buff 128))
)
  (let
    (
      (identity (unwrap! (get-identity identity-id) (err ERR-IDENTITY-NOT-FOUND)))
    )
    
    ;; Check if caller is the identity owner
    (asserts! (is-eq tx-sender (get owner identity)) (err ERR-NOT-AUTHORIZED))
    
    ;; Create or update disclosure authorization
    (map-set disclosure-authorizations
      { identity-id: identity-id, authorized-principal: authorized-principal }
      {
        authorized-at: block-height,
        expires-at: expires-at,
        authorized-types: authorized-types,
        authorization-proof: authorization-proof
      }
    )
    
    (ok true)
  )
)

;; Revoke disclosure authorization
(define-public (revoke-disclosure-authorization (identity-id uint) (authorized-principal principal))
  (let
    (
      (identity (unwrap! (get-identity identity-id) (err ERR-IDENTITY-NOT-FOUND)))
    )
    
    ;; Check if caller is the identity owner
    (asserts! (is-eq tx-sender (get owner identity)) (err ERR-NOT-AUTHORIZED))
    
    ;; Remove disclosure authorization
    (map-delete disclosure-authorizations { identity-id: identity-id, authorized-principal: authorized-principal })
    
    (ok true)
  )
)

;; Submit a reputation attestation
(define-public (submit-reputation-attestation
  (identity-id uint)
  (context (string-utf8 50))
  (score-change int)
  (attestation-proof (buff 128))
)
  (let
    (
      (identity (unwrap! (get-identity identity-id) (err ERR-IDENTITY-NOT-FOUND)))
      (provider-mapping (unwrap! (map-get? provider-principals { principal: tx-sender }) (err ERR-PROVIDER-NOT-FOUND)))
      (provider-id (get provider-id provider-mapping))
      (provider (unwrap! (get-provider provider-id) (err ERR-PROVIDER-NOT-FOUND)))
    )
    
    ;; Check if provider is active
    (asserts! (get is-active provider) (err ERR-NOT-AUTHORIZED))
    
    ;; Update reputation score
    (match (map-get? reputation-scores { identity-id: identity-id, context: context })
      existing-score
      (let
        (
          (new-score (+ (get score existing-score) score-change))
          (clamped-score (max (min new-score 100) 0))
          (new-count (+ (get attestation-count existing-score) u1))
        )
        (map-set reputation-scores
          { identity-id: identity-id, context: context }
          {
            score: clamped-score,
            updated-at: block-height,
            attestation-count: new-count,
            confidence-score: (min (+ (get confidence-score existing-score) u5) u100),
            proof-hash: (sha256 (concat (get proof-hash existing-score) attestation-proof))
          }
        )
      )
      ;; First attestation for this context
      (begin
        (map-set reputation-scores
          { identity-id: identity-id, context: context }
          {
            score: (if (> score-change 0) (to-uint score-change) u50), ;; Default to 50 if negative
            updated-at: block-height,
            attestation-count: u1,
            confidence-score: u10, ;; Initial confidence
            proof-hash: (sha256 attestation-proof)
          }
        )
      )
    )
    
    (ok true)
  )
)

;; Verify a credential with a provider
(define-public (verify-credential (credential-id uint) (verification-proof (buff 512)))
  (let
    (
      (credential (unwrap! (map-get? credentials { credential-id: credential-id }) (err ERR-CREDENTIAL-NOT-FOUND)))
      (provider-mapping (unwrap! (map-get? provider-principals { principal: tx-sender }) (err ERR-PROVIDER-NOT-FOUND)))
      (provider-id (get provider-id provider-mapping))
      (verification-id (var-get next-verification-id))
    )
  ;; Check if credential is not already revoked
    (asserts! (is-none (get revoked-at credential)) (err ERR-REVOKED-CREDENTIAL))
    
    ;; Check if credential is not expired
    (match (get expires-at credential)
      expiry (asserts! (< block-height expiry) (err ERR-EXPIRED-CREDENTIAL))
      true
    )
    
    ;; Create verification record
    (map-set verifications
      { verification-id: verification-id }
      {
        credential-id: credential-id,
        verifier-id: provider-id,
        verified-at: block-height,
        verification-proof: verification-proof,
        verification-status: VERIFICATION-STATUS-APPROVED,
        verification-expiry: (some (+ block-height u10950)) ;; Valid for ~3 months (assuming ~1 block/min)
      }
    )
    
    ;; Increment verification ID
    (var-set next-verification-id (+ verification-id u1))
    
    (ok verification-id)
  )
)

;; Request disclosure of specific identity attributes
;; This function simulates a request - in reality, this would trigger an off-chain flow
(define-public (request-disclosure (identity-id uint) (requested-types (list 10 uint)))
  (let
    (
      (identity (unwrap! (get-identity identity-id) (err ERR-IDENTITY-NOT-FOUND)))
    )
    
    ;; Check if disclosure is authorized
    (asserts! 
      (fold check-all-types-authorized requested-types true)
      (err ERR-DISCLOSURE-NOT-AUTHORIZED)
    )
    
    ;; This would trigger an off-chain notification/flow
    ;; Return success to simulate
    (ok true)
  )
)

;; Helper function to check if all requested types are authorized
(define-private (check-all-types-authorized (credential-type uint) (all-authorized bool))
  (if all-authorized
    (is-disclosure-authorized identity-id tx-sender credential-type)
    false
  )
)

;; Transfer ownership of the contract
(define-public (transfer-ownership (new-owner principal))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) (err ERR-NOT-AUTHORIZED))
    (var-set contract-owner new-owner)
    (ok true)
  )
)