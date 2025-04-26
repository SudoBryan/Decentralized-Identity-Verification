import { Clarinet, Tx, Chain, Account, types } from 'https://deno.land/x/clarinet@v0.14.0/index.ts';
import { assertEquals } from 'https://deno.land/std@0.90.0/testing/asserts.ts';

// Test constants
const ERR_NOT_AUTHORIZED = 1;
const ERR_IDENTITY_NOT_FOUND = 2;
const ERR_PROVIDER_NOT_FOUND = 3;
const ERR_CREDENTIAL_NOT_FOUND = 4;
const ERR_INVALID_PROOF = 5;
const ERR_EXPIRED_CREDENTIAL = 6;
const ERR_ALREADY_EXISTS = 7;
const ERR_REVOKED_CREDENTIAL = 8;
const ERR_INVALID_SIGNATURE = 9;
const ERR_INVALID_PARAMETERS = 10;
const ERR_VERIFICATION_FAILED = 11;
const ERR_DISCLOSURE_NOT_AUTHORIZED = 12;
const ERR_REPUTATION_NOT_FOUND = 13;

// Credential type constants
const CREDENTIAL_TYPE_IDENTITY = 1;
const CREDENTIAL_TYPE_AGE = 2;
const CREDENTIAL_TYPE_ADDRESS = 3;
const CREDENTIAL_TYPE_EDUCATION = 4;
const CREDENTIAL_TYPE_EMPLOYMENT = 5;
const CREDENTIAL_TYPE_FINANCIAL = 6;
const CREDENTIAL_TYPE_GOVERNMENT_ID = 7;
const CREDENTIAL_TYPE_HEALTH = 8;
const CREDENTIAL_TYPE_REPUTATION = 9;

// Verification status constants
const VERIFICATION_STATUS_PENDING = 1;
const VERIFICATION_STATUS_APPROVED = 2;
const VERIFICATION_STATUS_REJECTED = 3;
const VERIFICATION_STATUS_REVOKED = 4;

Clarinet.test({
  name: "Can register identity provider and create identity",
  async fn(chain: Chain, accounts: Map<string, Account>) {
    const deployer = accounts.get('deployer')!;
    const user1 = accounts.get('wallet_1')!;
    
    // Register identity provider (by contract owner)
    let block = chain.mineBlock([
      Tx.contractCall(
        'decentralized-identity-verification',
        'register-provider',
        [
          types.utf8("Gov ID Authority"),
          types.buff(new Uint8Array(33).fill(1)), // Public key (mock)
          types.utf8("https://gov-id.example.com"),
          types.utf8("government"),
        ],
        deployer.address
      )
    ]);
    
    // Check that provider registration succeeded
    assertEquals(block.receipts.length, 1);
    assertEquals(block.receipts[0].result, '(ok u1)'); // First provider ID is 1
    
    // User creates identity
    block = chain.mineBlock([
      Tx.contractCall(
        'decentralized-identity-verification',
        'create-identity',
        [
          types.buff(new Uint8Array(32).fill(2)), // Identity hash (mock)
          types.some(types.utf8("ipfs://QmHash")), // Metadata URI
        ],
        user1.address
      )
    ]);
    
    // Check that identity creation succeeded
    assertEquals(block.receipts.length, 1);
    assertEquals(block.receipts[0].result, '(ok u1)'); // First identity ID is 1
    
    // Check identity details
    let identityCall = chain.callReadOnlyFn(
      'decentralized-identity-verification',
      'get-identity',
      [types.uint(1)],
      deployer.address
    );
    
    let identity = identityCall.result.expectTuple();
    assertEquals(identity.owner, user1.address);
    assertEquals(identity['is-active'], types.bool(true));
    assertEquals(identity['verification-level'], types.uint(1)); // Initial level
  },
});

Clarinet.test({
  name: "Prevents unauthorized provider registration",
  async fn(chain: Chain, accounts: Map<string, Account>) {
    const randomUser = accounts.get('wallet_1')!;
    
    // Try to register provider without being contract owner
    let block = chain.mineBlock([
      Tx.contractCall(
        'decentralized-identity-verification',
        'register-provider',
        [
          types.utf8("Fake Authority"),
          types.buff(new Uint8Array(33).fill(1)), // Public key (mock)
          types.utf8("https://fake.example.com"),
          types.utf8("fake"),
        ],
        randomUser.address
      )

    ]);
    
    // Check that provider registration failed
    assertEquals(block.receipts.length, 1);
    assertEquals(block.receipts[0].result, `(err u${ERR_NOT_AUTHORIZED})`);
  },
});

Clarinet.test({
  name: "Can issue credentials for an identity",
  async fn(chain: Chain, accounts: Map<string, Account>) {
    const deployer = accounts.get('deployer')!;
    const user1 = accounts.get('wallet_1')!;
    
    // Setup - Register provider and create identity
    let setupBlock = chain.mineBlock([
      // Register provider
      Tx.contractCall(
        'decentralized-identity-verification',
        'register-provider',
        [
          types.utf8("Gov ID Authority"),
          types.buff(new Uint8Array(33).fill(1)), // Public key (mock)
          types.utf8("https://gov-id.example.com"),
          types.utf8("government"),
        ],
        deployer.address
      ),
      // Create identity
      Tx.contractCall(
        'decentralized-identity-verification',
        'create-identity',
        [
          types.buff(new Uint8Array(32).fill(2)), // Identity hash (mock)
          types.some(types.utf8("ipfs://QmHash")), // Metadata URI
        ],
        user1.address
      )
    ]);
    
    // Provider issues a government ID credential
    let issueBlock = chain.mineBlock([
      Tx.contractCall(
        'decentralized-identity-verification',
        'issue-credential',
        [
          types.uint(1), // identity-id
          types.uint(CREDENTIAL_TYPE_GOVERNMENT_ID), // credential-type
          types.buff(new Uint8Array(32).fill(3)), // credential-hash
          types.buff(new Uint8Array(512).fill(4)), // verification-proof
          types.some(types.uint(100000)), // expires-at (far in the future)
        ],
        deployer.address // Provider is the deployer in this case
      )
    ]);
    
    // Check that credential issuance succeeded
    assertEquals(issueBlock.receipts.length, 1);
    assertEquals(issueBlock.receipts[0].result, '(ok u1)'); // First credential ID is 1
    
    // Check credential details
    let credentialCall = chain.callReadOnlyFn(
      'decentralized-identity-verification',
      'get-credential',
      [types.uint(1)],
      deployer.address
    );
    
    let credential = credentialCall.result.expectTuple();
    assertEquals(credential['identity-id'], types.uint(1));
    assertEquals(credential['credential-type'], types.uint(CREDENTIAL_TYPE_GOVERNMENT_ID));
    assertEquals(credential['issuer-id'], types.uint(1));
    assertEquals(credential.status, types.uint(VERIFICATION_STATUS_APPROVED));
    
    // Check if credential is valid
    let validityCheck = chain.callReadOnlyFn(
      'decentralized-identity-verification',
      'is-credential-valid',
      [types.uint(1)],
      deployer.address
    );
    
    assertEquals(validityCheck.result, types.bool(true));
  },
});

Clarinet.test({
  name: "Can issue and verify age proofs",
  async fn(chain: Chain, accounts: Map<string, Account>) {
    const deployer = accounts.get('deployer')!;
    const user1 = accounts.get('wallet_1')!;
    
    // Setup - Register provider and create identity
    let setupBlock = chain.mineBlock([
      // Register provider
      Tx.contractCall(
        'decentralized-identity-verification',
        'register-provider',
        [
          types.utf8("Age Verification Authority"),
          types.buff(new Uint8Array(33).fill(1)), // Public key (mock)
          types.utf8("https://age-verify.example.com"),
          types.utf8("government"),
        ],
        deployer.address
      ),
      // Create identity
      Tx.contractCall(
        'decentralized-identity-verification',
        'create-identity',
        [
          types.buff(new Uint8Array(32).fill(2)), // Identity hash (mock)
          types.some(types.utf8("ipfs://QmHash")), // Metadata URI
        ],
        user1.address
      )
    ]);
    
    // Provider issues an age proof
    let ageProofBlock = chain.mineBlock([
      Tx.contractCall(
        'decentralized-identity-verification',
        'issue-age-proof',
        [
          types.uint(1), // identity-id
          types.bool(true), // age-over-18
          types.bool(true), // age-over-21
          types.bool(false), // age-over-65
          types.buff(new Uint8Array(32).fill(5)), // proof-hash
          types.some(types.uint(100000)), // expires-at (far in the future)
        ],
        deployer.address // Provider is the deployer
      )
    ]);
    
    // Check that age proof issuance succeeded
    assertEquals(ageProofBlock.receipts.length, 1);
    assertEquals(ageProofBlock.receipts[0].result, '(ok true)');
    
    // Verify over-18 check
    let over18Check = chain.callReadOnlyFn(
      'decentralized-identity-verification',
      'verify-age-over',
      [types.uint(1), types.uint(18)],
      deployer.address
    );
    
    assertEquals(over18Check.result, '(ok true)');
    
    // Verify over-21 check
    let over21Check = chain.callReadOnlyFn(
      'decentralized-identity-verification',
      'verify-age-over',
      [types.uint(1), types.uint(21)],
      deployer.address
    );
    
    assertEquals(over21Check.result, '(ok true)');
    
    // Verify over-65 check (should be false)
    let over65Check = chain.callReadOnlyFn(
      'decentralized-identity-verification',
      'verify-age-over',
      [types.uint(1), types.uint(65)],
      deployer.address
    );
    
    assertEquals(over65Check.result, '(ok false)');
  },
});

Clarinet.test({
  name: "Can revoke credentials",
  async fn(chain: Chain, accounts: Map<string, Account>) {
    const deployer = accounts.get('deployer')!;
    const user1 = accounts.get('wallet_1')!;
    
    // Setup - Register provider, create identity, issue credential
    let setupBlock = chain.mineBlock([
      // Register provider
      Tx.contractCall(
        'decentralized-identity-verification',
        'register-provider',
        [
          types.utf8("Credential Authority"),
          types.buff(new Uint8Array(33).fill(1)), // Public key (mock)
          types.utf8("https://creds.example.com"),
          types.utf8("educational"),
        ],
        deployer.address
      ),
      // Create identity
      Tx.contractCall(
        'decentralized-identity-verification',
        'create-identity',
        [
          types.buff(new Uint8Array(32).fill(2)), // Identity hash (mock)
          types.some(types.utf8("ipfs://QmHash")), // Metadata URI
        ],
        user1.address
      ),
      // Issue credential
      Tx.contractCall(
        'decentralized-identity-verification',
        'issue-credential',
        [
          types.uint(1), // identity-id
          types.uint(CREDENTIAL_TYPE_EDUCATION), // credential-type
          types.buff(new Uint8Array(32).fill(3)), // credential-hash
          types.buff(new Uint8Array(512).fill(4)), // verification-proof
          types.some(types.uint(100000)), // expires-at
        ],
        deployer.address
      )
    ]);
    
    // Check credential is valid before revocation
    let validityBeforeRevoke = chain.callReadOnlyFn(
      'decentralized-identity-verification',
      'is-credential-valid',
      [types.uint(1)],
      deployer.address
    );
    
    assertEquals(validityBeforeRevoke.result, types.bool(true));
    
    // Revoke the credential
    let revokeBlock = chain.mineBlock([
      Tx.contractCall(
        'decentralized-identity-verification',
        'revoke-credential',
        [
          types.uint(1), // credential-id
        ],
        deployer.address // Provider who issued the credential
      )
    ]);
     // Check that revocation succeeded
     assertEquals(revokeBlock.receipts.length, 1);
     assertEquals(revokeBlock.receipts[0].result, '(ok true)');
     
     // Check credential is no longer valid after revocation
     let validityAfterRevoke = chain.callReadOnlyFn(
       'decentralized-identity-verification',
       'is-credential-valid',
       [types.uint(1)],
       deployer.address
     );
     
     assertEquals(validityAfterRevoke.result, types.bool(false));
   },
 });
 
 Clarinet.test({
   name: "Can manage selective disclosure authorizations",
   async fn(chain: Chain, accounts: Map<string, Account>) {
     const deployer = accounts.get('deployer')!;
     const user1 = accounts.get('wallet_1')!;
     const verifier = accounts.get('wallet_2')!;
     
     // Setup - Create identity
     let setupBlock = chain.mineBlock([
       // Create identity
       Tx.contractCall(
         'decentralized-identity-verification',
         'create-identity',
         [
           types.buff(new Uint8Array(32).fill(2)), // Identity hash (mock)
           types.some(types.utf8("ipfs://QmHash")), // Metadata URI
         ],
         user1.address
       )
     ]);
     
     // User authorizes disclosure of certain credential types to a verifier
     let authorizeBlock = chain.mineBlock([
       Tx.contractCall(
         'decentralized-identity-verification',
         'authorize-disclosure',
         [
           types.uint(1), // identity-id
           types.principal(verifier.address), // authorized-principal
           types.list([
             types.uint(CREDENTIAL_TYPE_AGE),
             types.uint(CREDENTIAL_TYPE_EDUCATION)
           ]), // authorized-types
           types.some(types.uint(100000)), // expires-at
           types.buff(new Uint8Array(128).fill(6)), // authorization-proof
         ],
         user1.address // Identity owner
       )
     ]);
     
     // Check that authorization succeeded
     assertEquals(authorizeBlock.receipts.length, 1);
     assertEquals(authorizeBlock.receipts[0].result, '(ok true)');
     
     // Check if disclosure is authorized for specific types
     let ageAuthCheck = chain.callReadOnlyFn(
       'decentralized-identity-verification',
       'is-disclosure-authorized',
       [
         types.uint(1), // identity-id
         types.principal(verifier.address), // requestor
         types.uint(CREDENTIAL_TYPE_AGE), // credential-type
       ],
       deployer.address
     );
     
     assertEquals(ageAuthCheck.result, types.bool(true));
     
     // Check if unauthorized type is correctly rejected
     let healthAuthCheck = chain.callReadOnlyFn(
       'decentralized-identity-verification',
       'is-disclosure-authorized',
       [
         types.uint(1), // identity-id
         types.principal(verifier.address), // requestor
         types.uint(CREDENTIAL_TYPE_HEALTH), // credential-type (not authorized)
       ],
       deployer.address
     );
     
     assertEquals(healthAuthCheck.result, types.bool(false));
     
     // Revoke the authorization
     let revokeBlock = chain.mineBlock([
       Tx.contractCall(
         'decentralized-identity-verification',
         'revoke-disclosure-authorization',
         [
           types.uint(1), // identity-id
           types.principal(verifier.address), // authorized-principal
         ],
         user1.address // Identity owner
       )
     ]);
     
     // Check that revocation succeeded
     assertEquals(revokeBlock.receipts.length, 1);
     assertEquals(revokeBlock.receipts[0].result, '(ok true)');
     
     // Verify authorization is revoked
     let ageAuthCheckAfterRevoke = chain.callReadOnlyFn(
       'decentralized-identity-verification',
       'is-disclosure-authorized',
       [
         types.uint(1), // identity-id
         types.principal(verifier.address), // requestor
         types.uint(CREDENTIAL_TYPE_AGE), // credential-type
       ],
       deployer.address
     );
     
     assertEquals(ageAuthCheckAfterRevoke.result, types.bool(false));
   },
 });
 
 Clarinet.test({
   name: "Can commit and verify attributes",
   async fn(chain: Chain, accounts: Map<string, Account>) {
     const deployer = accounts.get('deployer')!;
     const user1 = accounts.get('wallet_1')!;
     
     // Setup - Create identity
     let setupBlock = chain.mineBlock([
       // Create identity
       Tx.contractCall(
         'decentralized-identity-verification',
         'create-identity',
         [
           types.buff(new Uint8Array(32).fill(2)), // Identity hash (mock)
           types.some(types.utf8("ipfs://QmHash")), // Metadata URI
         ],
         user1.address
       )
     ]);
     
     // Commit an attribute (e.g., hashed address)
     let attributeHash = new Uint8Array(32).fill(7);
     let commitBlock = chain.mineBlock([
       Tx.contractCall(
         'decentralized-identity-verification',
         'commit-attribute',
         [
           types.uint(1), // identity-id
           types.ascii("home_address"), // attribute-name
           types.buff(attributeHash), // attribute-hash
           types.buff(new Uint8Array(64).fill(8)), // commitment
           types.buff(new Uint8Array(32).fill(9)), // salt
         ],
         user1.address // Identity owner
       )
     ]);
     
     // Check that commitment succeeded
     assertEquals(commitBlock.receipts.length, 1);
     assertEquals(commitBlock.receipts[0].result, '(ok true)');
     
     // Verify attribute match (should be true)
     let matchCheckTrue = chain.callReadOnlyFn(
       'decentralized-identity-verification',
       'verify-attribute-match',
       [
         types.uint(1), // identity-id
         types.ascii("home_address"), // attribute-name
         types.buff(attributeHash), // expected-hash (matching)
       ],
       deployer.address
     );
     
     assertEquals(matchCheckTrue.result, types.bool(true));
     
     // Verify attribute mismatch (should be false)
     let wrongHash = new Uint8Array(32).fill(10);
     let matchCheckFalse = chain.callReadOnlyFn(
       'decentralized-identity-verification',
       'verify-attribute-match',
       [
         types.uint(1), // identity-id
         types.ascii("home_address"), // attribute-name
         types.buff(wrongHash), // expected-hash (non-matching)
       ],
       deployer.address
     );
     
     assertEquals(matchCheckFalse.result, types.bool(false));
   },
 });
 
 Clarinet.test({
   name: "Can submit and query reputation attestations",
   async fn(chain: Chain, accounts: Map<string, Account>) {
     const deployer = accounts.get('deployer')!;
     const user1 = accounts.get('wallet_1')!;
     
     // Setup - Register provider and create identity
     let setupBlock = chain.mineBlock([
       // Register provider
       Tx.contractCall(
         'decentralized-identity-verification',
         'register-provider',
         [
           types.utf8("Reputation Authority"),
           types.buff(new Uint8Array(33).fill(1)), // Public key (mock)
           types.utf8("https://rep.example.com"),
           types.utf8("reputation"),
         ],
         deployer.address
       ),
       // Create identity
       Tx.contractCall(
         'decentralized-identity-verification',
         'create-identity',
         [
           types.buff(new Uint8Array(32).fill(2)), // Identity hash (mock)
           types.some(types.utf8("ipfs://QmHash")), // Metadata URI
         ],
         user1.address
       )
     ]);
     
     // Submit a positive reputation attestation
     let attestBlock = chain.mineBlock([
       Tx.contractCall(
         'decentralized-identity-verification',
         'submit-reputation-attestation',
         [
           types.uint(1), // identity-id
           types.utf8("marketplace"), // context
           types.int(10), // score-change (positive)
           types.buff(new Uint8Array(128).fill(11)), // attestation-proof
         ],
         deployer.address // Provider is the attestor
       )
     ]);
     
     // Check that attestation succeeded
     assertEquals(attestBlock.receipts.length, 1);
     assertEquals(attestBlock.receipts[0].result, '(ok true)');
     
     // Query reputation score
     let reputationCall = chain.callReadOnlyFn(
       'decentralized-identity-verification',
       'get-reputation',
       [
         types.uint(1), // identity-id
         types.utf8("marketplace"), // context
       ],
       deployer.address
     );
     
     let reputation = reputationCall.result.expectSome().expectTuple();
     assertEquals(reputation.score, types.uint(10)); // Should be 10 from our attestation
     assertEquals(reputation['attestation-count'], types.uint(1)); // One attestation so far
     
     // Submit another attestation
     let attestBlock2 = chain.mineBlock([
       Tx.contractCall(
         'decentralized-identity-verification',
         'submit-reputation-attestation',
         [
           types.uint(1), // identity-id
           types.utf8("marketplace"), // context
           types.int(5), // score-change (another positive)
           types.buff(new Uint8Array(128).fill(12)), // attestation-proof
         ],
         deployer.address // Provider is the attestor
       )
     ]);
     
     // Query updated reputation score
     let updatedReputationCall = chain.callReadOnlyFn(
       'decentralized-identity-verification',
       'get-reputation',
       [
         types.uint(1), // identity-id
         types.utf8("marketplace"), // context
       ],
       deployer.address
     );
     
     let updatedReputation = updatedReputationCall.result.expectSome().expectTuple();
     assertEquals(updatedReputation.score, types.uint(15)); // Should be 10 + 5 = 15
     assertEquals(updatedReputation['attestation-count'], types.uint(2)); // Two attestations now
   },
 });
 
 Clarinet.test({
   name: "Can verify credentials with another provider",
   async fn(chain: Chain, accounts: Map<string, Account>) {
     const deployer = accounts.get('deployer')!; // First provider
     const secondProvider = accounts.get('wallet_2')!;
     const user1 = accounts.get('wallet_1')!;
     
     // Setup - Register providers, create identity, issue credential
     let setupBlock = chain.mineBlock([
       // Register first provider
       Tx.contractCall(
         'decentralized-identity-verification',
         'register-provider',
         [
           types.utf8("Primary Authority"),
           types.buff(new Uint8Array(33).fill(1)), // Public key (mock)
           types.utf8("https://primary.example.com"),
           types.utf8("government"),
         ],
         deployer.address
       ),
       // Register second provider
       Tx.contractCall(
         'decentralized-identity-verification',
         'register-provider',
         [
           types.utf8("Secondary Verifier"),
           types.buff(new Uint8Array(33).fill(2)), // Public key (mock)
           types.utf8("https://secondary.example.com"),
           types.utf8("commercial"),
         ],
         secondProvider.address // Note: this would normally be done by deployer/owner
       ),
       // Create identity
       Tx.contractCall(
         'decentralized-identity-verification',
         'create-identity',
         [
           types.buff(new Uint8Array(32).fill(2)), // Identity hash (mock)
           types.some(types.utf8("ipfs://QmHash")), // Metadata URI
         ],
         user1.address
       ),
       // Primary provider issues a credential
       Tx.contractCall(
         'decentralized-identity-verification',
         'issue-credential',
         [
           types.uint(1), // identity-id
           types.uint(CREDENTIAL_TYPE_GOVERNMENT_ID), // credential-type
           types.buff(new Uint8Array(32).fill(3)), // credential-hash
           types.buff(new Uint8Array(512).fill(4)), // verification-proof
           types.some(types.uint(100000)), // expires-at
         ],
         deployer.address // First provider issues
       )
     ]);
     
     // Second provider verifies the credential
     let verifyBlock = chain.mineBlock([
       Tx.contractCall(
         'decentralized-identity-verification',
         'verify-credential',
         [
           types.uint(1), // credential-id
           types.buff(new Uint8Array(512).fill(13)), // verification-proof
         ],
         secondProvider.address // Second provider verifies
       )
     ]);
     
     // Check that verification succeeded
     assertEquals(verifyBlock.receipts.length, 1);
     assertEquals(verifyBlock.receipts[0].result, '(ok u1)'); // First verification ID is 1
   },
 });
 
 Clarinet.test({
   name: "Enforces owner-only identity operations",
   async fn(chain: Chain, accounts: Map<string, Account>) {
     const deployer = accounts.get('deployer')!;
     const user1 = accounts.get('wallet_1')!;
     const attacker = accounts.get('wallet_3')!;
     
     // Setup - Create identity
     let setupBlock = chain.mineBlock([
       // Create identity
       Tx.contractCall(
         'decentralized-identity-verification',
         'create-identity',
         [
           types.buff(new Uint8Array(32).fill(2)), // Identity hash (mock)
           types.some(types.utf8("ipfs://QmHash")), // Metadata URI
         ],
         user1.address
       )
     ]);
     
     // Attacker tries to commit an attribute to user1's identity
     let attackBlock = chain.mineBlock([
       Tx.contractCall(
         'decentralized-identity-verification',
         'commit-attribute',
         [
           types.uint(1), // identity-id
           types.ascii("compromised_data"), // attribute-name
           types.buff(new Uint8Array(32).fill(7)), // attribute-hash
           types.buff(new Uint8Array(64).fill(8)), // commitment
           types.buff(new Uint8Array(32).fill(9)), // salt
         ],
         attacker.address // Attacker, not the identity owner
       )
     ]);
     
     // Check that the operation failed due to not being authorized
     assertEquals(attackBlock.receipts.length, 1);
     assertEquals(attackBlock.receipts[0].result, `(err u${ERR_NOT_AUTHORIZED})`);
     
     // Attacker tries to authorize disclosure on user1's identity
     let attackBlock2 = chain.mineBlock([
       Tx.contractCall(
         'decentralized-identity-verification',
         'authorize-disclosure',
         [
           types.uint(1), // identity-id
           types.principal(attacker.address), // authorized-principal
           types.list([types.uint(CREDENTIAL_TYPE_FINANCIAL)]), // authorized-types
           types.none(), // expires-at
           types.buff(new Uint8Array(128).fill(6)), // authorization-proof
         ],
         attacker.address // Attacker, not the identity owner
       )
     ]);
     
     // Check that the operation failed due to not being authorized
     assertEquals(attackBlock2.receipts.length, 1);
     assertEquals(attackBlock2.receipts[0].result, `(err u${ERR_NOT_AUTHORIZED})`);
   },
 });