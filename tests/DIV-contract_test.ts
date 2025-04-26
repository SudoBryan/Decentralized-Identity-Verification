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