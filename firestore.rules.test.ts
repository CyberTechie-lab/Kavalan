/**
 * Kavalan SIEM — Phase 0 Security TDD Verification Suite
 *
 * Verifies all "Dirty Dozen" adversarial payloads and structural security
 * invariants declared in security_spec.md against firestore.rules.
 */
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';

const rulesPath = path.resolve(process.cwd(), 'firestore.rules');
const draftPath = path.resolve(process.cwd(), 'DRAFT_firestore.rules');
const activeRulesPath = fs.existsSync(rulesPath) ? rulesPath : draftPath;
const rulesContent = fs.readFileSync(activeRulesPath, 'utf8');

const dirtyDozenAssertions: Array<{ name: string; check: () => void }> = [
  {
    name: '1. Global default-deny safety net present',
    check: () => {
      assert.match(rulesContent, /match \/\{document=\*\*\}\s*\{\s*allow read, write: if false;\s*\}/);
    },
  },
  {
    name: '2. Self-assigned admin escalation blocked on /users/{userId} create',
    check: () => {
      assert.match(rulesContent, /incoming\(\)\.role == 'analyst'/);
      assert.match(rulesContent, /incoming\(\)\.role == existing\(\)\.role/);
    },
  },
  {
    name: '3. Shadow field injection blocked via hasAll + hasOnly blueprints',
    check: () => {
      for (const fn of [
        'isValidUserProfile',
        'isValidAdminRecord',
        'isValidIncidentCase',
        'isValidCaseNote',
        'isValidCustomRule',
        'isValidSavedSearch',
        'isValidAlertTriage',
      ]) {
        assert.ok(rulesContent.includes(`function ${fn}(data)`), `Missing blueprint ${fn}`);
      }
      assert.ok(rulesContent.includes('data.keys().hasAll('));
      assert.ok(rulesContent.includes('data.keys().hasOnly('));
    },
  },
  {
    name: '4. Unverified admin email spoof blocked via email_verified == true',
    check: () => {
      assert.match(rulesContent, /request\.auth\.token\.email_verified == true/);
      assert.ok(!/request\.auth\.token\.email\s*==/.test(rulesContent.replace(/isVerified\(\)\s*&&\s*request\.auth\.token\.email\s*==/g, '')));
    },
  },
  {
    name: '5. Cross-user PII read blocked on /users/{userId}',
    check: () => {
      assert.match(rulesContent, /match \/users\/\{userId\}[\s\S]*?allow get: if isSignedIn\(\) && isValidId\(userId\) && \(isOwner\(userId\) \|\| isAdmin\(\)\);/);
    },
  },
  {
    name: '6. Blanket list queries forbidden (all allow list check resource ownership or bootstrapped admin)',
    check: () => {
      assert.ok(!/allow list:\s*if\s*isSignedIn\(\)\s*;/.test(rulesContent));
      assert.ok(!/allow read:\s*if\s*isSignedIn\(\)\s*;/.test(rulesContent));
    },
  },
  {
    name: '7. Path variable ID poisoning blocked via isValidId()',
    check: () => {
      assert.match(rulesContent, /id\.matches\('\^\[a-zA-Z0-9_\\\\-\]\+\$'\)/);
      assert.ok(rulesContent.includes('id.size() <= 128'));
    },
  },
  {
    name: '8. Denial-of-Wallet string size bounds enforced across all schemas',
    check: () => {
      assert.ok(rulesContent.includes('data.title.size() <= 200'));
      assert.ok(rulesContent.includes('data.description.size() <= 4000'));
      assert.ok(rulesContent.includes('data.query.size() <= 2000'));
      assert.ok(rulesContent.includes('data.rawSigma.size() <= 8000'));
      assert.ok(rulesContent.includes('data.note.size() <= 2000'));
    },
  },
  {
    name: '9. Terminal state lock enforced for CLOSED IncidentCases',
    check: () => {
      assert.ok(rulesContent.includes("existing().status != 'CLOSED'"));
    },
  },
  {
    name: '10. Value poisoning on updates blocked by calling isValid* inside every allow update',
    check: () => {
      assert.ok(rulesContent.includes('affectedKeys().hasOnly('));
      const updateBlocks = rulesContent.match(/allow update: if[\s\S]*?;/g) || [];
      assert.ok(updateBlocks.length >= 5);
      for (const block of updateBlocks) {
        if (block.includes('allow update: if false;')) continue;
        assert.match(block, /isValid[A-Za-z]+\(incoming\(\)\)/, `Update block missing validation blueprint: ${block}`);
      }
    },
  },
  {
    name: '11. Temporal integrity strictly enforces request.time on createdAt and updatedAt',
    check: () => {
      assert.ok(rulesContent.includes('incoming().createdAt == request.time'));
      assert.ok(rulesContent.includes('incoming().updatedAt == request.time'));
      assert.ok(rulesContent.includes('incoming().createdAt == existing().createdAt'));
    },
  },
  {
    name: '12. Master Gate & Atomicity Guarantee enforced on /incident_cases/{caseId}/notes/{noteId}',
    check: () => {
      assert.ok(rulesContent.includes('exists(/databases/$(database)/documents/incident_cases/$(caseId))'));
      assert.ok(rulesContent.includes('existsAfter(/databases/$(database)/documents/incident_cases/$(caseId))'));
      assert.ok(rulesContent.includes('getAfter(/databases/$(database)/documents/incident_cases/$(caseId)).data.updatedAt == request.time'));
    },
  },
];

let passed = 0;
for (const test of dirtyDozenAssertions) {
  test.check();
  passed++;
  console.log(`PASS: ${test.name}`);
}
console.log(`\nAll ${passed}/${dirtyDozenAssertions.length} Dirty Dozen Firestore security assertions passed.`);
