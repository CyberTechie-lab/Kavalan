# Kavalan SIEM Firestore Security Specification (Phase 0 TDD)

## 1. Data Invariants

1. **Identity & Email Verification**: All data mutations require an authenticated Firebase user with `request.auth.token.email_verified == true`.
2. **PII Isolation**: `/users/{userId}` contains `email` and can ONLY be read (`get`) by the owning user (`request.auth.uid == userId`) or an administrator. Listing `/users` is restricted to administrators only.
3. **No Self-Assigned Privilege Escalation**: On `/users/{userId}` creation, non-admins can ONLY set `role == 'analyst'`, and `role` cannot be changed by non-admins on update. `/admins/{adminId}` can only be written by existing administrators.
4. **Strict Ownership & Immutability**: Every document in `incident_cases`, `custom_rules`, `saved_searches`, and `alert_triage` must set `ownerId == request.auth.uid` on create and preserve `ownerId` and `createdAt` immutably on update.
5. **Master Gate & Atomicity on Subcollections**: `/incident_cases/{caseId}/notes/{noteId}` cannot exist without a parent `/incident_cases/{caseId}` owned by `request.auth.uid` (or admin), verified via `get()` and `existsAfter()`, with parent `updatedAt` updated atomically (`getAfter(...).data.updatedAt == request.time`).
6. **Terminal State Locking**: Once an `IncidentCase` reaches `status == 'CLOSED'`, non-admin updates are strictly rejected.
7. **Temporal Integrity**: `createdAt` on create and `updatedAt` on update must strictly equal `request.time`.
8. **Strict Key Allowlists & Size Bounds**: Every write validates exact keys (`hasAll` + `hasOnly` on create; `affectedKeys().hasOnly(...)` on update), valid document IDs (`^[a-zA-Z0-9_\-]+$`, `<= 128`), and explicit `.size()` caps on every string.
9. **Query Enforcer (Cost-Safe `allow list`)**: Every `allow list` rule enforces `resource.data.ownerId == request.auth.uid || isBootstrappedAdmin()` with zero `get()`/`exists()` calls.

## 2. The "Dirty Dozen" Adversarial Payloads

All 12 payloads below MUST return `PERMISSION_DENIED`:

1. **Self-Assigned Admin Escalation** (`CREATE /users/attacker_uid`):
   `{"uid":"attacker_uid","email":"a@evil.test","displayName":"Mallory","role":"admin","createdAt":"<SERVER_TIME>","updatedAt":"<SERVER_TIME>"}`
2. **Shadow Field Injection on Create** (`CREATE /incident_cases/case-1`):
   `{"id":"case-1","ownerId":"u1","title":"Test","description":"","severity":"HIGH","status":"NEW","assignee":"u1","isVerified":true,"createdAt":"<SERVER_TIME>","updatedAt":"<SERVER_TIME>"}`
3. **Identity Spoofing** (`CREATE /incident_cases/case-2` as `u1`):
   `{"id":"case-2","ownerId":"victim_uid","title":"Spoof","description":"","severity":"HIGH","status":"NEW","assignee":"u1","createdAt":"<SERVER_TIME>","updatedAt":"<SERVER_TIME>"}`
4. **Unverified Admin Email Spoof** (`GET /users/victim_uid` with `email == 'shiyam2offical@gmail.com'` and `email_verified == false`):
   Must fail because `email_verified == true` is mandatory.
5. **Cross-User PII Read** (`GET /users/victim_uid` as non-admin `u1`):
   Must fail because `/users/{userId}` enforces strict owner/admin PII isolation.
6. **Blanket Collection Scrape** (`LIST /incident_cases` without `where('ownerId', '==', uid)` as `u1`):
   Must fail because `allow list` explicitly checks `resource.data.ownerId == request.auth.uid`.
7. **Document ID Poisoning** (`CREATE /saved_searches/bad..id$%20` or 200-char ID):
   Must fail `isValidId(searchId)`.
8. **Denial-of-Wallet Oversized String** (`CREATE /saved_searches/s-big`):
   `{"id":"s-big","ownerId":"u1","name":"Big","query":"<2001 chars>","description":"","createdAt":"<SERVER_TIME>","updatedAt":"<SERVER_TIME>"}`
9. **Terminal State Mutation** (`UPDATE /incident_cases/case-closed` as non-admin owner when existing `status == 'CLOSED'`):
   `{"status":"OPEN","updatedAt":"<SERVER_TIME>"}`
10. **Value Poisoning on Allowed Update Key** (`UPDATE /incident_cases/case-1`):
    `{"severity":12345,"updatedAt":"<SERVER_TIME>"}`
11. **Backdated Client Timestamp** (`CREATE /custom_rules/rule-1`):
    `{"createdAt":"2020-01-01T00:00:00Z", ...}` (does not equal `request.time`).
12. **Orphaned Subcollection Note Without Atomic Parent Update** (`CREATE /incident_cases/case-1/notes/note-1` outside a batch that updates parent `updatedAt` or targeting non-existent/foreign parent case):
    Must fail Master Gate `get()` and `getAfter()` atomicity checks.
