import { User } from 'firebase/auth';
import {
  collection,
  deleteDoc,
  doc,
  getDoc,
  getDocs,
  onSnapshot,
  query,
  serverTimestamp,
  setDoc,
  Timestamp,
  Unsubscribe,
  updateDoc,
  where,
  writeBatch,
} from 'firebase/firestore';
import { auth, db, handleFirestoreError, OperationType } from './firebase.ts';

const BOOTSTRAPPED_ADMIN_EMAIL = 'shiyam2offical@gmail.com';
const ID_PATTERN = /^[a-zA-Z0-9_-]+$/;

export function sanitizeId(raw: string, fallbackPrefix = 'doc'): string {
  const cleaned = String(raw || '')
    .trim()
    .replace(/[^a-zA-Z0-9_-]/g, '_')
    .slice(0, 128);
  if (cleaned.length > 0 && ID_PATTERN.test(cleaned)) {
    return cleaned;
  }
  return `${fallbackPrefix}_${Date.now()}`;
}

function clampString(val: unknown, maxLen: number, fallback = ''): string {
  const s = String(val ?? fallback).trim();
  if (!s && fallback) return fallback.slice(0, maxLen);
  return s.slice(0, maxLen);
}

function clampNonEmpty(val: unknown, maxLen: number, fallback: string): string {
  const s = String(val ?? '').trim();
  return (s.length > 0 ? s : fallback).slice(0, maxLen);
}

function timestampToUnix(ts: unknown): number {
  if (ts instanceof Timestamp) {
    return Math.floor(ts.toMillis() / 1000);
  }
  if (typeof ts === 'number' && Number.isFinite(ts)) {
    return ts;
  }
  return Math.floor(Date.now() / 1000);
}

const VALID_SEVERITIES = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']);
const VALID_CASE_STATUSES = new Set(['NEW', 'OPEN', 'IN_PROGRESS', 'CONTAINED', 'RESOLVED', 'CLOSED']);
const VALID_TRIAGE_STATUSES = new Set(['open', 'suppressed', 'closed']);
const VALID_FEEDBACK = new Set(['none', 'true_positive', 'false_positive', 'benign_positive']);

export interface HydratedCloudPayload {
  cases: Array<{
    id: string;
    title: string;
    description: string;
    severity: string;
    status: string;
    assignee: string;
    created_at: number;
    updated_at: number;
    notes: Array<{ id: string; author: string; note: string; created_at: number }>;
  }>;
  custom_rules: Array<{
    id: number;
    name: string;
    title: string;
    description: string;
    level: number;
    log_type: string;
    enabled: boolean;
    raw_sigma: string;
    created_at: number;
    updated_at: number;
  }>;
  saved_searches: Array<{
    id: string;
    name: string;
    query: string;
    description: string;
    created_at: number;
  }>;
  alert_triage: Array<{
    campaign_key: string;
    triage_status: 'open' | 'suppressed' | 'closed';
    feedback: string;
    feedback_note: string;
  }>;
}

export async function ensureUserProfile(user: User): Promise<void> {
  if (!user.uid || !user.email) return;
  const uid = sanitizeId(user.uid, 'usr');
  const path = `users/${uid}`;
  const ref = doc(db, 'users', uid);
  const displayName = clampNonEmpty(user.displayName || user.email.split('@')[0], 120, 'SOC Operator');
  const email = clampNonEmpty(user.email, 254, 'operator@kavalan.local');
  const defaultRole =
    user.emailVerified && user.email === BOOTSTRAPPED_ADMIN_EMAIL ? 'admin' : 'analyst';

  try {
    const snap = await getDoc(ref);
    if (!snap.exists()) {
      await setDoc(ref, {
        uid,
        email,
        displayName,
        role: defaultRole,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
    } else {
      await updateDoc(ref, {
        displayName,
        updatedAt: serverTimestamp(),
      });
    }
  } catch (error) {
    handleFirestoreError(error, OperationType.WRITE, path);
  }
}

export async function syncCaseCreate(input: {
  id: string;
  title: string;
  description?: string;
  severity?: string;
  status?: string;
  assignee?: string;
}): Promise<void> {
  const user = auth.currentUser;
  if (!user) return;
  const caseId = sanitizeId(input.id, 'CASE');
  const path = `incident_cases/${caseId}`;
  const severity = VALID_SEVERITIES.has(String(input.severity || '').toUpperCase())
    ? String(input.severity).toUpperCase()
    : 'HIGH';
  const status = VALID_CASE_STATUSES.has(String(input.status || '').toUpperCase())
    ? String(input.status).toUpperCase()
    : 'NEW';

  try {
    await setDoc(doc(db, 'incident_cases', caseId), {
      id: caseId,
      ownerId: user.uid,
      title: clampNonEmpty(input.title, 200, 'Security Incident Investigation'),
      description: clampString(input.description, 4000, ''),
      severity,
      status,
      assignee: clampNonEmpty(input.assignee, 120, 'Unassigned'),
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.CREATE, path);
  }
}

export async function syncCaseUpdate(
  rawCaseId: string,
  updates: {
    status?: string;
    assignee?: string;
    severity?: string;
    title?: string;
    description?: string;
  }
): Promise<void> {
  const user = auth.currentUser;
  if (!user) return;
  const caseId = sanitizeId(rawCaseId, 'CASE');
  const path = `incident_cases/${caseId}`;
  const ref = doc(db, 'incident_cases', caseId);

  try {
    const snap = await getDoc(ref);
    if (!snap.exists()) {
      await syncCaseCreate({
        id: caseId,
        title: updates.title || `Incident ${caseId}`,
        description: updates.description || '',
        severity: updates.severity || 'HIGH',
        status: updates.status || 'OPEN',
        assignee: updates.assignee || 'Unassigned',
      });
      return;
    }

    const patch: Record<string, any> = { updatedAt: serverTimestamp() };
    if (updates.status && VALID_CASE_STATUSES.has(updates.status.toUpperCase())) {
      patch.status = updates.status.toUpperCase();
    }
    if (updates.assignee !== undefined) {
      patch.assignee = clampNonEmpty(updates.assignee, 120, 'Unassigned');
    }
    if (updates.severity && VALID_SEVERITIES.has(updates.severity.toUpperCase())) {
      patch.severity = updates.severity.toUpperCase();
    }
    await updateDoc(ref, patch);
  } catch (error) {
    handleFirestoreError(error, OperationType.UPDATE, path);
  }
}

export async function syncCaseNoteAtomic(
  rawCaseId: string,
  noteText: string,
  author: string,
  fallbackCase?: { title?: string; severity?: string; status?: string; assignee?: string }
): Promise<void> {
  const user = auth.currentUser;
  if (!user) return;
  const caseId = sanitizeId(rawCaseId, 'CASE');
  const noteId = sanitizeId(`note_${Date.now()}_${Math.floor(Math.random() * 10000)}`, 'note');
  const path = `incident_cases/${caseId}/notes/${noteId}`;
  const caseRef = doc(db, 'incident_cases', caseId);
  const noteRef = doc(db, 'incident_cases', caseId, 'notes', noteId);

  try {
    const existingCase = await getDoc(caseRef);
    if (!existingCase.exists()) {
      await syncCaseCreate({
        id: caseId,
        title: fallbackCase?.title || `Incident ${caseId}`,
        description: '',
        severity: fallbackCase?.severity || 'HIGH',
        status: fallbackCase?.status || 'OPEN',
        assignee: fallbackCase?.assignee || 'Unassigned',
      });
    }

    const batch = writeBatch(db);
    batch.update(caseRef, { updatedAt: serverTimestamp() });
    batch.set(noteRef, {
      id: noteId,
      caseId,
      ownerId: user.uid,
      author: clampNonEmpty(author, 120, user.displayName || 'SOC Analyst'),
      note: clampNonEmpty(noteText, 2000, 'Investigation note'),
      createdAt: serverTimestamp(),
    });
    await batch.commit();
  } catch (error) {
    handleFirestoreError(error, OperationType.CREATE, path);
  }
}

export async function syncRuleSave(rule: {
  id: number | string;
  name: string;
  title?: string;
  description?: string;
  level?: number;
  log_type?: string;
  enabled?: boolean;
  raw_sigma?: string;
}): Promise<void> {
  const user = auth.currentUser;
  if (!user) return;
  const numericId = Math.max(1, Math.min(9999999, Number(rule.id) || Date.now() % 900000 + 100000));
  const ruleId = sanitizeId(`rule_${numericId}`, 'rule');
  const path = `custom_rules/${ruleId}`;
  const ref = doc(db, 'custom_rules', ruleId);

  try {
    const snap = await getDoc(ref);
    const level = Math.max(1, Math.min(15, Number(rule.level) || 7));
    if (!snap.exists()) {
      await setDoc(ref, {
        id: ruleId,
        ownerId: user.uid,
        ruleNumericId: numericId,
        name: clampNonEmpty(rule.name, 120, `rule_${numericId}`),
        title: clampNonEmpty(rule.title || rule.name, 200, `Custom Rule ${numericId}`),
        description: clampString(rule.description, 2000, ''),
        level,
        logType: clampNonEmpty(rule.log_type, 64, '*'),
        enabled: rule.enabled !== false,
        rawSigma: clampString(rule.raw_sigma, 8000, ''),
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
    } else {
      await updateDoc(ref, {
        name: clampNonEmpty(rule.name, 120, `rule_${numericId}`),
        title: clampNonEmpty(rule.title || rule.name, 200, `Custom Rule ${numericId}`),
        description: clampString(rule.description, 2000, ''),
        level,
        logType: clampNonEmpty(rule.log_type, 64, '*'),
        enabled: rule.enabled !== false,
        rawSigma: clampString(rule.raw_sigma, 8000, ''),
        updatedAt: serverTimestamp(),
      });
    }
  } catch (error) {
    handleFirestoreError(error, OperationType.WRITE, path);
  }
}

export async function syncRuleToggle(numericId: number | string, enabled: boolean): Promise<void> {
  const user = auth.currentUser;
  if (!user) return;
  const ruleId = sanitizeId(`rule_${numericId}`, 'rule');
  const path = `custom_rules/${ruleId}`;
  try {
    const ref = doc(db, 'custom_rules', ruleId);
    const snap = await getDoc(ref);
    if (!snap.exists()) return;
    await updateDoc(ref, {
      enabled: Boolean(enabled),
      updatedAt: serverTimestamp(),
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.UPDATE, path);
  }
}

export async function syncRuleDelete(numericId: number | string): Promise<void> {
  const user = auth.currentUser;
  if (!user) return;
  const ruleId = sanitizeId(`rule_${numericId}`, 'rule');
  const path = `custom_rules/${ruleId}`;
  try {
    await deleteDoc(doc(db, 'custom_rules', ruleId));
  } catch (error) {
    handleFirestoreError(error, OperationType.DELETE, path);
  }
}

export async function syncSavedSearchSave(search: {
  id: string;
  name: string;
  query: string;
  description?: string;
}): Promise<void> {
  const user = auth.currentUser;
  if (!user) return;
  const searchId = sanitizeId(search.id, 'SRCH');
  const path = `saved_searches/${searchId}`;
  const ref = doc(db, 'saved_searches', searchId);

  try {
    const snap = await getDoc(ref);
    if (!snap.exists()) {
      await setDoc(ref, {
        id: searchId,
        ownerId: user.uid,
        name: clampNonEmpty(search.name, 160, `Saved Hunt ${searchId}`),
        query: clampNonEmpty(search.query, 2000, '*'),
        description: clampString(search.description, 1000, ''),
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
    } else {
      await updateDoc(ref, {
        name: clampNonEmpty(search.name, 160, `Saved Hunt ${searchId}`),
        query: clampNonEmpty(search.query, 2000, '*'),
        description: clampString(search.description, 1000, ''),
        updatedAt: serverTimestamp(),
      });
    }
  } catch (error) {
    handleFirestoreError(error, OperationType.WRITE, path);
  }
}

export async function syncSavedSearchDelete(rawId: string): Promise<void> {
  const user = auth.currentUser;
  if (!user) return;
  const searchId = sanitizeId(rawId, 'SRCH');
  const path = `saved_searches/${searchId}`;
  try {
    await deleteDoc(doc(db, 'saved_searches', searchId));
  } catch (error) {
    handleFirestoreError(error, OperationType.DELETE, path);
  }
}

export async function syncAlertTriage(input: {
  campaignKey: string;
  triageStatus?: string;
  feedback?: string;
  feedbackNote?: string;
}): Promise<void> {
  const user = auth.currentUser;
  if (!user) return;
  const alertKey = sanitizeId(input.campaignKey, 'alert');
  const path = `alert_triage/${alertKey}`;
  const ref = doc(db, 'alert_triage', alertKey);
  const triageStatus = VALID_TRIAGE_STATUSES.has(String(input.triageStatus || ''))
    ? String(input.triageStatus)
    : 'open';
  const feedback = VALID_FEEDBACK.has(String(input.feedback || ''))
    ? String(input.feedback)
    : 'none';

  try {
    const snap = await getDoc(ref);
    if (!snap.exists()) {
      await setDoc(ref, {
        id: alertKey,
        ownerId: user.uid,
        campaignKey: clampNonEmpty(input.campaignKey, 256, alertKey),
        triageStatus,
        feedback,
        feedbackNote: clampString(input.feedbackNote, 1000, ''),
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
    } else {
      await updateDoc(ref, {
        triageStatus,
        feedback,
        feedbackNote: clampString(input.feedbackNote, 1000, ''),
        updatedAt: serverTimestamp(),
      });
    }
  } catch (error) {
    handleFirestoreError(error, OperationType.WRITE, path);
  }
}

export async function loadUserWorkspaceSnapshot(uid: string): Promise<HydratedCloudPayload> {
  const result: HydratedCloudPayload = {
    cases: [],
    custom_rules: [],
    saved_searches: [],
    alert_triage: [],
  };

  try {
    const casesSnap = await getDocs(
      query(collection(db, 'incident_cases'), where('ownerId', '==', uid))
    );
    for (const d of casesSnap.docs) {
      const data = d.data();
      const notesPath = `incident_cases/${d.id}/notes`;
      let notes: Array<{ id: string; author: string; note: string; created_at: number }> = [];
      try {
        const notesSnap = await getDocs(
          query(collection(db, 'incident_cases', d.id, 'notes'), where('ownerId', '==', uid))
        );
        notes = notesSnap.docs.map((nd) => {
          const n = nd.data();
          return {
            id: nd.id,
            author: String(n.author || 'SOC Analyst'),
            note: String(n.note || ''),
            created_at: timestampToUnix(n.createdAt),
          };
        });
      } catch (noteErr) {
        handleFirestoreError(noteErr, OperationType.LIST, notesPath);
      }
      result.cases.push({
        id: String(data.id || d.id),
        title: String(data.title || 'Security Incident'),
        description: String(data.description || ''),
        severity: String(data.severity || 'HIGH'),
        status: String(data.status || 'NEW'),
        assignee: String(data.assignee || 'Unassigned'),
        created_at: timestampToUnix(data.createdAt),
        updated_at: timestampToUnix(data.updatedAt),
        notes,
      });
    }
  } catch (error) {
    handleFirestoreError(error, OperationType.LIST, 'incident_cases');
  }

  try {
    const rulesSnap = await getDocs(
      query(collection(db, 'custom_rules'), where('ownerId', '==', uid))
    );
    result.custom_rules = rulesSnap.docs.map((d) => {
      const data = d.data();
      return {
        id: Number(data.ruleNumericId) || 100900,
        name: String(data.name || d.id),
        title: String(data.title || data.name || d.id),
        description: String(data.description || ''),
        level: Number(data.level) || 7,
        log_type: String(data.logType || '*'),
        enabled: Boolean(data.enabled),
        raw_sigma: String(data.rawSigma || ''),
        created_at: timestampToUnix(data.createdAt),
        updated_at: timestampToUnix(data.updatedAt),
      };
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.LIST, 'custom_rules');
  }

  try {
    const searchSnap = await getDocs(
      query(collection(db, 'saved_searches'), where('ownerId', '==', uid))
    );
    result.saved_searches = searchSnap.docs.map((d) => {
      const data = d.data();
      return {
        id: String(data.id || d.id),
        name: String(data.name || d.id),
        query: String(data.query || '*'),
        description: String(data.description || ''),
        created_at: timestampToUnix(data.createdAt),
      };
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.LIST, 'saved_searches');
  }

  try {
    const triageSnap = await getDocs(
      query(collection(db, 'alert_triage'), where('ownerId', '==', uid))
    );
    result.alert_triage = triageSnap.docs.map((d) => {
      const data = d.data();
      return {
        campaign_key: String(data.campaignKey || d.id),
        triage_status: (data.triageStatus || 'open') as 'open' | 'suppressed' | 'closed',
        feedback: String(data.feedback || 'none'),
        feedback_note: String(data.feedbackNote || ''),
      };
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.LIST, 'alert_triage');
  }

  return result;
}

export function subscribeWorkspaceRealtime(
  uid: string,
  onChange: () => void
): Unsubscribe {
  const unsubs: Unsubscribe[] = [];

  const attach = (collectionName: string) => {
    const q = query(collection(db, collectionName), where('ownerId', '==', uid));
    let initial = true;
    const u = onSnapshot(
      q,
      () => {
        if (initial) {
          initial = false;
          return;
        }
        onChange();
      },
      (error) => {
        handleFirestoreError(error, OperationType.LIST, collectionName);
      }
    );
    unsubs.push(u);
  };

  attach('incident_cases');
  attach('custom_rules');
  attach('saved_searches');
  attach('alert_triage');

  return () => {
    for (const u of unsubs) {
      try {
        u();
      } catch {
        // ignore unsubscribe errors
      }
    }
  };
}
