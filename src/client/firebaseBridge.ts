import {
  onAuthStateChanged,
  signInWithPopup,
  signOut,
  Unsubscribe,
  User,
} from 'firebase/auth';
import { auth, googleAuthProvider } from './firebase.ts';
import {
  ensureUserProfile,
  loadUserWorkspaceSnapshot,
  subscribeWorkspaceRealtime,
  syncAlertTriage,
  syncCaseCreate,
  syncCaseNoteAtomic,
  syncCaseUpdate,
  syncRuleDelete,
  syncRuleSave,
  syncRuleToggle,
  syncSavedSearchDelete,
  syncSavedSearchSave,
} from './firestoreSync.ts';

interface KavalanCloudAPI {
  getCurrentUser: () => User | null;
  signInWithGoogle: () => Promise<{ ok: boolean; token?: string; user?: any; error?: string }>;
  signOutGoogle: () => Promise<void>;
  hydrateBackend: () => Promise<void>;
  syncCaseCreate: typeof syncCaseCreate;
  syncCaseUpdate: typeof syncCaseUpdate;
  syncCaseNoteAtomic: typeof syncCaseNoteAtomic;
  syncRuleSave: typeof syncRuleSave;
  syncRuleToggle: typeof syncRuleToggle;
  syncRuleDelete: typeof syncRuleDelete;
  syncSavedSearchSave: typeof syncSavedSearchSave;
  syncSavedSearchDelete: typeof syncSavedSearchDelete;
  syncAlertTriage: typeof syncAlertTriage;
}

declare global {
  interface Window {
    KavalanCloud?: KavalanCloudAPI;
    onKavalanCloudHydrated?: () => void;
    onKavalanFirebaseSignIn?: (data: { token: string; user: any }) => void;
  }
}

let realtimeUnsub: Unsubscribe | null = null;
let hydrateDebounceTimer: number | null = null;
let lastHydratedUid: string | null = null;

async function hydrateBackendForUser(user: User): Promise<void> {
  try {
    const snapshot = await loadUserWorkspaceSnapshot(user.uid);
    const hasData =
      snapshot.cases.length > 0 ||
      snapshot.custom_rules.length > 0 ||
      snapshot.saved_searches.length > 0 ||
      snapshot.alert_triage.length > 0;
    if (!hasData) return;

    const res = await fetch('/api/sync/hydrate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(snapshot),
    });
    if (res.ok && typeof window.onKavalanCloudHydrated === 'function') {
      window.onKavalanCloudHydrated();
    }
  } catch (err) {
    console.error('[KavalanCloud] Hydration error:', err);
  }
}

async function exchangeFirebaseSession(user: User): Promise<{ ok: boolean; token?: string; user?: any; error?: string }> {
  const idToken = await user.getIdToken();
  const res = await fetch('/api/auth/firebase', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ idToken }),
  });
  const data = await res.json();
  if (!res.ok || !data.token) {
    return { ok: false, error: data.error || 'Failed to establish Kavalan SOC session' };
  }
  return { ok: true, token: data.token, user: data.user };
}

function attachRealtimeForUser(user: User): void {
  if (realtimeUnsub) {
    realtimeUnsub();
    realtimeUnsub = null;
  }
  realtimeUnsub = subscribeWorkspaceRealtime(user.uid, () => {
    if (hydrateDebounceTimer) {
      window.clearTimeout(hydrateDebounceTimer);
    }
    hydrateDebounceTimer = window.setTimeout(() => {
      void hydrateBackendForUser(user);
    }, 800);
  });
}

onAuthStateChanged(auth, async (user) => {
  if (!user) {
    if (realtimeUnsub) {
      realtimeUnsub();
      realtimeUnsub = null;
    }
    lastHydratedUid = null;
    return;
  }

  try {
    await ensureUserProfile(user);
    if (lastHydratedUid !== user.uid) {
      lastHydratedUid = user.uid;
      attachRealtimeForUser(user);
      const sessionRes = await fetch('/api/auth/session');
      if (sessionRes.ok) {
        await hydrateBackendForUser(user);
      } else {
        const session = await exchangeFirebaseSession(user);
        if (session.ok && session.token && typeof window.onKavalanFirebaseSignIn === 'function') {
          window.onKavalanFirebaseSignIn({ token: session.token, user: session.user });
          await hydrateBackendForUser(user);
        }
      }
    }
  } catch (err) {
    console.error('[KavalanCloud] Auth state sync error:', err);
  }
});

const api: KavalanCloudAPI = {
  getCurrentUser: () => auth.currentUser,

  async signInWithGoogle() {
    try {
      const cred = await signInWithPopup(auth, googleAuthProvider);
      const user = cred.user;
      await ensureUserProfile(user);
      const session = await exchangeFirebaseSession(user);
      if (!session.ok || !session.token) {
        return session;
      }
      if (typeof window.onKavalanFirebaseSignIn === 'function') {
        window.onKavalanFirebaseSignIn({ token: session.token, user: session.user });
      }
      lastHydratedUid = user.uid;
      attachRealtimeForUser(user);
      await hydrateBackendForUser(user);
      return session;
    } catch (err: any) {
      const msg = err?.code === 'auth/popup-closed-by-user'
        ? 'Google sign-in popup was closed before completing authentication.'
        : (err?.message || 'Google authentication failed');
      return { ok: false, error: msg };
    }
  },

  async signOutGoogle() {
    if (realtimeUnsub) {
      realtimeUnsub();
      realtimeUnsub = null;
    }
    lastHydratedUid = null;
    if (auth.currentUser) {
      await signOut(auth);
    }
  },

  async hydrateBackend() {
    if (auth.currentUser) {
      await hydrateBackendForUser(auth.currentUser);
    }
  },

  syncCaseCreate,
  syncCaseUpdate,
  syncCaseNoteAtomic,
  syncRuleSave,
  syncRuleToggle,
  syncRuleDelete,
  syncSavedSearchSave,
  syncSavedSearchDelete,
  syncAlertTriage,
};

window.KavalanCloud = api;
