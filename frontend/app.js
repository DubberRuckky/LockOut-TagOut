/**
 * frontend/app.js - Central Application & State Controller (ES Module)
 * Implements camera face presence, shifting code ratchet, and zero-trust UI.
 */

import {
  deriveSessionSeed,
  clientCode,
  isEd25519Supported,
  signNonce,
  configHashHex,
  sha256Hex,
  hexToBytes,
  bytesToHex
} from '/ui/crypto.js';

// Rank tier names matching docs/SPEC.md
const RANK_NAMES = {
  1: 'Constable (Tier 1)',
  2: 'Head Constable (Tier 2)',
  3: 'Sub-Inspector (Tier 3)',
  4: 'Inspector (Tier 4)',
  5: 'Superintendent (Tier 5)'
};

// Global application state
const state = {
  authenticated: false,
  officerId: null,
  rankTier: 1,
  deviceId: null,
  sessionId: null,
  sessionSeed: null,
  counter: 0,
  keyfile: null,
  activeNonce: null,
  activeCaseId: null,
  videoStream: null,
  faceCheckOk: false,
  cameraPollInterval: null,
  statusPollInterval: null,
  ws: null,
};

// =============================================================================
// Toast Notifications & Helpers
// =============================================================================
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => {
    toast.remove();
  }, 4000);
}

function updateSystemBadge(lockState) {
  const badge = document.getElementById('systemStateBadge');
  const text = document.getElementById('systemStateText');
  if (!badge || !text) return;

  badge.className = 'status-badge';
  text.textContent = lockState || 'UNKNOWN';

  const s = (lockState || '').toUpperCase();
  if (s === 'NORMAL') {
    badge.classList.add('status-normal');
  } else if (s === 'RESTRICTED') {
    badge.classList.add('status-restricted');
  } else if (s === 'LOCKED') {
    badge.classList.add('status-locked');
  } else if (s === 'TAGOUT') {
    badge.classList.add('status-tagout');
  }
}

// =============================================================================
// Fullscreen Lock / Tagout Screen Management
// =============================================================================
function setLockOverlay(lockInfo) {
  const lockedScreen = document.getElementById('screenLocked');
  const tagoutScreen = document.getElementById('screenTagout');
  const s = (lockInfo?.state || '').toUpperCase();

  if (s === 'LOCKED') {
    document.getElementById('lockedReason').textContent = lockInfo.reason || 'Threshold Violation';
    document.getElementById('lockedSince').textContent = lockInfo.since ? new Date(lockInfo.since * 1000).toLocaleString() : 'Just now';
    lockedScreen.classList.add('active');
    tagoutScreen.classList.remove('active');
  } else if (s === 'TAGOUT') {
    document.getElementById('tagoutInitiator').textContent = lockInfo.initiator || 'Inspector';
    document.getElementById('tagoutSince').textContent = lockInfo.since ? new Date(lockInfo.since * 1000).toLocaleString() : 'Just now';
    tagoutScreen.classList.add('active');
    lockedScreen.classList.remove('active');
  } else {
    lockedScreen.classList.remove('active');
    tagoutScreen.classList.remove('active');
  }
}

// =============================================================================
// Authenticated API Client with Shifting Code Ratchet
// =============================================================================
async function authFetch(url, options = {}) {
  if (!state.authenticated || !state.sessionId || !state.sessionSeed) {
    throw new Error('Not authenticated');
  }

  // Increment counter for every request
  state.counter += 1;
  const counterVal = state.counter;
  const code = await clientCode(state.sessionSeed, counterVal);

  const headers = new Headers(options.headers || {});
  headers.set('X-Session-Id', state.sessionId);
  headers.set('X-Counter', counterVal.toString());
  headers.set('X-Code', code);

  const fetchOptions = {
    ...options,
    headers,
  };

  const resp = await fetch(url, fetchOptions);

  if (resp.status === 401) {
    showToast('Session expired or unauthorized', 'error');
    signOut();
    throw new Error('Unauthorized');
  }

  if (resp.status === 503) {
    pollStatus();
    throw new Error('Service unavailable (System Locked or Sealed)');
  }

  return resp;
}

// =============================================================================
// Camera & Biometric Presence Management
// =============================================================================
async function initCamera() {
  const video = document.getElementById('loginVideo');
  const statusBadge = document.getElementById('cameraStatusBadge');
  const statusText = document.getElementById('cameraStatusText');

  function setCameraStatus(cls, text) {
    statusBadge.className = `camera-badge ${cls}`;
    statusText.textContent = text;
  }

  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    setCameraStatus('camera-no-cam', 'No camera detected');
    return;
  }

  try {
    const stream = await navigator.mediaDevices.getUserMedia({
      video: { width: { ideal: 320 }, height: { ideal: 240 } }
    });
    state.videoStream = stream;
    video.srcObject = stream;
    setCameraStatus('camera-no-face', 'Camera active (No face)');

    // Start background presence detection
    startCameraMonitoring();
  } catch (err) {
    if (err.name === 'NotAllowedError' || err.name === 'PermissionDeniedError') {
      setCameraStatus('camera-blocked', 'Camera blocked (Permission denied)');
    } else {
      setCameraStatus('camera-no-cam', 'No camera detected');
    }
    const loginSubmitBtn = document.getElementById('loginSubmitBtn');
    if (loginSubmitBtn) {
      loginSubmitBtn.disabled = true;
      loginSubmitBtn.textContent = 'Sign In (Camera Required)';
    }
  }
}

function captureFrameBase64() {
  const video = document.getElementById('loginVideo');
  const canvas = document.getElementById('captureCanvas');
  if (!video || !canvas || video.readyState !== 4) return null;

  const ctx = canvas.getContext('2d');
  ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
  const dataUrl = canvas.toDataURL('image/jpeg', 0.7);
  const base64Index = dataUrl.indexOf(',');
  return base64Index !== -1 ? dataUrl.substring(base64Index + 1) : null;
}

function startCameraMonitoring() {
  if (state.cameraPollInterval) clearInterval(state.cameraPollInterval);

  // Periodic capture every 3 seconds to check face presence if keyfile & officer are filled
  state.cameraPollInterval = setInterval(async () => {
    if (state.authenticated) return;
    await performFaceCheckIfReady();
  }, 3000);
}

async function performFaceCheckIfReady() {
  const officerInput = document.getElementById('officerIdInput');
  const statusBadge = document.getElementById('cameraStatusBadge');
  const statusText = document.getElementById('cameraStatusText');
  const loginSubmitBtn = document.getElementById('loginSubmitBtn');

  if (!state.keyfile || !officerInput.value.trim()) {
    return;
  }

  // Obtain an active challenge nonce if we do not already have one
  if (!state.activeNonce) {
    try {
      const cResp = await fetch('/auth/challenge', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ device_id: state.keyfile.device_id }),
      });
      if (cResp.ok) {
        const cData = await cResp.json();
        state.activeNonce = cData.nonce;
      }
    } catch (e) {
      return;
    }
  }

  if (!state.activeNonce) return;

  // Capture 2-3 frames from video
  const frame1 = captureFrameBase64();
  if (!frame1) return;

  const frames = [frame1];

  try {
    const fResp = await fetch('/auth/face', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        device_id: state.keyfile.device_id,
        nonce: state.activeNonce,
        frames,
      }),
    });

    if (fResp.ok) {
      const fData = await fResp.json();
      if (fData.face_ok) {
        state.faceCheckOk = true;
        statusBadge.className = 'camera-badge camera-face-ok';
        statusText.textContent = 'Face detected (Verified)';
        loginSubmitBtn.disabled = false;
        loginSubmitBtn.textContent = 'Sign In';
      } else {
        state.faceCheckOk = false;
        statusBadge.className = 'camera-badge camera-no-face';
        statusText.textContent = 'No face detected';
        loginSubmitBtn.disabled = true;
        loginSubmitBtn.textContent = 'Sign In (Awaiting Face)';
      }
    } else {
      state.faceCheckOk = false;
      // If nonce expired or tripped rate limit, clear nonce to get a fresh one next cycle
      if (fResp.status === 400 || fResp.status === 429) {
        state.activeNonce = null;
      }
    }
  } catch (err) {
    state.faceCheckOk = false;
  }
}

// =============================================================================
// Authentication & Login Flow
// =============================================================================
async function handleLogin(e) {
  e.preventDefault();
  const officerId = document.getElementById('officerIdInput').value.trim();
  const passcode = document.getElementById('passcodeInput').value;
  const loginSubmitBtn = document.getElementById('loginSubmitBtn');

  if (!state.keyfile) {
    showToast('Please select a valid device keyfile (.json)', 'error');
    return;
  }

  if (!state.faceCheckOk) {
    showToast('Face verification required before signing in', 'error');
    return;
  }

  loginSubmitBtn.disabled = true;
  loginSubmitBtn.textContent = 'Authenticating...';

  try {
    // 1. Ensure we have a fresh nonce
    if (!state.activeNonce) {
      const cResp = await fetch('/auth/challenge', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ device_id: state.keyfile.device_id }),
      });
      if (!cResp.ok) throw new Error('Challenge request failed');
      const cData = await cResp.json();
      state.activeNonce = cData.nonce;
    }

    // 2. Sign nonce with Ed25519
    const signature = await signNonce(state.keyfile.signing_key_hex, state.activeNonce);
    const configHash = await configHashHex(state.keyfile.device_config);

    // 3. Post to /auth/login
    const loginPayload = {
      device_id: state.keyfile.device_id,
      nonce: state.activeNonce,
      signature,
      config_hash: configHash,
      passcode,
    };

    const lResp = await fetch('/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(loginPayload),
    });

    if (!lResp.ok) {
      const err = await lResp.json().catch(() => ({}));
      state.activeNonce = null;
      state.faceCheckOk = false;
      throw new Error(err.detail || 'Login failed. Check passcode or device authorization.');
    }

    const lData = await lResp.json();
    state.sessionId = lData.session_id;

    // 4. Derive Session Seed
    const secretBytes = hexToBytes(state.keyfile.shared_secret_hex);
    const nonceBytes = hexToBytes(state.activeNonce);
    state.sessionSeed = await deriveSessionSeed(secretBytes, nonceBytes, state.keyfile.device_id);
    state.counter = 0;
    state.authenticated = true;
    state.officerId = officerId;
    state.deviceId = state.keyfile.device_id;

    // 5. Query /api/ping to resolve officer tier from gateway headers
    const pingResp = await authFetch('/api/ping');
    if (pingResp.ok) {
      const pingData = await pingResp.json();
      state.rankTier = parseInt(pingData.rank_tier || '1', 10);
      updateOfficerBadge(state.officerId, state.rankTier);
    }

    showToast(`Welcome, Officer ${state.officerId}`, 'success');

    // Switch to Cases view
    document.getElementById('view-login').classList.remove('active');
    document.getElementById('mainTabBar').style.display = 'flex';
    document.getElementById('officerHeaderBadge').style.display = 'flex';
    
    // Configure role-dependent UI tabs
    configureRoleUI(state.rankTier);

    switchTab('view-cases');
    loadCases();

  } catch (err) {
    showToast(err.message, 'error');
    loginSubmitBtn.disabled = false;
    loginSubmitBtn.textContent = 'Sign In';
  }
}

function updateOfficerBadge(officerId, rankTier) {
  const badge = document.getElementById('officerHeaderBadge');
  const nameSpan = document.getElementById('headerOfficerId');
  const rankPill = document.getElementById('headerRankPill');
  if (!badge) return;

  badge.style.display = 'flex';
  nameSpan.textContent = officerId;
  rankPill.textContent = RANK_NAMES[rankTier] || `Tier ${rankTier}`;
}

function configureRoleUI(rankTier) {
  const tabAmendmentsBtn = document.getElementById('tabAmendmentsBtn');
  const tabTagoutBtn = document.getElementById('tabTagoutBtn');

  // Tier 4-5 gets Tagout access and Amendment decision authority
  if (rankTier >= 4) {
    if (tabTagoutBtn) tabTagoutBtn.style.display = 'inline-flex';
    if (tabAmendmentsBtn) tabAmendmentsBtn.style.display = 'inline-flex';
  } else {
    if (tabTagoutBtn) tabTagoutBtn.style.display = 'none';
  }
}

function signOut() {
  state.authenticated = false;
  state.sessionId = null;
  state.sessionSeed = null;
  state.counter = 0;
  state.activeNonce = null;
  state.faceCheckOk = false;

  document.getElementById('mainTabBar').style.display = 'none';
  document.getElementById('officerHeaderBadge').style.display = 'none';
  
  // Switch to login view
  document.querySelectorAll('.view-section').forEach(el => el.classList.remove('active'));
  document.getElementById('view-login').classList.add('active');

  const loginSubmitBtn = document.getElementById('loginSubmitBtn');
  if (loginSubmitBtn) {
    loginSubmitBtn.disabled = true;
    loginSubmitBtn.textContent = 'Sign In (Awaiting Face Check)';
  }
}

// =============================================================================
// Tab Routing
// =============================================================================
window.switchTab = function(tabId) {
  document.querySelectorAll('.view-section').forEach(el => el.classList.remove('active'));
  const target = document.getElementById(tabId);
  if (target) target.classList.add('active');

  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.tab === tabId);
  });

  if (tabId === 'view-cases') loadCases();
  if (tabId === 'view-review') loadReviewQueue();
  if (tabId === 'view-amendments') loadAmendments();
  if (tabId === 'view-audit') loadAuditLog();
};

// =============================================================================
// Cases Ledger & Detail
// =============================================================================
async function loadCases() {
  try {
    const resp = await authFetch('/api/cases');
    const cases = await resp.json();
    const tbody = document.getElementById('casesTableBody');
    tbody.replaceChildren();

    document.getElementById('statTotalCases').textContent = cases.length.toString();

    let totalFiles = 0;

    if (cases.length === 0) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 7;
      td.style.textAlign = 'center';
      td.style.color = 'var(--text-muted)';
      td.textContent = 'No cases found in the vault.';
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    cases.forEach(c => {
      totalFiles += (c.files_count || 0);
      const tr = document.createElement('tr');

      const tdId = document.createElement('td');
      tdId.className = 'table-code';
      tdId.textContent = c.case_id;
      tr.appendChild(tdId);

      const tdTitle = document.createElement('td');
      tdTitle.style.fontWeight = '600';
      tdTitle.textContent = c.title;
      tr.appendChild(tdTitle);

      const tdType = document.createElement('td');
      tdType.textContent = c.case_type || 'General';
      tr.appendChild(tdType);

      const tdStatus = document.createElement('td');
      const statusPill = document.createElement('span');
      statusPill.className = `pill ${c.status === 'open' ? 'pill-open' : 'pill-closed'}`;
      statusPill.textContent = (c.status || 'open').toUpperCase();
      tdStatus.appendChild(statusPill);
      tr.appendChild(tdStatus);

      const tdWitness = document.createElement('td');
      tdWitness.textContent = c.witness_protection ? 'Active (Masked)' : 'None';
      tr.appendChild(tdWitness);

      const tdCreator = document.createElement('td');
      tdCreator.textContent = c.created_by;
      tr.appendChild(tdCreator);

      const tdAction = document.createElement('td');
      const viewBtn = document.createElement('button');
      viewBtn.className = 'btn btn-secondary';
      viewBtn.style.padding = '0.25rem 0.6rem';
      viewBtn.style.fontSize = '0.75rem';
      viewBtn.textContent = 'Open Vault';
      viewBtn.onclick = () => openCaseDetail(c.case_id);
      tdAction.appendChild(viewBtn);
      tr.appendChild(tdAction);

      tbody.appendChild(tr);
    });

    document.getElementById('statTotalFiles').textContent = totalFiles.toString();

  } catch (err) {
    showToast('Failed to load cases: ' + err.message, 'error');
  }
}

async function openCaseDetail(caseId) {
  state.activeCaseId = caseId;
  const tabDetailBtn = document.getElementById('tabDetailBtn');
  if (tabDetailBtn) tabDetailBtn.style.display = 'inline-flex';

  switchTab('view-detail');

  try {
    const cResp = await authFetch(`/api/cases/${caseId}`);
    const c = await cResp.json();

    document.getElementById('detailCaseId').textContent = c.case_id;
    document.getElementById('detailCaseTitle').textContent = c.title;
    document.getElementById('detailCaseStatus').textContent = (c.status || 'open').toUpperCase();
    document.getElementById('detailCaseType').textContent = c.case_type || 'General';
    document.getElementById('detailCaseWitness').textContent = c.witness_protection ? 'Enabled' : 'Disabled';
    document.getElementById('detailCaseCreator').textContent = c.created_by;
    document.getElementById('detailCaseHash').textContent = c.case_hash || 'Open (unsealed)';

    // Show Close Case button if case is open and user has tier 3+ or is creator
    const closeBtn = document.getElementById('btnCloseCaseBtn');
    if (c.status === 'open' && (state.rankTier >= 3 || state.officerId === c.created_by)) {
      closeBtn.style.display = 'inline-flex';
      closeBtn.onclick = () => closeCase(c.case_id);
    } else {
      closeBtn.style.display = 'none';
    }

    loadCaseFiles(caseId);

  } catch (err) {
    showToast('Failed to load case detail: ' + err.message, 'error');
  }
}

async function closeCase(caseId) {
  if (!confirm('Are you sure you want to permanently close and seal this case record?')) return;
  try {
    const resp = await authFetch(`/api/cases/${caseId}/close`, { method: 'POST' });
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to close case');
    }
    const data = await resp.json();
    showToast(`Case sealed. Root Hash: ${data.case_hash.substring(0, 12)}...`, 'success');
    openCaseDetail(caseId);
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function loadCaseFiles(caseId) {
  const tbody = document.getElementById('caseFilesTableBody');
  tbody.replaceChildren();

  try {
    const resp = await authFetch(`/api/cases/${caseId}/files`);
    const files = await resp.json();

    if (files.length === 0) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 7;
      td.style.textAlign = 'center';
      td.style.color = 'var(--text-muted)';
      td.textContent = 'No evidence files deposited in this case.';
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    files.forEach(f => {
      const tr = document.createElement('tr');

      const tdId = document.createElement('td');
      tdId.className = 'table-code';
      tdId.textContent = f.file_id;
      tr.appendChild(tdId);

      const tdName = document.createElement('td');
      tdName.textContent = f.filename;
      tr.appendChild(tdName);

      const tdClass = document.createElement('td');
      const pill = document.createElement('span');
      pill.className = `pill ${f.classification === 'classified' ? 'pill-classified' : 'pill-review'}`;
      pill.textContent = f.classification || 'unknown';
      tdClass.appendChild(pill);
      tr.appendChild(tdClass);

      const tdTags = document.createElement('td');
      tdTags.textContent = (f.tags || []).join(', ') || '-';
      tr.appendChild(tdTags);

      const tdConf = document.createElement('td');
      tdConf.textContent = f.confidence ? `${Math.round(f.confidence * 100)}%` : '-';
      tr.appendChild(tdConf);

      const tdHash = document.createElement('td');
      tdHash.className = 'table-code';
      tdHash.textContent = (f.sha256 || '').substring(0, 16) + '...';
      tr.appendChild(tdHash);

      const tdVer = document.createElement('td');
      const verBtn = document.createElement('button');
      verBtn.className = 'btn btn-secondary';
      verBtn.style.padding = '0.2rem 0.5rem';
      verBtn.style.fontSize = '0.75rem';
      verBtn.textContent = 'Verify AES';
      verBtn.onclick = async () => {
        verBtn.disabled = true;
        verBtn.textContent = 'Checking...';
        const vResp = await authFetch(`/api/files/${f.file_id}/verify`);
        const vData = await vResp.json();
        if (vData.valid) {
          verBtn.textContent = 'Valid ✓';
          verBtn.style.color = 'var(--status-normal)';
        } else {
          verBtn.textContent = 'Tampered ✗';
          verBtn.style.color = 'var(--status-locked)';
        }
      };
      tdVer.appendChild(verBtn);
      tr.appendChild(tdVer);

      tbody.appendChild(tr);
    });

  } catch (err) {
    showToast('Failed to load case files: ' + err.message, 'error');
  }
}

// Drag & Drop Upload
function setupDropzone() {
  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('evidenceFileInput');

  dropzone.onclick = () => fileInput.click();

  dropzone.ondragover = (e) => {
    e.preventDefault();
    dropzone.classList.add('dragover');
  };

  dropzone.ondragleave = () => {
    dropzone.classList.remove('dragover');
  };

  dropzone.ondrop = (e) => {
    e.preventDefault();
    dropzone.classList.remove('dragover');
    if (e.dataTransfer.files.length > 0) {
      uploadFile(e.dataTransfer.files[0]);
    }
  };

  fileInput.onchange = () => {
    if (fileInput.files.length > 0) {
      uploadFile(fileInput.files[0]);
    }
  };
}

async function uploadFile(file) {
  if (!state.activeCaseId) {
    showToast('Please select a case before depositing evidence', 'error');
    return;
  }

  showToast(`Uploading ${file.name}...`, 'info');
  const formData = new FormData();
  formData.append('file', file);

  try {
    const resp = await authFetch(`/api/cases/${state.activeCaseId}/upload`, {
      method: 'POST',
      body: formData,
    });

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new Error(err.detail || 'Upload rejected by security validation');
    }

    const data = await resp.json();
    showToast(`Deposited ${file.name} (SHA-256: ${data.sha256.substring(0, 10)}...)`, 'success');
    loadCaseFiles(state.activeCaseId);

  } catch (err) {
    showToast(err.message, 'error');
  }
}

// =============================================================================
// Review Queue
// =============================================================================
async function loadReviewQueue() {
  const tbody = document.getElementById('reviewTableBody');
  tbody.replaceChildren();

  try {
    const resp = await authFetch('/api/cases');
    const cases = await resp.json();

    let flaggedCount = 0;

    for (const c of cases) {
      const fResp = await authFetch(`/api/cases/${c.case_id}/files`);
      const files = await fResp.json();
      const reviewFiles = files.filter(f => f.classification === 'needs_review' || (f.confidence && f.confidence < 0.6));

      reviewFiles.forEach(f => {
        flaggedCount++;
        const tr = document.createElement('tr');

        const tdFileId = document.createElement('td');
        tdFileId.className = 'table-code';
        tdFileId.textContent = f.file_id;
        tr.appendChild(tdFileId);

        const tdCaseId = document.createElement('td');
        tdCaseId.className = 'table-code';
        tdCaseId.textContent = c.case_id;
        tr.appendChild(tdCaseId);

        const tdName = document.createElement('td');
        tdName.textContent = f.filename;
        tr.appendChild(tdName);

        const tdTags = document.createElement('td');
        tdTags.textContent = (f.tags || []).join(', ') || 'none';
        tr.appendChild(tdTags);

        const tdConf = document.createElement('td');
        tdConf.textContent = f.confidence ? `${Math.round(f.confidence * 100)}%` : '-';
        tr.appendChild(tdConf);

        const tdReason = document.createElement('td');
        tdReason.textContent = f.confidence && f.confidence < 0.6 ? 'Low OCR confidence' : 'Needs review flag';
        tr.appendChild(tdReason);

        tbody.appendChild(tr);
      });
    }

    document.getElementById('statReviewCount').textContent = flaggedCount.toString();

    if (flaggedCount === 0) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 6;
      td.style.textAlign = 'center';
      td.style.color = 'var(--text-muted)';
      td.textContent = 'Review queue is empty. No files require manual clearance.';
      tr.appendChild(td);
      tbody.appendChild(tr);
    }

  } catch (err) {
    showToast('Failed to load review queue: ' + err.message, 'error');
  }
}

// =============================================================================
// Amendments Queue
// =============================================================================
async function loadAmendments() {
  const tbody = document.getElementById('amendmentsTableBody');
  tbody.replaceChildren();

  try {
    const resp = await authFetch('/api/amendments');
    const amendments = await resp.json();

    document.getElementById('statPendingAmendments').textContent =
      amendments.filter(a => a.status === 'pending').length.toString();

    if (amendments.length === 0) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 7;
      td.style.textAlign = 'center';
      td.style.color = 'var(--text-muted)';
      td.textContent = 'No amendments registered in the ledger.';
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    amendments.forEach(a => {
      const tr = document.createElement('tr');

      const tdId = document.createElement('td');
      tdId.className = 'table-code';
      tdId.textContent = a.amendment_id;
      tr.appendChild(tdId);

      const tdCase = document.createElement('td');
      tdCase.className = 'table-code';
      tdCase.textContent = a.case_id;
      tr.appendChild(tdCase);

      const tdBy = document.createElement('td');
      tdBy.textContent = a.officer_id;
      tr.appendChild(tdBy);

      const tdChanges = document.createElement('td');
      tdChanges.textContent = JSON.stringify(a.changes);
      tr.appendChild(tdChanges);

      const tdStatus = document.createElement('td');
      const pill = document.createElement('span');
      pill.className = `pill ${a.status === 'pending' ? 'pill-review' : (a.status === 'approved' ? 'pill-open' : 'pill-closed')}`;
      pill.textContent = (a.status || 'pending').toUpperCase();
      tdStatus.appendChild(pill);
      tr.appendChild(tdStatus);

      const tdDecided = document.createElement('td');
      tdDecided.textContent = a.decided_by || '-';
      tr.appendChild(tdDecided);

      const tdAction = document.createElement('td');
      if (a.status === 'pending' && state.rankTier >= 4) {
        const btnApprove = document.createElement('button');
        btnApprove.className = 'btn btn-primary';
        btnApprove.style.padding = '0.2rem 0.5rem';
        btnApprove.style.fontSize = '0.75rem';
        btnApprove.textContent = 'Approve';
        btnApprove.onclick = () => decideAmendment(a.amendment_id, 'approved');

        const btnReject = document.createElement('button');
        btnReject.className = 'btn btn-danger';
        btnReject.style.padding = '0.2rem 0.5rem';
        btnReject.style.fontSize = '0.75rem';
        btnReject.style.marginLeft = '0.25rem';
        btnReject.textContent = 'Reject';
        btnReject.onclick = () => decideAmendment(a.amendment_id, 'rejected');

        tdAction.appendChild(btnApprove);
        tdAction.appendChild(btnReject);
      } else {
        tdAction.textContent = '-';
      }
      tr.appendChild(tdAction);

      tbody.appendChild(tr);
    });

  } catch (err) {
    showToast('Failed to load amendments: ' + err.message, 'error');
  }
}

async function decideAmendment(amendmentId, decision) {
  try {
    const resp = await authFetch(`/api/amendments/${amendmentId}/review`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ decision }),
    });

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new Error(err.detail || 'Decision rejected');
    }

    showToast(`Amendment ${decision}`, 'success');
    loadAmendments();

  } catch (err) {
    showToast(err.message, 'error');
  }
}

// =============================================================================
// Audit Log & Verification
// =============================================================================
async function loadAuditLog() {
  const tbody = document.getElementById('auditTableBody');
  tbody.replaceChildren();

  try {
    const resp = await authFetch('/api/audit');
    const data = await resp.json();
    const events = data.events || [];

    if (events.length === 0) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 6;
      td.style.textAlign = 'center';
      td.style.color = 'var(--text-muted)';
      td.textContent = 'No audit records found.';
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    events.forEach(e => {
      const tr = document.createElement('tr');

      const tdSeq = document.createElement('td');
      tdSeq.style.fontWeight = '600';
      tdSeq.textContent = `#${e.sequence}`;
      tr.appendChild(tdSeq);

      const tdTime = document.createElement('td');
      tdTime.textContent = new Date(e.timestamp * 1000).toLocaleTimeString();
      tr.appendChild(tdTime);

      const tdEvent = document.createElement('td');
      tdEvent.textContent = e.event_type;
      tr.appendChild(tdEvent);

      const tdOfficer = document.createElement('td');
      tdOfficer.textContent = e.officer_id || 'system';
      tr.appendChild(tdOfficer);

      const tdDetails = document.createElement('td');
      tdDetails.style.fontSize = '0.8rem';
      tdDetails.textContent = JSON.stringify(e.details);
      tr.appendChild(tdDetails);

      const tdHash = document.createElement('td');
      tdHash.className = 'table-code';
      tdHash.textContent = (e.record_hash || '').substring(0, 16) + '...';
      tr.appendChild(tdHash);

      tbody.appendChild(tr);
    });

  } catch (err) {
    showToast('Failed to load audit log: ' + err.message, 'error');
  }
}

async function verifyAuditChain() {
  const statusBox = document.getElementById('auditVerifyStatus');
  statusBox.style.display = 'block';
  statusBox.textContent = 'Verifying cryptographic hash chain integrity...';
  statusBox.style.background = 'var(--pale-blue-subtle)';
  statusBox.style.color = 'var(--navy)';

  try {
    const resp = await authFetch('/api/audit/verify', { method: 'POST' });
    const data = await resp.json();

    if (data.valid) {
      statusBox.style.background = 'var(--status-normal-bg)';
      statusBox.style.color = 'var(--status-normal)';
      statusBox.textContent = `✓ Audit Chain Intact: Verified ${data.count} sequential cryptographic records.`;
    } else {
      statusBox.style.background = 'var(--status-locked-bg)';
      statusBox.style.color = 'var(--status-locked)';
      statusBox.textContent = `✗ Cryptographic Integrity Compromised at Sequence #${data.broken_at}`;
    }
  } catch (err) {
    statusBox.style.background = 'var(--status-locked-bg)';
    statusBox.style.color = 'var(--status-locked)';
    statusBox.textContent = 'Verification error: ' + err.message;
  }
}

// =============================================================================
// Prove-A-File (Zero-Knowledge Browser Hashing)
// =============================================================================
function setupProveAFile() {
  const input = document.getElementById('proveFileInput');
  const box = document.getElementById('proveResultBox');
  const hashDisplay = document.getElementById('proveHashDisplay');
  const statusDisplay = document.getElementById('proveMatchStatus');
  const detailsDisplay = document.getElementById('proveMatchDetails');

  input.onchange = async () => {
    if (!input.files.length) return;
    const file = input.files[0];

    box.style.display = 'block';
    hashDisplay.textContent = 'Calculating client-side SHA-256...';
    statusDisplay.textContent = 'Searching Vault Ledger...';
    detailsDisplay.textContent = '';

    try {
      const buffer = await file.arrayBuffer();
      const hash = await sha256Hex(new Uint8Array(buffer));
      hashDisplay.textContent = hash;

      const resp = await authFetch(`/api/archive/lookup?sha256=${hash}`);
      const data = await resp.json();

      if (data.exists) {
        statusDisplay.textContent = '✓ PROVED: Document Exists in Vault';
        statusDisplay.style.color = 'var(--status-normal)';
        detailsDisplay.textContent = `Case ID: ${data.case_id} | Deposited: ${new Date(data.created_at * 1000).toLocaleString()}`;
      } else {
        statusDisplay.textContent = '✗ UNPROVED: Document Not Found';
        statusDisplay.style.color = 'var(--status-locked)';
        detailsDisplay.textContent = 'No evidence record with this exact SHA-256 checksum exists in the ledger.';
      }
    } catch (err) {
      statusDisplay.textContent = 'Lookup Failed: ' + err.message;
      statusDisplay.style.color = 'var(--status-locked)';
    }
  };
}

// =============================================================================
// Emergency Investigation Tagout
// =============================================================================
async function triggerTagout() {
  if (state.rankTier < 4) {
    showToast('Permission denied: Tagout requires Tier 4 (Inspector) or higher', 'error');
    return;
  }

  const confirmed = confirm(
    'CRITICAL ACTION: Triggering Tagout will sever all network sessions and seal the case vault under investigation status. Proceed?'
  );
  if (!confirmed) return;

  try {
    const resp = await authFetch('/api/tagout', { method: 'POST' });
    if (!resp.ok) throw new Error('Tagout failed');
    showToast('Investigation Tagout Engaged', 'success');
    pollStatus();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// =============================================================================
// System Status Polling & WebSockets
// =============================================================================
async function pollStatus() {
  try {
    const resp = await fetch('/status');
    if (resp.ok) {
      const lockInfo = await resp.json();
      updateSystemBadge(lockInfo.state);
      setLockOverlay(lockInfo);
    }
  } catch (e) {
    // Fail-closed UI if gateway unreachable
    updateSystemBadge('LOCKED');
    setLockOverlay({ state: 'LOCKED', reason: 'Gateway unreachable' });
  }
}

function initWebSocket() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}/ws`;

  try {
    state.ws = new WebSocket(wsUrl);

    state.ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.event === 'lock_state_changed' || msg.state) {
          updateSystemBadge(msg.state);
          setLockOverlay(msg);
        }
      } catch (e) {}
    };

    state.ws.onclose = () => {
      setTimeout(initWebSocket, 5000);
    };
  } catch (e) {}
}

// =============================================================================
// Initialization
// =============================================================================
document.addEventListener('DOMContentLoaded', async () => {
  // Check Ed25519 WebCrypto Support
  const edOk = await isEd25519Supported();
  if (!edOk) {
    showToast('Warning: Your browser does not support WebCrypto Ed25519. Please use Chrome 113+, Edge 113+, or Firefox 129+.', 'error');
  }

  // Reload buttons on Lock & Tagout screens
  const reloadLocked = document.getElementById('btnReloadLocked');
  if (reloadLocked) reloadLocked.addEventListener('click', () => window.location.reload());
  const reloadTagout = document.getElementById('btnReloadTagout');
  if (reloadTagout) reloadTagout.addEventListener('click', () => window.location.reload());

  // Back to Cases button on Case Detail view
  const btnBack = document.getElementById('btnBackToCases');
  if (btnBack) btnBack.addEventListener('click', () => switchTab('view-cases'));

  // Bind Form and Buttons
  document.getElementById('loginForm').addEventListener('submit', handleLogin);
  document.getElementById('signOutBtn').addEventListener('click', signOut);

  // Keyfile file picker
  document.getElementById('keyfileInput').addEventListener('change', (e) => {
    const file = e.target.files[0];
    const status = document.getElementById('keyfileStatus');
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (evt) => {
      try {
        const json = JSON.parse(evt.target.result);
        if (!json.device_id || !json.signing_key_hex || !json.shared_secret_hex) {
          throw new Error('Keyfile missing essential cryptographic fields');
        }
        state.keyfile = json;
        status.textContent = `Loaded keyfile for device: ${json.device_id}`;
        status.style.color = 'var(--status-normal)';
        state.activeNonce = null; // force fresh challenge for this device
        performFaceCheckIfReady();
      } catch (err) {
        state.keyfile = null;
        status.textContent = 'Invalid keyfile JSON: ' + err.message;
        status.style.color = 'var(--status-locked)';
      }
    };
    reader.readAsText(file);
  });

  // Tab buttons
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const tabId = btn.dataset.tab;
      if (tabId) switchTab(tabId);
    });
  });

  // New Case Drawer
  const newCaseModal = document.getElementById('newCaseModal');
  document.getElementById('btnOpenNewCase').addEventListener('click', () => {
    newCaseModal.style.display = 'block';
  });
  document.getElementById('btnCloseNewCase').addEventListener('click', () => {
    newCaseModal.style.display = 'none';
  });
  document.getElementById('newCaseForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const title = document.getElementById('newCaseTitle').value.trim();
    const caseType = document.getElementById('newCaseType').value;
    const complainantName = document.getElementById('newCaseComplainant').value.trim();
    const witnessProtection = document.getElementById('newCaseWitnessProtection').checked;

    try {
      const resp = await authFetch('/api/cases', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title,
          case_type: caseType,
          complainant_name: complainantName,
          witness_protection: witnessProtection,
        }),
      });

      if (!resp.ok) throw new Error('Failed to create case');
      showToast('New case registered in vault ledger', 'success');
      newCaseModal.style.display = 'none';
      document.getElementById('newCaseForm').reset();
      loadCases();
    } catch (err) {
      showToast(err.message, 'error');
    }
  });

  // Review & Amendments refresh buttons
  document.getElementById('btnRefreshReview').addEventListener('click', loadReviewQueue);
  document.getElementById('btnRefreshAmendments').addEventListener('click', loadAmendments);

  // Audit verify button
  document.getElementById('verifyAuditBtn').addEventListener('click', verifyAuditChain);

  // Emergency Tagout button
  document.getElementById('btnTriggerTagout').addEventListener('click', triggerTagout);

  // Setup Drag & Drop and Prove a File
  setupDropzone();
  setupProveAFile();

  // Initialize camera and status watchers
  initCamera();
  initWebSocket();
  pollStatus();
  state.statusPollInterval = setInterval(pollStatus, 5000);
});
