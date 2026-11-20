// frontend/app.js - ES Module for Officer Sign-In & Camera Feed

const cameraFeed = document.getElementById("cameraFeed");
const cameraStatus = document.getElementById("cameraStatus");
const statusText = document.getElementById("statusText");
const signInBtn = document.getElementById("signInBtn");
const officerIdInput = document.getElementById("officerId");
const passcodeInput = document.getElementById("passcode");
const keyfileInput = document.getElementById("keyfileInput");
const systemStateText = document.getElementById("systemStateText");

let streamActive = false;
let keyfileData = null;

function setCameraState(state, message) {
  cameraStatus.className = "camera-status";
  switch (state) {
    case "blocked":
      cameraStatus.classList.add("status-blocked");
      statusText.textContent = message || "Camera blocked: permission denied";
      signInBtn.disabled = true;
      break;
    case "nocamera":
      cameraStatus.classList.add("status-noface");
      statusText.textContent = message || "No camera detected";
      signInBtn.disabled = true;
      break;
    case "noface":
      cameraStatus.classList.add("status-noface");
      statusText.textContent = message || "No face detected";
      signInBtn.disabled = true;
      break;
    case "detected":
      cameraStatus.classList.add("status-detected");
      statusText.textContent = message || "Face presence detected";
      validateForm();
      break;
    default:
      cameraStatus.classList.add("status-init");
      statusText.textContent = message || "Initializing biometric scanner...";
      signInBtn.disabled = true;
  }
}

async function initCamera() {
  setCameraState("init", "Requesting optical presence feed...");

  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    setCameraState("nocamera", "No camera API available on this browser");
    return;
  }

  try {
    const stream = await navigator.mediaDevices.getUserMedia({
      video: {
        width: { ideal: 640 },
        height: { ideal: 480 },
        facingMode: "user",
      },
      audio: false,
    });

    cameraFeed.srcObject = stream;
    streamActive = true;
    setCameraState("detected", "Face presence detected (Live feed active)");
  } catch (err) {
    streamActive = false;
    if (err.name === "NotAllowedError" || err.name === "PermissionDeniedError") {
      setCameraState("blocked", "Camera blocked: access denied by user or OS");
    } else if (err.name === "NotFoundError" || err.name === "DevicesNotFoundError") {
      setCameraState("nocamera", "No camera device found");
    } else {
      setCameraState("blocked", `Camera error: ${err.message || err.name}`);
    }
  }
}

function validateForm() {
  const hasOfficer = Boolean(officerIdInput && officerIdInput.value.trim());
  const hasPasscode = Boolean(passcodeInput && passcodeInput.value.trim());
  const hasKeyfile = Boolean(keyfileData);

  if (streamActive && hasOfficer && hasPasscode && hasKeyfile) {
    signInBtn.disabled = false;
  } else {
    signInBtn.disabled = true;
  }
}

async function loadGatewayStatus() {
  try {
    const resp = await fetch("/status");
    if (resp.ok) {
      const data = await resp.json();
      if (systemStateText && data.state) {
        systemStateText.textContent = data.state;
      }
    }
  } catch (e) {
    if (systemStateText) {
      systemStateText.textContent = "OFFLINE";
    }
  }
}

// Event Listeners
if (keyfileInput) {
  keyfileInput.addEventListener("change", async (e) => {
    const file = e.target.files && e.target.files[0];
    if (file) {
      try {
        const text = await file.text();
        keyfileData = JSON.parse(text);
        if (keyfileData.officer_id && !officerIdInput.value) {
          officerIdInput.value = keyfileData.officer_id;
        }
      } catch (err) {
        keyfileData = null;
      }
    } else {
      keyfileData = null;
    }
    validateForm();
  });
}

if (officerIdInput) {
  officerIdInput.addEventListener("input", validateForm);
}

if (passcodeInput) {
  passcodeInput.addEventListener("input", validateForm);
}

// Initialize on page load
window.addEventListener("DOMContentLoaded", () => {
  initCamera();
  loadGatewayStatus();
});
