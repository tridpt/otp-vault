"use strict";

const API = "/api";

// ----------------------- Tiện ích -----------------------
async function api(path, options = {}) {
  const res = await fetch(API + path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.detail || "Lỗi không xác định");
  }
  return data;
}

function showError(el, msg) {
  el.textContent = msg;
  el.classList.remove("hidden");
}

function clearError(el) {
  el.textContent = "";
  el.classList.add("hidden");
}

function formatCode(code) {
  // Chia 6 số thành "123 456" cho dễ đọc.
  if (!code) return "------";
  if (code.length === 6) return code.slice(0, 3) + " " + code.slice(3);
  return code;
}

// ----------------------- Sinh mã nhanh -----------------------
const quickSecret = document.getElementById("quickSecret");
const quickBtn = document.getElementById("quickBtn");
const quickResult = document.getElementById("quickResult");
const quickCode = document.getElementById("quickCode");
const quickCountdown = document.getElementById("quickCountdown");
const quickError = document.getElementById("quickError");

// Lưu lại secret đang xem để tự đếm ngược + tự lấy mã mới mỗi chu kỳ.
let quickState = null; // { secret, period }

async function refreshQuickCode() {
  if (!quickState) return;
  try {
    const data = await api("/generate", {
      method: "POST",
      body: JSON.stringify({ secret: quickState.secret }),
    });
    quickState.period = data.period;
    quickCode.textContent = formatCode(data.code);
  } catch (err) {
    quickState = null;
    quickResult.classList.add("hidden");
    showError(quickError, err.message);
  }
}

async function doQuick() {
  clearError(quickError);
  const secret = quickSecret.value.trim();
  if (!secret) {
    showError(quickError, "Hãy nhập secret key.");
    return;
  }
  quickState = { secret, period: 30 };
  quickResult.classList.remove("hidden");
  await refreshQuickCode();
}

// Tự cập nhật đếm ngược cho ô "Sinh mã nhanh" mỗi giây (theo đồng hồ máy).
setInterval(() => {
  if (!quickState) return;
  const period = quickState.period || 30;
  const remaining = period - (Math.floor(Date.now() / 1000) % period);
  quickCountdown.textContent = remaining + "s";
  // Vừa sang chu kỳ mới -> lấy mã mới.
  if (remaining === period) refreshQuickCode();
}, 1000);

quickBtn.addEventListener("click", doQuick);
quickSecret.addEventListener("keydown", (e) => {
  if (e.key === "Enter") doQuick();
});

// ----------------------- Thêm / nhập tài khoản -----------------------
const accName = document.getElementById("accName");
const accSecret = document.getElementById("accSecret");
const addBtn = document.getElementById("addBtn");
const otpauthUri = document.getElementById("otpauthUri");
const importBtn = document.getElementById("importBtn");
const addError = document.getElementById("addError");

async function addAccount() {
  clearError(addError);
  const secret = accSecret.value.trim();
  if (!secret) {
    showError(addError, "Hãy nhập secret key.");
    return;
  }
  try {
    await api("/accounts", {
      method: "POST",
      body: JSON.stringify({ name: accName.value.trim(), secret }),
    });
    accName.value = "";
    accSecret.value = "";
    await loadAccounts();
  } catch (err) {
    showError(addError, err.message);
  }
}

async function importUri() {
  clearError(addError);
  const uri = otpauthUri.value.trim();
  if (!uri) {
    showError(addError, "Hãy dán chuỗi otpauth://...");
    return;
  }
  try {
    await api("/accounts/import-uri", {
      method: "POST",
      body: JSON.stringify({ uri }),
    });
    otpauthUri.value = "";
    await loadAccounts();
  } catch (err) {
    showError(addError, err.message);
  }
}

addBtn.addEventListener("click", addAccount);
importBtn.addEventListener("click", importUri);
accSecret.addEventListener("keydown", (e) => {
  if (e.key === "Enter") addAccount();
});

// ----------------------- Quét QR -----------------------
const scanCamBtn = document.getElementById("scanCamBtn");
const scanFileBtn = document.getElementById("scanFileBtn");
const qrFile = document.getElementById("qrFile");
const camWrap = document.getElementById("camWrap");
const camVideo = document.getElementById("camVideo");
const camStatus = document.getElementById("camStatus");
const camStopBtn = document.getElementById("camStopBtn");

let camStream = null;
let camRAF = null;
const qrCanvas = document.createElement("canvas");
const qrCtx = qrCanvas.getContext("2d", { willReadFrequently: true });

// Gửi chuỗi otpauth quét được lên server để lưu tài khoản.
async function submitScanned(text) {
  if (!text || !text.toLowerCase().startsWith("otpauth://")) {
    showError(addError, "Mã QR không phải dạng 2FA (otpauth://).");
    return false;
  }
  try {
    await api("/accounts/import-uri", {
      method: "POST",
      body: JSON.stringify({ uri: text }),
    });
    await loadAccounts();
    return true;
  } catch (err) {
    showError(addError, err.message);
    return false;
  }
}

// --- Quét từ ảnh tải lên ---
scanFileBtn.addEventListener("click", () => qrFile.click());
qrFile.addEventListener("change", () => {
  clearError(addError);
  const file = qrFile.files && qrFile.files[0];
  if (!file) return;
  const img = new Image();
  img.onload = async () => {
    qrCanvas.width = img.naturalWidth;
    qrCanvas.height = img.naturalHeight;
    qrCtx.drawImage(img, 0, 0);
    const imgData = qrCtx.getImageData(0, 0, qrCanvas.width, qrCanvas.height);
    const result = window.jsQR(imgData.data, imgData.width, imgData.height);
    URL.revokeObjectURL(img.src);
    if (result && result.data) {
      await submitScanned(result.data);
    } else {
      showError(addError, "Không tìm thấy mã QR trong ảnh.");
    }
    qrFile.value = "";
  };
  img.onerror = () => showError(addError, "Không đọc được ảnh.");
  img.src = URL.createObjectURL(file);
});

// --- Quét bằng camera ---
function stopCamera() {
  if (camRAF) cancelAnimationFrame(camRAF);
  camRAF = null;
  if (camStream) {
    camStream.getTracks().forEach((t) => t.stop());
    camStream = null;
  }
  camWrap.classList.add("hidden");
}

function scanCameraFrame() {
  if (!camStream) return;
  if (camVideo.readyState === camVideo.HAVE_ENOUGH_DATA) {
    qrCanvas.width = camVideo.videoWidth;
    qrCanvas.height = camVideo.videoHeight;
    qrCtx.drawImage(camVideo, 0, 0, qrCanvas.width, qrCanvas.height);
    const imgData = qrCtx.getImageData(0, 0, qrCanvas.width, qrCanvas.height);
    const result = window.jsQR(imgData.data, imgData.width, imgData.height);
    if (result && result.data) {
      camStatus.textContent = "Đã quét được mã, đang lưu...";
      submitScanned(result.data).then((ok) => {
        if (ok) {
          stopCamera();
        } else {
          // Mã không hợp lệ -> tiếp tục quét.
          camRAF = requestAnimationFrame(scanCameraFrame);
        }
      });
      return;
    }
  }
  camRAF = requestAnimationFrame(scanCameraFrame);
}

scanCamBtn.addEventListener("click", async () => {
  clearError(addError);
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    showError(addError, "Trình duyệt không hỗ trợ camera.");
    return;
  }
  try {
    camStream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: "environment" },
    });
    camVideo.srcObject = camStream;
    await camVideo.play();
    camStatus.textContent = "Đang tìm mã QR...";
    camWrap.classList.remove("hidden");
    camRAF = requestAnimationFrame(scanCameraFrame);
  } catch (err) {
    showError(addError, "Không mở được camera: " + err.message);
  }
});

camStopBtn.addEventListener("click", stopCamera);

// ----------------------- Danh sách tài khoản -----------------------
const accountList = document.getElementById("accountList");
const emptyMsg = document.getElementById("emptyMsg");
const search = document.getElementById("search");

let accounts = [];

async function loadAccounts() {
  try {
    const data = await api("/accounts");
    accounts = data.accounts || [];
    renderAccounts();
  } catch (err) {
    console.error(err);
  }
}

async function deleteAccount(id) {
  if (!confirm("Xóa tài khoản này?")) return;
  try {
    await api("/accounts/" + id, { method: "DELETE" });
    await loadAccounts();
  } catch (err) {
    alert(err.message);
  }
}

function copyCode(code) {
  const raw = code.replace(/\s/g, "");
  navigator.clipboard?.writeText(raw);
}

function renderAccounts() {
  const term = search.value.trim().toLowerCase();
  const filtered = accounts.filter((a) =>
    (a.name || "").toLowerCase().includes(term)
  );

  accountList.innerHTML = "";
  emptyMsg.classList.toggle("hidden", accounts.length > 0);

  filtered.forEach((acc) => {
    const item = document.createElement("div");
    item.className = "account-item";

    if (acc.error) {
      item.innerHTML = `
        <div class="acc-info">
          <span class="acc-name">${escapeHtml(acc.name)}</span>
          <span class="error-inline">⚠ ${escapeHtml(acc.error)}</span>
        </div>
        <button class="del" data-id="${acc.id}">✕</button>`;
    } else {
      const pct = Math.round((acc.remaining / acc.period) * 100);
      item.innerHTML = `
        <div class="acc-info">
          <span class="acc-name">${escapeHtml(acc.name)}</span>
          <span class="acc-code" title="Bấm để copy">${formatCode(acc.code)}</span>
        </div>
        <div class="acc-right">
          <div class="ring" title="${acc.remaining}s còn lại">
            <span>${acc.remaining}</span>
            <div class="bar" style="width:${pct}%"></div>
          </div>
          <button class="del" data-id="${acc.id}">✕</button>
        </div>`;
      const codeEl = item.querySelector(".acc-code");
      codeEl.addEventListener("click", () => {
        copyCode(acc.code);
        codeEl.classList.add("copied");
        setTimeout(() => codeEl.classList.remove("copied"), 600);
      });
    }

    item.querySelector(".del").addEventListener("click", () =>
      deleteAccount(acc.id)
    );
    accountList.appendChild(item);
  });
}

function escapeHtml(str) {
  return String(str || "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

search.addEventListener("input", renderAccounts);

// Tự làm mới mã mỗi giây (cập nhật mã + đếm ngược).
setInterval(loadAccounts, 1000);
loadAccounts();
