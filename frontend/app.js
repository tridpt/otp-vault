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

// ----------------------- Khóa / mở khóa kho -----------------------
const lockScreen = document.getElementById("lockScreen");
const lockTitle = document.getElementById("lockTitle");
const lockPassword = document.getElementById("lockPassword");
const lockPassword2 = document.getElementById("lockPassword2");
const lockBtn = document.getElementById("lockBtn");
const lockError = document.getElementById("lockError");
const lockHint = document.getElementById("lockHint");
const lockNowBtn = document.getElementById("lockNowBtn");
const toggleHideBtn = document.getElementById("toggleHideBtn");

let unlocked = false;
let needSetup = false; // true = chưa có mật khẩu chủ -> chế độ thiết lập
let hideCodes = false; // ẩn mã trong danh sách

function showLockScreen() {
  unlocked = false;
  lockScreen.classList.remove("hidden");
  lockPassword.value = "";
  lockPassword2.value = "";
  clearError(lockError);
  if (needSetup) {
    lockTitle.textContent = "Tạo mật khẩu chủ để bảo vệ kho mã";
    lockPassword2.classList.remove("hidden");
    lockBtn.textContent = "Tạo & mở khóa";
    lockHint.textContent = "Mật khẩu này dùng để mã hóa dữ liệu. Quên là không khôi phục được.";
  } else {
    lockTitle.textContent = "Nhập mật khẩu chủ để mở khóa";
    lockPassword2.classList.add("hidden");
    lockBtn.textContent = "Mở khóa";
    lockHint.textContent = "";
  }
  lockPassword.focus();
}

function hideLockScreen() {
  unlocked = true;
  lockScreen.classList.add("hidden");
  loadAccounts();
}

async function refreshStatus() {
  try {
    const st = await api("/status");
    needSetup = !st.initialized;
    if (st.locked) {
      showLockScreen();
    } else {
      hideLockScreen();
    }
  } catch (err) {
    console.error(err);
  }
}

async function doUnlock() {
  clearError(lockError);
  const pw = lockPassword.value;
  if (!pw) {
    showError(lockError, "Hãy nhập mật khẩu.");
    return;
  }
  try {
    if (needSetup) {
      if (pw.length < 6) {
        showError(lockError, "Mật khẩu tối thiểu 6 ký tự.");
        return;
      }
      if (pw !== lockPassword2.value) {
        showError(lockError, "Hai mật khẩu không khớp.");
        return;
      }
      await api("/setup", { method: "POST", body: JSON.stringify({ password: pw }) });
    } else {
      await api("/unlock", { method: "POST", body: JSON.stringify({ password: pw }) });
    }
    needSetup = false;
    hideLockScreen();
  } catch (err) {
    showError(lockError, err.message);
  }
}

lockBtn.addEventListener("click", doUnlock);
lockPassword.addEventListener("keydown", (e) => { if (e.key === "Enter") doUnlock(); });
lockPassword2.addEventListener("keydown", (e) => { if (e.key === "Enter") doUnlock(); });

lockNowBtn.addEventListener("click", async () => {
  try {
    await api("/lock", { method: "POST" });
  } catch (err) {
    console.error(err);
  }
  accounts = [];
  renderAccounts();
  needSetup = false;
  showLockScreen();
});

toggleHideBtn.addEventListener("click", () => {
  hideCodes = !hideCodes;
  toggleHideBtn.textContent = hideCodes ? "👁️ Hiện mã" : "👁️ Ẩn mã";
  renderAccounts();
});

// ----------------------- Danh sách tài khoản -----------------------
const accountList = document.getElementById("accountList");
const emptyMsg = document.getElementById("emptyMsg");
const search = document.getElementById("search");

let accounts = [];

async function loadAccounts() {
  if (!unlocked) return;
  try {
    const data = await api("/accounts");
    accounts = data.accounts || [];
    renderAccounts();
  } catch (err) {
    // Hết hạn phiên (auto-lock) -> server trả 401 -> hiện lại màn khóa.
    if (String(err.message).includes("khóa")) {
      needSetup = false;
      showLockScreen();
    } else {
      console.error(err);
    }
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

async function renameAccount(id, currentName) {
  const name = prompt("Tên mới cho tài khoản:", currentName || "");
  if (name === null) return;
  try {
    await api("/accounts/" + id, {
      method: "PATCH",
      body: JSON.stringify({ name }),
    });
    await loadAccounts();
  } catch (err) {
    alert(err.message);
  }
}

async function moveAccount(id, direction) {
  // Sắp xếp dựa trên thứ tự đầy đủ hiện tại (không theo bộ lọc tìm kiếm).
  const idx = accounts.findIndex((a) => a.id === id);
  const target = idx + direction;
  if (idx < 0 || target < 0 || target >= accounts.length) return;
  const order = accounts.map((a) => a.id);
  [order[idx], order[target]] = [order[target], order[idx]];
  // Cập nhật ngay tại chỗ cho mượt, rồi đồng bộ server.
  [accounts[idx], accounts[target]] = [accounts[target], accounts[idx]];
  renderAccounts();
  try {
    await api("/accounts/reorder", {
      method: "POST",
      body: JSON.stringify({ ids: order }),
    });
  } catch (err) {
    console.error(err);
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
      const shown = hideCodes ? "••• •••" : formatCode(acc.code);
      item.innerHTML = `
        <div class="acc-info">
          <span class="acc-name">${escapeHtml(acc.name)}</span>
          <span class="acc-code" title="Bấm để copy">${shown}</span>
        </div>
        <div class="acc-right">
          <div class="ring" title="${acc.remaining}s còn lại">
            <span>${acc.remaining}</span>
            <div class="bar" style="width:${pct}%"></div>
          </div>
          <button class="iconbtn move-up" data-id="${acc.id}" title="Lên">▲</button>
          <button class="iconbtn move-down" data-id="${acc.id}" title="Xuống">▼</button>
          <button class="iconbtn edit" data-id="${acc.id}" title="Đổi tên">✎</button>
          <button class="reveal" data-id="${acc.id}" title="Hiện QR / secret">🔳</button>
          <button class="del" data-id="${acc.id}">✕</button>
        </div>`;
      const codeEl = item.querySelector(".acc-code");
      codeEl.addEventListener("click", () => {
        copyCode(acc.code);
        codeEl.classList.add("copied");
        setTimeout(() => codeEl.classList.remove("copied"), 600);
      });
      item.querySelector(".reveal").addEventListener("click", () =>
        revealAccount(acc.id)
      );
      item.querySelector(".edit").addEventListener("click", () =>
        renameAccount(acc.id, acc.name)
      );
      item.querySelector(".move-up").addEventListener("click", () =>
        moveAccount(acc.id, -1)
      );
      item.querySelector(".move-down").addEventListener("click", () =>
        moveAccount(acc.id, 1)
      );
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

// ----------------------- Hiện QR / secret -----------------------
const revealModal = document.getElementById("revealModal");
const revealClose = document.getElementById("revealClose");
const revealName = document.getElementById("revealName");
const revealQr = document.getElementById("revealQr");
const revealSecret = document.getElementById("revealSecret");
const revealCopy = document.getElementById("revealCopy");

async function revealAccount(id) {
  try {
    const data = await api("/accounts/" + id + "/reveal");
    revealName.textContent = data.name;
    revealQr.innerHTML = data.qr_svg || "<p class='hint'>(Không tạo được QR)</p>";
    revealSecret.textContent = data.secret;
    revealModal.classList.remove("hidden");
  } catch (err) {
    alert(err.message);
  }
}

function closeReveal() {
  revealModal.classList.add("hidden");
  revealQr.innerHTML = "";
  revealSecret.textContent = "";
}

revealClose.addEventListener("click", closeReveal);
revealModal.addEventListener("click", (e) => {
  if (e.target === revealModal) closeReveal();
});
revealCopy.addEventListener("click", () => {
  navigator.clipboard?.writeText(revealSecret.textContent);
  revealCopy.textContent = "Đã copy";
  setTimeout(() => (revealCopy.textContent = "Copy"), 800);
});

// ----------------------- Sao lưu / khôi phục -----------------------
const exportBtn = document.getElementById("exportBtn");
const importBtnFile = document.getElementById("importBtnFile");
const backupFile = document.getElementById("backupFile");
const backupMsg = document.getElementById("backupMsg");
const backupError = document.getElementById("backupError");

exportBtn.addEventListener("click", async () => {
  clearError(backupError);
  backupMsg.textContent = "";
  const pw = prompt("Đặt mật khẩu cho file sao lưu (tối thiểu 6 ký tự):");
  if (pw === null) return;
  if (pw.length < 6) {
    showError(backupError, "Mật khẩu sao lưu tối thiểu 6 ký tự.");
    return;
  }
  try {
    const data = await api("/export", {
      method: "POST",
      body: JSON.stringify({ password: pw }),
    });
    const blob = new Blob([JSON.stringify(data, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    const stamp = new Date().toISOString().slice(0, 10);
    a.href = url;
    a.download = `otp-vault-backup-${stamp}.json`;
    a.click();
    URL.revokeObjectURL(url);
    backupMsg.textContent = "Đã tạo file sao lưu. Giữ file + mật khẩu an toàn.";
  } catch (err) {
    showError(backupError, err.message);
  }
});

importBtnFile.addEventListener("click", () => backupFile.click());
backupFile.addEventListener("change", async () => {
  clearError(backupError);
  backupMsg.textContent = "";
  const file = backupFile.files && backupFile.files[0];
  if (!file) return;
  let backup;
  try {
    backup = JSON.parse(await file.text());
  } catch {
    showError(backupError, "File không phải JSON hợp lệ.");
    backupFile.value = "";
    return;
  }
  const pw = prompt("Nhập mật khẩu của file sao lưu:");
  backupFile.value = "";
  if (pw === null) return;
  try {
    const res = await api("/import", {
      method: "POST",
      body: JSON.stringify({ password: pw, backup }),
    });
    backupMsg.textContent = `Đã khôi phục ${res.added} tài khoản.`;
    await loadAccounts();
  } catch (err) {
    showError(backupError, err.message);
  }
});

// Tự làm mới mã mỗi giây khi đã mở khóa (cập nhật mã + đếm ngược).
setInterval(loadAccounts, 1000);

// Khởi động: kiểm tra trạng thái kho (cần thiết lập / khóa / mở).
refreshStatus();

// Đăng ký service worker để cài được như app (PWA).
if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("/sw.js").catch((err) =>
      console.warn("Đăng ký service worker thất bại:", err)
    );
  });
}
