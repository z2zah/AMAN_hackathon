const API = "http://127.0.0.1:8000/analyze";
const statusEl = document.getElementById("status");
const btn = document.getElementById("btn");
const mainDiv = document.getElementById("main");
const resultDiv = document.getElementById("result");

function showMain() { mainDiv.style.display = "block"; resultDiv.style.display = "none"; }
function showResult() { mainDiv.style.display = "none"; resultDiv.style.display = "block"; }
function setStatus(msg, err = false) { statusEl.className = "status" + (err ? " error" : ""); statusEl.textContent = msg; }

async function getTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

btn.addEventListener("click", async () => {
  try {
    setStatus("📧 جاري قراءة الإيميل...");
    const tab = await getTab();
    if (!tab?.id || !tab.url?.includes("mail.google.com")) {
      setStatus("افتح Gmail أولاً", true);
      return;
    }
    const email = await chrome.tabs.sendMessage(tab.id, { type: "GET_EMAIL" });
    if (!email?.ok) {
      setStatus("افتح رسالة (مو القائمة) ثم حاول", true);
      return;
    }
    setStatus("🔍 جاري التحليل...");
    const resp = await fetch(API, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: email.data.fullText })
    });
    if (!resp.ok) {
      setStatus("تأكد أن السيرفر شغال على localhost:8000", true);
      return;
    }
    const data = await resp.json();
    chrome.tabs.sendMessage(tab.id, { type: "SHOW_RESULT", result: data });
    display(data);
  } catch (e) {
    setStatus("خطأ: " + (e?.message || e), true);
  }
});

document.getElementById("resetBtn").addEventListener("click", () => {
  showMain();
  setStatus("افتح إيميل في Gmail ثم اضغط تحليل");
});

function display(d) {
  const s = d.risk_score || 0;
  const lv = s >= 70 ? "danger" : s >= 40 ? "warning" : "safe";
  document.getElementById("card").className = "result-card " + lv;
  document.getElementById("icon").textContent = s >= 70 ? "🚨" : s >= 40 ? "⚠️" : "✅";
  document.getElementById("title").textContent = s >= 70 ? "تحذير - خطر!" : s >= 40 ? "مشبوه" : "آمن";
  document.getElementById("subtitle").textContent = s >= 70 ? "لا تتفاعل!" : s >= 40 ? "توخى الحذر" : "لم يُكتشف تهديد";
  document.getElementById("score").textContent = s + "%";
  document.getElementById("threat").textContent = d.threat_type || "-";
  document.getElementById("advice").textContent = d.advice || "-";
  
  const fg = document.getElementById("flags");
  const fd = document.getElementById("flagsDiv");
  if (d.flags && d.flags.length > 0) {
    fg.innerHTML = d.flags.map(f => 
      `<div class="flag-item ${f.severity}"><span class="flag-icon">${f.icon}</span><div><div class="flag-title">${f.title}</div><div class="flag-desc">${f.description}</div></div></div>`
    ).join("");
    fd.style.display = "block";
  } else {
    fd.style.display = "none";
  }
  
  const ac = document.getElementById("actions");
  if (d.actions) {
    ac.innerHTML = d.actions.map(a => 
      `<div class="action-item"><span>${a.icon}</span><div><div class="action-text">${a.action}</div><div class="action-desc">${a.description}</div></div></div>`
    ).join("");
  }
  
  showResult();
}
