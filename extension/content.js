/**
 * Aman Content Script
 * يعمل داخل Gmail ويحلل الإيميلات تلقائياً
 */

const API_URL = "http://127.0.0.1:8000/analyze";
let lastAnalyzedEmail = "";
let isAnalyzing = false;

// ========== استخراج محتوى الإيميل ==========
function extractEmailContent() {
  try {
    // الحصول على محتوى الإيميل
    const emailBody = document.querySelector('[data-message-id] .a3s.aiL') ||
                      document.querySelector('.a3s.aiL') ||
                      document.querySelector('[role="listitem"] .ii.gt');
    
    // الحصول على المرسل
    const senderEl = document.querySelector('[email]') ||
                     document.querySelector('.gD');
    
    // الحصول على الموضوع
    const subjectEl = document.querySelector('h2.hP') ||
                      document.querySelector('[data-thread-perm-id] h2');
    
    const body = emailBody?.innerText?.trim() || "";
    const sender = senderEl?.getAttribute('email') || senderEl?.innerText || "";
    const subject = subjectEl?.innerText?.trim() || "";
    
    const fullText = `From: ${sender}\nSubject: ${subject}\n\n${body}`;
    
    return { body, sender, subject, fullText };
  } catch (e) {
    console.error("Aman: Error extracting email", e);
    return null;
  }
}

// ========== إنشاء بانر النتيجة ==========
function createBanner(result) {
  // إزالة البانر القديم
  const oldBanner = document.getElementById('aman-banner');
  if (oldBanner) oldBanner.remove();
  
  const score = result.risk_score || 0;
  const level = score >= 70 ? 'danger' : score >= 40 ? 'warning' : 'safe';
  
  const colors = {
    danger: { bg: '#fee2e2', border: '#f87171', text: '#b91c1c', icon: '🚨' },
    warning: { bg: '#fef3c7', border: '#fbbf24', text: '#b45309', icon: '⚠️' },
    safe: { bg: '#d1fae5', border: '#34d399', text: '#065f46', icon: '✅' }
  };
  
  const color = colors[level];
  
  const banner = document.createElement('div');
  banner.id = 'aman-banner';
  banner.style.cssText = `
    position: fixed;
    top: 10px;
    right: 10px;
    z-index: 99999;
    background: ${color.bg};
    border: 2px solid ${color.border};
    border-radius: 12px;
    padding: 15px 20px;
    min-width: 280px;
    max-width: 350px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.15);
    font-family: 'Segoe UI', Tahoma, Arial, sans-serif;
    direction: rtl;
  `;
  
  // إنشاء محتوى البانر
  let flagsHtml = '';
  if (result.flags && result.flags.length > 0) {
    flagsHtml = `
      <div style="margin-top: 10px; padding-top: 10px; border-top: 1px solid ${color.border};">
        <div style="font-weight: 600; margin-bottom: 5px; color: ${color.text};">🚩 لماذا؟</div>
        ${result.flags.slice(0, 3).map(f => `
          <div style="display: flex; align-items: center; gap: 5px; font-size: 12px; margin: 3px 0; color: #333;">
            <span>${f.icon}</span>
            <span>${f.title}</span>
          </div>
        `).join('')}
      </div>
    `;
  }
  
  const titles = {
    danger: 'تحذير - خطر عالي!',
    warning: 'رسالة مشبوهة',
    safe: 'يبدو آمناً'
  };
  
  banner.innerHTML = `
    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px;">
      <span style="font-size: 28px;">${color.icon}</span>
      <div>
        <div style="font-weight: 700; font-size: 15px; color: ${color.text};">${titles[level]}</div>
        <div style="font-size: 12px; color: #666;">${result.threat_type || '-'}</div>
      </div>
      <div style="margin-right: auto; text-align: center;">
        <div style="font-size: 24px; font-weight: 800; color: ${color.text};">${score}%</div>
        <div style="font-size: 10px; color: #666;">خطورة</div>
      </div>
    </div>
    ${score >= 40 ? `<div style="font-size: 12px; color: ${color.text}; font-weight: 500;">💡 ${result.advice || 'كن حذراً!'}</div>` : ''}
    ${flagsHtml}
    <div style="display: flex; justify-content: space-between; margin-top: 10px; align-items: center;">
      <span style="font-size: 10px; color: #999;">🛡️ أمان</span>
      <button onclick="this.parentElement.parentElement.remove()" style="background: none; border: none; cursor: pointer; font-size: 12px; color: #666;">✕ إغلاق</button>
    </div>
  `;
  
  document.body.appendChild(banner);
  
  // إخفاء البانر بعد 15 ثانية (للآمن) أو 60 ثانية (للخطر)
  const hideDelay = score >= 70 ? 60000 : score >= 40 ? 30000 : 10000;
  setTimeout(() => banner.remove(), hideDelay);
}

// ========== تحليل الإيميل ==========
async function analyzeEmail() {
  if (isAnalyzing) return;
  
  const emailData = extractEmailContent();
  if (!emailData || !emailData.body || emailData.body.length < 5) return;
  
  // تجنب إعادة تحليل نفس الإيميل
  const emailHash = emailData.fullText.substring(0, 200);
  if (emailHash === lastAnalyzedEmail) return;
  
  lastAnalyzedEmail = emailHash;
  isAnalyzing = true;
  
  try {
    const response = await fetch(API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: emailData.fullText })
    });
    
    if (response.ok) {
      const result = await response.json();
      createBanner(result);
    }
  } catch (error) {
    // السيرفر مو شغال - صامت
    console.log("Aman: Server not available");
  }
  
  isAnalyzing = false;
}

// ========== مراقبة فتح إيميل جديد ==========
function setupAutoAnalysis() {
  // تحليل عند تحميل الصفحة (إذا كان هناك إيميل مفتوح)
  setTimeout(analyzeEmail, 2000);
  
  // مراقبة تغييرات URL (فتح إيميل جديد)
  let lastUrl = location.href;
  const urlObserver = new MutationObserver(() => {
    if (location.href !== lastUrl) {
      lastUrl = location.href;
      // انتظر تحميل محتوى الإيميل
      setTimeout(analyzeEmail, 1500);
    }
  });
  
  urlObserver.observe(document.body, { subtree: true, childList: true });
  
  // مراقبة ظهور محتوى الإيميل
  const contentObserver = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      if (mutation.addedNodes.length) {
        const hasEmailContent = document.querySelector('.a3s.aiL');
        if (hasEmailContent) {
          setTimeout(analyzeEmail, 1000);
          break;
        }
      }
    }
  });
  
  contentObserver.observe(document.body, { subtree: true, childList: true });
}

// ========== استقبال رسائل من popup ==========
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === "GET_EMAIL") {
    const emailData = extractEmailContent();
    if (emailData && emailData.body) {
      sendResponse({ ok: true, data: emailData });
    } else {
      sendResponse({ ok: false, error: "لم يتم العثور على إيميل مفتوح" });
    }
  }
  
  if (request.type === "SHOW_RESULT") {
    createBanner(request.result);
    sendResponse({ ok: true });
  }
  
  return true;
});

// ========== بدء التحليل التلقائي ==========
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', setupAutoAnalysis);
} else {
  setupAutoAnalysis();
}

console.log("🛡️ Aman: Auto-analysis enabled");
