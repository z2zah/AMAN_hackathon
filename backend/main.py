"""
🛡️ أمان | Aman API
الملف الرئيسي للسيرفر
مع التعلم التلقائي!
"""

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx
import json
import csv
import os
from datetime import datetime

# استيراد الملفات المحلية
from config import GROQ_API_KEY, RULE_WEIGHT, ML_WEIGHT, AI_WEIGHT
from rules import calculate_rule_score, detect_threat_type, extract_flags, get_actions, get_advice
from analytics import analytics
from ml_model import FraudDetectionModel
from link_scanner import scan_all_urls_deep, full_link_analysis, extract_urls

# ==================== مسار حفظ البيانات الجديدة ====================
NEW_DATA_PATH = "data/new_emails.csv"
TRAINING_DATA_PATH = "data/training_data.csv"
AUTO_RETRAIN_THRESHOLD = 20  # يعيد التدريب كل 20 رسالة جديدة
new_emails_count = 0

# ==================== إعداد التطبيق ====================
app = FastAPI(
    title="Aman API",
    description="نظام ذكي لكشف الاحتيال",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)

# ==================== تحميل نموذج ML ====================
ml_model = FraudDetectionModel()
try:
    ml_model.load()
    print("✅ تم تحميل نموذج ML")
except:
    print("⚠️ نموذج ML غير موجود، سيتم استخدام القواعد فقط")


# ==================== دوال التعلم التلقائي ====================
def save_email_for_learning(text: str, score: int, threat_type: str):
    """حفظ الإيميل تلقائياً للتعلم"""
    global new_emails_count
    
    # تحديد التصنيف بناءً على النتيجة
    label = 1 if score >= 50 else 0
    
    # تحويل نوع التهديد للإنجليزي
    threat_map = {
        "احتيال اجتماعي": "social_engineering",
        "انتحال صفة بنك": "bank_impersonation",
        "جوائز وهمية": "fake_prize",
        "تصيد احتيالي": "phishing",
        "طلب تحويل مشبوه": "money_transfer",
        "رسالة عادية": "safe"
    }
    threat_en = threat_map.get(threat_type, "unknown")
    
    # إنشاء الملف إذا ما موجود
    file_exists = os.path.exists(NEW_DATA_PATH)
    
    with open(NEW_DATA_PATH, 'a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(['text', 'label', 'threat_type', 'score', 'timestamp'])
        
        # تنظيف النص
        clean_text = text.replace('\n', ' ').replace('\r', ' ')[:500]
        writer.writerow([clean_text, label, threat_en, score, datetime.now().isoformat()])
    
    new_emails_count += 1
    print(f"📝 تم حفظ الإيميل #{new_emails_count} للتعلم")
    
    # إعادة التدريب التلقائي
    if new_emails_count >= AUTO_RETRAIN_THRESHOLD:
        auto_retrain()


def auto_retrain():
    """إعادة تدريب النموذج تلقائياً"""
    global new_emails_count
    
    print("\n🔄 بدء إعادة التدريب التلقائي...")
    
    try:
        # دمج البيانات الجديدة مع القديمة
        merge_training_data()
        
        # إعادة التدريب
        ml_model.train(TRAINING_DATA_PATH)
        ml_model.save()
        
        # إعادة تحميل النموذج
        ml_model.load()
        
        # تصفير العداد
        new_emails_count = 0
        
        print("✅ تم إعادة التدريب بنجاح!")
        return True
    except Exception as e:
        print(f"❌ خطأ في إعادة التدريب: {e}")
        return False


def merge_training_data():
    """دمج البيانات الجديدة مع بيانات التدريب"""
    if not os.path.exists(NEW_DATA_PATH):
        return
    
    # قراءة البيانات الجديدة
    new_rows = []
    with open(NEW_DATA_PATH, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            new_rows.append({
                'text': row['text'],
                'label': row['label'],
                'threat_type': row['threat_type']
            })
    
    # إضافتها لملف التدريب الأصلي
    with open(TRAINING_DATA_PATH, 'a', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['text', 'label', 'threat_type'])
        for row in new_rows:
            writer.writerow(row)
    
    # حذف ملف البيانات الجديدة
    os.remove(NEW_DATA_PATH)
    print(f"📊 تم دمج {len(new_rows)} رسالة جديدة")


# ==================== Models ====================
class Message(BaseModel):
    text: str

class LinkCheck(BaseModel):
    url: str


# ==================== HTML Page ====================
HTML_PAGE = """
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>أمان - حماية ذكية</title>
    <link href="https://fonts.googleapis.com/css2?family=Tajawal:wght@400;500;700;800&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Tajawal', sans-serif; background: linear-gradient(180deg, #0f1419 0%, #1a252f 100%); min-height: 100vh; color: #e7e9ea; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; }
        .header { text-align: center; padding: 30px 0; }
        .logo { font-size: 50px; }
        .brand { font-size: 2rem; font-weight: 800; margin: 10px 0; }
        .tagline { color: #71767b; }
        .badge { display: inline-block; margin-top: 10px; padding: 5px 15px; background: rgba(29,155,240,0.2); border-radius: 15px; font-size: 0.8rem; color: #1d9bf0; }
        .stats { display: flex; gap: 15px; justify-content: center; margin: 20px 0; flex-wrap: wrap; }
        .stat { background: rgba(255,255,255,0.05); padding: 15px 25px; border-radius: 10px; text-align: center; }
        .stat-value { font-size: 1.8rem; font-weight: 800; color: #1d9bf0; }
        .stat-label { font-size: 0.75rem; color: #71767b; }
        .stat.danger .stat-value { color: #f4212e; }
        .card { background: #192734; border: 1px solid #38444d; border-radius: 16px; padding: 25px; margin: 20px 0; }
        textarea { width: 100%; height: 120px; padding: 15px; border: 1px solid #38444d; border-radius: 12px; background: #0f1419; color: #e7e9ea; font-family: 'Tajawal'; font-size: 1rem; resize: none; margin-bottom: 15px; }
        textarea:focus { outline: none; border-color: #1d9bf0; }
        .btn { width: 100%; padding: 15px; border: none; border-radius: 12px; background: linear-gradient(90deg, #1d9bf0, #00d4aa); color: #fff; font-size: 1.1rem; font-weight: 700; cursor: pointer; }
        .btn:hover { opacity: 0.9; }
        .examples { margin-top: 15px; }
        .examples-title { font-size: 0.85rem; color: #71767b; margin-bottom: 10px; }
        .examples-grid { display: flex; gap: 8px; flex-wrap: wrap; }
        .ex-btn { padding: 8px 12px; background: rgba(255,255,255,0.05); border: 1px solid #38444d; border-radius: 8px; color: #e7e9ea; cursor: pointer; font-size: 0.8rem; }
        .ex-btn:hover { border-color: #1d9bf0; }
        .ex-btn.danger { border-color: rgba(244,33,46,0.3); color: #f4212e; }
        .loading { display: none; text-align: center; padding: 30px; }
        .spinner { width: 40px; height: 40px; border: 4px solid #38444d; border-top-color: #1d9bf0; border-radius: 50%; animation: spin 0.8s linear infinite; margin: 0 auto 15px; }
        @keyframes spin { to { transform: rotate(360deg); } }
        .result { display: none; }
        .result-card { border-radius: 16px; padding: 25px; border: 2px solid; margin-bottom: 15px; }
        .result-card.danger { background: linear-gradient(135deg, rgba(244,33,46,0.15) 0%, #1a252f 100%); border-color: #f4212e; }
        .result-card.warning { background: linear-gradient(135deg, rgba(255,212,0,0.15) 0%, #1a252f 100%); border-color: #ffd400; }
        .result-card.safe { background: linear-gradient(135deg, rgba(0,186,124,0.15) 0%, #1a252f 100%); border-color: #00ba7c; }
        .result-header { display: flex; align-items: center; gap: 15px; margin-bottom: 20px; }
        .result-icon { font-size: 40px; }
        .result-title { font-size: 1.3rem; font-weight: 700; }
        .result-card.danger .result-title { color: #f4212e; }
        .result-card.warning .result-title { color: #ffd400; }
        .result-card.safe .result-title { color: #00ba7c; }
        .score-row { display: flex; align-items: center; gap: 20px; margin-bottom: 20px; }
        .score-circle { width: 70px; height: 70px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 1.3rem; font-weight: 800; background: rgba(0,0,0,0.3); }
        .result-card.danger .score-circle { border: 3px solid #f4212e; color: #f4212e; }
        .result-card.warning .score-circle { border: 3px solid #ffd400; color: #ffd400; }
        .result-card.safe .score-circle { border: 3px solid #00ba7c; color: #00ba7c; }
        .threat-badge { padding: 6px 12px; border-radius: 15px; font-size: 0.85rem; background: rgba(0,0,0,0.3); }
        .section-title { font-size: 0.9rem; font-weight: 600; margin-bottom: 10px; color: #a8b3bd; }
        .flag-item { display: flex; gap: 10px; padding: 10px; background: rgba(0,0,0,0.2); border-radius: 8px; margin-bottom: 6px; }
        .flag-icon { font-size: 1.2rem; }
        .flag-title { font-weight: 600; }
        .flag-desc { font-size: 0.8rem; color: #71767b; }
        .flag-item.critical { border-right: 3px solid #f4212e; }
        .flag-item.high { border-right: 3px solid #ffd400; }
        .action-item { display: flex; gap: 10px; padding: 10px; background: rgba(29,155,240,0.1); border: 1px solid rgba(29,155,240,0.2); border-radius: 8px; margin-bottom: 6px; }
        .action-text { font-weight: 600; color: #1d9bf0; }
        .action-desc { font-size: 0.75rem; color: #71767b; }
        .advice-box { background: rgba(29,155,240,0.1); border: 1px solid rgba(29,155,240,0.2); border-radius: 10px; padding: 12px; margin-top: 15px; }
        .advice-title { font-weight: 600; color: #1d9bf0; font-size: 0.85rem; }
        .advice-text { color: #a8b3bd; font-size: 0.9rem; }
        .reset-btn { width: 100%; padding: 12px; background: transparent; border: 1px solid #38444d; border-radius: 10px; color: #71767b; cursor: pointer; }
        .reset-btn:hover { border-color: #1d9bf0; color: #1d9bf0; }
        .footer { text-align: center; padding: 30px 0; color: #536471; font-size: 0.8rem; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">🛡️</div>
            <div class="brand">أمان</div>
            <div class="tagline">نظام ذكي يحمي الإنسان من الاحتيال</div>
            <div class="badge">🧠 مدعوم بالذكاء الاصطناعي</div>
        </div>
        <div class="stats">
            <div class="stat"><div class="stat-value" id="total">0</div><div class="stat-label">تم تحليله</div></div>
            <div class="stat danger"><div class="stat-value" id="threats">0</div><div class="stat-label">تهديد</div></div>
            <div class="stat"><div class="stat-value" id="rate">0%</div><div class="stat-label">نسبة الحماية</div></div>
            <div class="stat" style="background:rgba(0,212,170,0.1);"><div class="stat-value" id="learning" style="color:#00d4aa;">0/20</div><div class="stat-label">🧠 تعلم تلقائي</div></div>
        </div>
        <div class="card" id="inputCard">
            <textarea id="msg" placeholder="الصق الإيميل المشبوه هنا..."></textarea>
            <button class="btn" onclick="analyze()">🔍 تحليل</button>
            <div class="examples">
                <div class="examples-title">🎯 أمثلة:</div>
                <div class="examples-grid">
                    <button class="ex-btn danger" onclick="setEx(1)">🏦 بنك</button>
                    <button class="ex-btn danger" onclick="setEx(2)">🎁 جائزة</button>
                    <button class="ex-btn danger" onclick="setEx(3)">👤 صديق</button>
                    <button class="ex-btn" onclick="setEx(4)">✅ آمن</button>
                </div>
            </div>
        </div>
        <div class="loading" id="loading"><div class="spinner"></div><p>جاري التحليل...</p></div>
        <div class="result" id="result">
            <div class="result-card" id="resultCard">
                <div class="result-header"><span class="result-icon" id="resIcon">🚨</span><div><div class="result-title" id="resTitle">تحذير</div><div style="color:#71767b;font-size:0.85rem;" id="resSub">تم اكتشاف تهديد</div></div></div>
                <div class="score-row"><div class="score-circle" id="score">85%</div><div><div style="color:#71767b;font-size:0.75rem;">نوع التهديد</div><div class="threat-badge" id="threat">-</div></div></div>
                <div id="flagsDiv"><div class="section-title">🚩 لماذا هذا خطر؟</div><div id="flags"></div></div>
                <div style="margin-top:15px;"><div class="section-title">🛡️ ماذا أفعل؟</div><div id="actions"></div></div>
                <div class="advice-box"><div class="advice-title">💡 نصيحة</div><div class="advice-text" id="advice">-</div></div>
                <div id="linksDiv" style="display:none;margin-top:15px;"><div class="section-title">🔗 الروابط المكتشفة</div><div id="links"></div></div>
            </div>
            <button class="reset-btn" onclick="reset()">↩️ تحليل آخر</button>
        </div>
        <div class="footer">أمان - نحوّل الموظف من نقطة ضعف إلى خط دفاع<br>جادة ثون 2025</div>
    </div>
    <script>
        const ex = {
            1: "تم إيقاف بطاقتك البنكية، حدث بياناتك فوراً: bank-update.xyz",
            2: "مبروك! ربحت 50,000 ريال، أرسل رقم بطاقتك فوراً",
            3: "أنا خويك من المدرسة، محتاج 1000 ريال ضروري",
            4: "تذكير: اجتماع الفريق غداً الساعة 10 صباحاً"
        };
        function setEx(n) { document.getElementById('msg').value = ex[n]; }
        function reset() { document.getElementById('inputCard').style.display='block'; document.getElementById('result').style.display='none'; document.getElementById('msg').value=''; }
        async function loadStats() { 
            try { 
                const r = await fetch('/stats'); 
                const d = await r.json(); 
                document.getElementById('total').textContent = d.total_analyzed; 
                document.getElementById('threats').textContent = d.threats_blocked; 
                document.getElementById('rate').textContent = d.protection_rate + '%'; 
                
                // تحميل حالة التعلم
                const lr = await fetch('/learning/status');
                const ld = await lr.json();
                document.getElementById('learning').textContent = ld.progress;
            } catch(e) {} 
        }
        loadStats();
        async function analyze() {
            const msg = document.getElementById('msg').value.trim();
            if (!msg) { alert('الصق الإيميل أولاً'); return; }
            document.getElementById('inputCard').style.display = 'none';
            document.getElementById('loading').style.display = 'block';
            try {
                const r = await fetch('/analyze', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({text: msg}) });
                const d = await r.json();
                showResult(d);
                loadStats();
            } catch(e) { alert('خطأ'); reset(); }
            document.getElementById('loading').style.display = 'none';
        }
        function showResult(d) {
            const s = d.risk_score || 0;
            const lv = s >= 70 ? 'danger' : s >= 40 ? 'warning' : 'safe';
            document.getElementById('resultCard').className = 'result-card ' + lv;
            document.getElementById('resIcon').textContent = s >= 70 ? '🚨' : s >= 40 ? '⚠️' : '✅';
            document.getElementById('resTitle').textContent = s >= 70 ? 'تحذير - خطر عالي' : s >= 40 ? 'مشبوه' : 'آمن';
            document.getElementById('resSub').textContent = s >= 70 ? 'لا تتفاعل!' : s >= 40 ? 'توخى الحذر' : 'لم يُكتشف تهديد';
            document.getElementById('score').textContent = s + '%';
            document.getElementById('threat').textContent = d.threat_type || '-';
            document.getElementById('advice').textContent = d.advice || '-';
            const fg = document.getElementById('flags');
            const fd = document.getElementById('flagsDiv');
            if (d.flags && d.flags.length > 0) {
                fg.innerHTML = d.flags.map(f => '<div class="flag-item '+f.severity+'"><span class="flag-icon">'+f.icon+'</span><div><div class="flag-title">'+f.title+'</div><div class="flag-desc">'+f.description+'</div></div></div>').join('');
                fd.style.display = 'block';
            } else { fd.style.display = 'none'; }
            const ac = document.getElementById('actions');
            if (d.actions) { ac.innerHTML = d.actions.map(a => '<div class="action-item"><span>'+a.icon+'</span><div><div class="action-text">'+a.action+'</div><div class="action-desc">'+a.description+'</div></div></div>').join(''); }
            
            // عرض الروابط مع التفاصيل
            const lk = document.getElementById('links');
            const ld = document.getElementById('linksDiv');
            if (d.links && d.links.total > 0) {
                lk.innerHTML = d.links.details.map(l => {
                    const lv = l.risk_score >= 70 ? 'critical' : l.risk_score >= 40 ? 'high' : '';
                    const ic = l.risk_score >= 70 ? '🚨' : l.risk_score >= 40 ? '⚠️' : '✅';
                    const fields = l.fields_detected && l.fields_detected.length > 0 
                        ? '<div style="font-size:10px;color:#f4212e;margin-top:3px;">يطلب: ' + l.fields_detected.join('، ') + '</div>' 
                        : '';
                    return '<div class="flag-item '+lv+'" style="cursor:pointer;" onclick="alert(`'+l.arabic_description.replace(/`/g,"'")+"`)\"><span class=\"flag-icon\">"+ic+"</span><div><div class=\"flag-title\" style=\"font-size:11px;word-break:break-all;\">"+l.domain+"</div><div class=\"flag-desc\">"+l.content_summary+"</div>"+fields+"</div></div>";
                }).join('');
                ld.style.display = 'block';
            } else { ld.style.display = 'none'; }
            
            document.getElementById('result').style.display = 'block';
        }
    </script>
</body>
</html>
"""


# ==================== API Endpoints ====================

@app.get("/", response_class=HTMLResponse)
async def home():
    """الصفحة الرئيسية"""
    return HTML_PAGE


@app.get("/stats")
async def get_stats():
    """الإحصائيات"""
    return analytics.get_stats()


@app.get("/model/status")
async def model_status():
    """حالة النموذج"""
    return {
        "is_trained": ml_model.is_trained,
        "message": "جاهز" if ml_model.is_trained else "غير مدرب"
    }


@app.post("/train")
async def train_model():
    """تدريب النموذج"""
    try:
        results = ml_model.train()
        ml_model.save()
        return {
            "success": True,
            "accuracy": results["accuracy"],
            "message": "تم التدريب بنجاح"
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.post("/retrain")
async def retrain_now():
    """إعادة التدريب الآن (يدوياً)"""
    success = auto_retrain()
    return {
        "success": success,
        "message": "تم إعادة التدريب" if success else "فشل إعادة التدريب"
    }


@app.get("/learning/status")
async def learning_status():
    """حالة التعلم التلقائي"""
    new_emails_exist = os.path.exists(NEW_DATA_PATH)
    
    # عد الرسائل الجديدة
    count = 0
    if new_emails_exist:
        with open(NEW_DATA_PATH, 'r', encoding='utf-8') as f:
            count = sum(1 for _ in f) - 1  # -1 للهيدر
    
    return {
        "new_emails_count": max(count, 0),
        "retrain_threshold": AUTO_RETRAIN_THRESHOLD,
        "progress": f"{max(count, 0)}/{AUTO_RETRAIN_THRESHOLD}",
        "model_trained": ml_model.is_trained,
        "message": f"باقي {AUTO_RETRAIN_THRESHOLD - max(count, 0)} رسالة لإعادة التدريب التلقائي"
    }


@app.post("/scan-link")
async def scan_link(link: LinkCheck):
    """فحص رابط واحد بالعمق"""
    result = await full_link_analysis(link.url)
    return result


@app.post("/scan-link-deep")
async def scan_link_deep(link: LinkCheck):
    """نفس scan-link (للتوافقية)"""
    return await scan_link(link)


@app.post("/analyze")
async def analyze(msg: Message):
    """تحليل إيميل"""
    
    # 1. تحليل بالقواعد
    rule_score = calculate_rule_score(msg.text)
    threat_type = detect_threat_type(msg.text)
    flags = extract_flags(msg.text)
    
    # 2. 🔗 فحص الروابط بالعمق (يدخل على المواقع!)
    link_scan = await scan_all_urls_deep(msg.text)
    link_risk = link_scan["overall_risk"]
    
    # إضافة تحذيرات الروابط
    for url_result in link_scan["urls"]:
        if url_result["risk_score"] >= 30:
            # إضافة ملخص المحتوى
            if url_result.get("content_summary"):
                flags.append({
                    "icon": "🔗",
                    "title": f"رابط: {url_result['domain'][:30]}",
                    "description": url_result["content_summary"],
                    "severity": "critical" if url_result["risk_score"] >= 70 else "high"
                })
    
    # 3. تحليل بـ ML (إذا متاح)
    ml_score = 0
    if ml_model.is_trained:
        ml_result = ml_model.predict(msg.text)
        ml_score = ml_result["risk_score"]
    
    # 4. تحليل بـ AI (إذا متاح)
    ai_score = 0
    if GROQ_API_KEY:
        try:
            async with httpx.AsyncClient() as client:
                prompt = f'حلل هذا الإيميل وأرجع JSON: {{"risk_score": 0-100}}\n"{msg.text[:400]}"'
                response = await client.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers={"Authorization": f"Bearer {GROQ_API_KEY}"},
                    json={"model": "llama-3.1-8b-instant", "messages": [{"role": "user", "content": prompt}], "temperature": 0.2},
                    timeout=10.0
                )
                data = response.json()
                if "choices" in data:
                    text = data["choices"][0]["message"]["content"]
                    text = text.replace("```json", "").replace("```", "").strip()
                    ai_result = json.loads(text)
                    ai_score = ai_result.get("risk_score", 0)
        except:
            pass
    
    # 5. حساب النتيجة النهائية
    if ml_model.is_trained and GROQ_API_KEY:
        base_score = int(rule_score * 0.25 + ml_score * 0.25 + ai_score * 0.2 + link_risk * 0.3)
    elif ml_model.is_trained:
        base_score = int(rule_score * 0.35 + ml_score * 0.3 + link_risk * 0.35)
    elif GROQ_API_KEY:
        base_score = int(rule_score * 0.35 + ai_score * 0.25 + link_risk * 0.4)
    else:
        base_score = int(rule_score * 0.5 + link_risk * 0.5)
    
    final_score = min(base_score, 100)
    
    # إذا فيه رابط خطير (يطلب بيانات)، ارفع النتيجة
    for url_result in link_scan["urls"]:
        if url_result.get("content_type") in ["payment", "login"]:
            if url_result["risk_score"] >= 50:
                final_score = max(final_score, 75)
                break
    
    # 6. الإجراءات والنصيحة
    actions = get_actions(final_score, flags)
    advice = get_advice(final_score, msg.text)
    
    # نصيحة خاصة بالروابط
    for url_result in link_scan["urls"]:
        if url_result.get("fields_detected"):
            fields_str = "، ".join([f.replace("🔑 ", "").replace("💳 ", "").replace("📧 ", "") for f in url_result["fields_detected"][:3]])
            advice = f"⚠️ الرابط يطلب: {fields_str}! " + advice
            break
    
    # 7. تسجيل
    analytics.record(final_score, threat_type)
    
    # 8. حفظ للتعلم
    save_email_for_learning(msg.text, final_score, threat_type)
    
    return {
        "risk_score": final_score,
        "threat_type": threat_type,
        "flags": flags,
        "actions": actions,
        "advice": advice,
        "links": {
            "total": link_scan["total_urls"],
            "dangerous": link_scan["dangerous_urls"],
            "summary": link_scan["summary"],
            "details": [{
                "url": u["url"],
                "domain": u["domain"],
                "risk_score": u["risk_score"],
                "verdict": u["verdict"],
                "content_summary": u["content_summary"],
                "arabic_description": u["arabic_description"],
                "fields_detected": u["fields_detected"],
                "page_title": u["page_title"]
            } for u in link_scan["urls"]]
        },
        "analysis_details": {
            "rule_score": rule_score,
            "ml_score": ml_score,
            "ai_score": ai_score,
            "link_risk": link_risk
        },
        "learning_status": f"تم حفظ ({new_emails_count}/{AUTO_RETRAIN_THRESHOLD})"
    }


# ==================== التشغيل ====================
if __name__ == "__main__":
    import uvicorn
    print("=" * 50)
    print("🛡️  أمان | Aman v3.0 - مع فحص الروابط!")
    print("=" * 50)
    print("🌐 http://localhost:8000")
    print("📊 http://localhost:8000/stats")
    print("🧠 http://localhost:8000/learning/status")
    print("🔗 http://localhost:8000/scan-link")
    print("=" * 50)
    uvicorn.run(app, host="0.0.0.0", port=8000)
