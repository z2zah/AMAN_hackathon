"""
🔗 فاحص الروابط المتقدم | Advanced Link Scanner
يدخل على الرابط فعلياً ويحلل المحتوى!

الفحوصات:
1. تحليل URL (الدومين، المسار)
2. 🆕 فتح الرابط وتحليل محتوى الصفحة
3. 🆕 كشف صفحات التسجيل والتصيد
4. 🆕 وصف واضح للمستخدم بالعربي
"""

import re
import httpx
from urllib.parse import urlparse
from typing import List, Dict
from bs4 import BeautifulSoup

# ==================== الدومينات المشبوهة ====================
SUSPICIOUS_TLDS = ['.xyz', '.top', '.click', '.loan', '.work', '.date', '.racing', '.download', '.gdn', '.win', '.bid', '.trade']

URL_SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'cutt.ly', 'rb.gy', 'shorturl.at']

# المواقع المستهدفة للانتحال
TARGETED_BRANDS = {
    'paypal': ['paypa1', 'paypai', 'paypaI', 'paipal', 'paypall', 'pay-pal'],
    'apple': ['app1e', 'appie', 'applе', 'apple-id', 'icloud-verify'],
    'microsoft': ['micros0ft', 'microsft', 'ms-login', 'outlook-verify'],
    'google': ['g00gle', 'googie', 'google-verify', 'gmail-secure'],
    'amazon': ['amaz0n', 'amazn', 'amazon-prime'],
    'الراجحي': ['alrajhi-bank', 'rajhi-secure', 'alrajhi-update', 'rajhi-verify'],
    'الأهلي': ['alahli-bank', 'ahli-secure', 'snb-update', 'alahli-verify'],
    'stc': ['stc-pay', 'stc-reward', 'mystc-update', 'stc-verify'],
    'الإنماء': ['alinma-bank', 'inma-secure'],
    'البلاد': ['albilad-bank', 'bilad-secure']
}


def extract_urls(text: str) -> List[str]:
    """استخراج كل الروابط من النص"""
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    urls = re.findall(url_pattern, text)
    cleaned = []
    for url in urls:
        url = url.rstrip('.,;:!?)')
        if len(url) > 10:
            cleaned.append(url)
    return list(set(cleaned))


def analyze_url_syntax(url: str) -> Dict:
    """تحليل شكل الرابط فقط (بدون فتحه)"""
    result = {
        "url": url,
        "risk_score": 0,
        "flags": [],
        "domain": "",
        "is_shortened": False,
        "is_suspicious_tld": False,
        "impersonating": None
    }
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        result["domain"] = domain
        
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                result["is_suspicious_tld"] = True
                result["risk_score"] += 25
                result["flags"].append(f"نطاق مشبوه ({tld})")
                break
        
        for shortener in URL_SHORTENERS:
            if shortener in domain:
                result["is_shortened"] = True
                result["risk_score"] += 20
                result["flags"].append("رابط مختصر يخفي الوجهة")
                break
        
        for brand, fakes in TARGETED_BRANDS.items():
            for fake in fakes:
                if fake in domain:
                    result["impersonating"] = brand
                    result["risk_score"] += 40
                    result["flags"].append(f"محاولة انتحال {brand}")
                    break
        
        if not url.startswith('https://'):
            result["risk_score"] += 15
            result["flags"].append("بدون تشفير HTTPS")
        
        if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            result["risk_score"] += 30
            result["flags"].append("يستخدم IP بدل دومين")
            
    except:
        pass
    
    return result


async def fetch_and_analyze_content(url: str, timeout: float = 10.0) -> Dict:
    """
    🔥 الدالة الرئيسية: تفتح الرابط وتحلل المحتوى!
    """
    result = {
        "url": url,
        "accessible": False,
        "final_url": None,
        "redirected": False,
        "page_title": None,
        "page_description": None,
        "content_type": None,
        "has_login_form": False,
        "has_password_field": False,
        "has_email_field": False,
        "has_card_fields": False,
        "has_otp_field": False,
        "has_download_button": False,
        "form_action_external": False,
        "fields_detected": [],
        "arabic_description": "",
        "content_summary": "",
        "risk_score": 0,
        "flags": []
    }
    
    try:
        async with httpx.AsyncClient(
            follow_redirects=True, 
            timeout=timeout,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        ) as client:
            
            response = await client.get(url)
            
            if response.status_code == 200:
                result["accessible"] = True
                result["final_url"] = str(response.url)
                
                if str(response.url) != url:
                    result["redirected"] = True
                    result["flags"].append(f"تم توجيهك لـ: {response.url.host}")
                    result["risk_score"] += 15
                
                html = response.text
                soup = BeautifulSoup(html, 'html.parser')
                
                # عنوان الصفحة
                title_tag = soup.find('title')
                if title_tag:
                    result["page_title"] = title_tag.get_text().strip()[:100]
                
                # تحليل الفورمات والحقول
                all_inputs = soup.find_all('input')
                fields = []
                
                for inp in all_inputs:
                    inp_type = inp.get('type', '').lower()
                    inp_name = inp.get('name', '').lower()
                    inp_placeholder = inp.get('placeholder', '').lower()
                    inp_id = inp.get('id', '').lower()
                    
                    all_attrs = f"{inp_type} {inp_name} {inp_placeholder} {inp_id}"
                    
                    # كلمة مرور
                    if inp_type == 'password' or 'password' in all_attrs or 'pass' in all_attrs:
                        result["has_password_field"] = True
                        if "🔑 كلمة مرور" not in fields:
                            fields.append("🔑 كلمة مرور")
                    
                    # إيميل
                    if inp_type == 'email' or 'email' in all_attrs or 'mail' in all_attrs:
                        result["has_email_field"] = True
                        if "📧 بريد إلكتروني" not in fields:
                            fields.append("📧 بريد إلكتروني")
                    
                    # بطاقة بنكية
                    if any(x in all_attrs for x in ['card', 'credit', 'cvv', 'cvc', 'expir', 'بطاقة']):
                        result["has_card_fields"] = True
                        if "💳 بيانات بطاقة بنكية" not in fields:
                            fields.append("💳 بيانات بطاقة بنكية")
                    
                    # OTP
                    if any(x in all_attrs for x in ['otp', 'code', 'verify', 'token', 'رمز']):
                        result["has_otp_field"] = True
                        if "🔢 رمز تحقق OTP" not in fields:
                            fields.append("🔢 رمز تحقق OTP")
                    
                    # جوال
                    if any(x in all_attrs for x in ['phone', 'mobile', 'tel', 'جوال']):
                        if "📱 رقم جوال" not in fields:
                            fields.append("📱 رقم جوال")
                    
                    # هوية
                    if any(x in all_attrs for x in ['ssn', 'national', 'هوية']):
                        if "🪪 رقم هوية" not in fields:
                            fields.append("🪪 رقم هوية")
                    
                    # اسم مستخدم
                    if any(x in all_attrs for x in ['user', 'login', 'username']):
                        if "👤 اسم مستخدم" not in fields:
                            fields.append("👤 اسم مستخدم")
                
                result["fields_detected"] = fields
                
                # كشف نوع الصفحة
                html_lower = html.lower()
                
                if result["has_password_field"]:
                    result["has_login_form"] = True
                    result["content_type"] = "login"
                    result["risk_score"] += 30
                
                if result["has_card_fields"]:
                    result["content_type"] = "payment"
                    result["risk_score"] += 50
                
                if any(x in html_lower for x in ['download', 'تحميل', '.exe', '.apk']):
                    result["has_download_button"] = True
                    result["content_type"] = "download"
                    result["risk_score"] += 25
                
                # فحص action الفورم
                forms = soup.find_all('form')
                for form in forms:
                    action = form.get('action', '')
                    if action and not action.startswith('/') and not action.startswith('#'):
                        parsed_action = urlparse(action)
                        parsed_url = urlparse(url)
                        if parsed_action.netloc and parsed_action.netloc != parsed_url.netloc:
                            result["form_action_external"] = True
                            result["flags"].append("البيانات ترسل لموقع خارجي!")
                            result["risk_score"] += 30
                
                # بناء الوصف بالعربي
                result["arabic_description"] = build_arabic_description(result)
                result["content_summary"] = build_content_summary(result)
                
            else:
                result["flags"].append(f"الموقع رجع خطأ: {response.status_code}")
                
    except httpx.TimeoutException:
        result["flags"].append("الموقع بطيء جداً")
        result["risk_score"] += 10
    except Exception as e:
        result["flags"].append("تعذر الوصول للموقع")
    
    result["risk_score"] = min(result["risk_score"], 100)
    return result


def build_arabic_description(analysis: Dict) -> str:
    """بناء وصف واضح بالعربي"""
    parts = []
    
    if analysis.get("content_type") == "login":
        parts.append("📄 هذا الرابط يفتح صفحة تسجيل دخول")
    elif analysis.get("content_type") == "payment":
        parts.append("💳 هذا الرابط يفتح صفحة دفع/بيانات بنكية")
    elif analysis.get("content_type") == "download":
        parts.append("⬇️ هذا الرابط يفتح صفحة تحميل")
    
    fields = analysis.get("fields_detected", [])
    if fields:
        parts.append(f"\n\n🔍 الصفحة تطلب منك:\n" + "\n".join([f"  • {f}" for f in fields]))
    
    warnings = []
    if analysis.get("has_password_field"):
        warnings.append("يطلب كلمة مرورك")
    if analysis.get("has_card_fields"):
        warnings.append("يطلب بيانات بطاقتك البنكية!")
    if analysis.get("redirected"):
        warnings.append(f"تم توجيهك لموقع آخر")
    if analysis.get("form_action_external"):
        warnings.append("البيانات ترسل لموقع خارجي!")
    
    if warnings:
        parts.append(f"\n\n⚠️ تحذيرات:\n" + "\n".join([f"  • {w}" for w in warnings]))
    
    if analysis.get("page_title"):
        parts.append(f"\n\n📌 عنوان الصفحة: {analysis['page_title']}")
    
    if not parts:
        if analysis.get("accessible"):
            return "✅ صفحة عادية بدون طلب بيانات حساسة"
        return "❌ تعذر الوصول للرابط"
    
    return "".join(parts)


def build_content_summary(analysis: Dict) -> str:
    """ملخص قصير"""
    if analysis.get("has_card_fields"):
        return "🚨 صفحة تطلب بيانات بطاقة بنكية!"
    if analysis.get("has_password_field") and analysis.get("has_email_field"):
        return "⚠️ صفحة تسجيل دخول تطلب إيميل وكلمة مرور"
    if analysis.get("has_password_field"):
        return "⚠️ صفحة تطلب كلمة مرور"
    if analysis.get("has_otp_field"):
        return "⚠️ صفحة تطلب رمز تحقق OTP"
    if analysis.get("has_download_button"):
        return "⬇️ صفحة تحميل ملفات"
    if analysis.get("redirected"):
        return f"↪️ تم التوجيه لموقع آخر"
    if analysis.get("accessible"):
        return "✅ صفحة عادية"
    return "❓ تعذر الفحص"


async def full_link_analysis(url: str) -> Dict:
    """التحليل الكامل: syntax + محتوى"""
    syntax = analyze_url_syntax(url)
    content = await fetch_and_analyze_content(url)
    
    total_risk = min(syntax["risk_score"] + content["risk_score"], 100)
    all_flags = syntax["flags"] + content["flags"]
    
    if total_risk >= 70:
        verdict = "🚨 خطير جداً - لا تدخل!"
        verdict_class = "danger"
    elif total_risk >= 40:
        verdict = "⚠️ مشبوه - احذر"
        verdict_class = "warning"
    else:
        verdict = "✅ يبدو آمناً"
        verdict_class = "safe"
    
    return {
        "url": url,
        "domain": syntax["domain"],
        "risk_score": total_risk,
        "verdict": verdict,
        "verdict_class": verdict_class,
        "is_shortened": syntax["is_shortened"],
        "is_suspicious_tld": syntax["is_suspicious_tld"],
        "impersonating": syntax["impersonating"],
        "accessible": content["accessible"],
        "final_url": content["final_url"],
        "redirected": content["redirected"],
        "page_title": content["page_title"],
        "content_type": content["content_type"],
        "fields_detected": content["fields_detected"],
        "arabic_description": content["arabic_description"],
        "content_summary": content["content_summary"],
        "flags": all_flags
    }


async def scan_all_urls_deep(text: str) -> Dict:
    """فحص كل الروابط بالعمق"""
    urls = extract_urls(text)
    
    if not urls:
        return {
            "total_urls": 0,
            "dangerous_urls": 0,
            "urls": [],
            "overall_risk": 0,
            "summary": "لا توجد روابط"
        }
    
    results = []
    max_risk = 0
    dangerous_count = 0
    
    for url in urls[:5]:
        analysis = await full_link_analysis(url)
        results.append(analysis)
        if analysis["risk_score"] > max_risk:
            max_risk = analysis["risk_score"]
        if analysis["risk_score"] >= 50:
            dangerous_count += 1
    
    if dangerous_count > 0:
        summary = f"🚨 تم اكتشاف {dangerous_count} رابط خطير!"
    elif max_risk >= 40:
        summary = "⚠️ بعض الروابط مشبوهة"
    else:
        summary = "✅ الروابط تبدو آمنة"
    
    return {
        "total_urls": len(urls),
        "dangerous_urls": dangerous_count,
        "urls": results,
        "overall_risk": max_risk,
        "summary": summary
    }


def scan_all_urls(text: str) -> Dict:
    """فحص سريع بدون فتح"""
    urls = extract_urls(text)
    if not urls:
        return {"total_urls": 0, "dangerous_urls": 0, "urls": [], "overall_risk": 0}
    
    results = []
    max_risk = 0
    dangerous_count = 0
    
    for url in urls[:10]:
        analysis = analyze_url_syntax(url)
        results.append(analysis)
        if analysis["risk_score"] > max_risk:
            max_risk = analysis["risk_score"]
        if analysis["risk_score"] >= 50:
            dangerous_count += 1
    
    return {
        "total_urls": len(urls),
        "dangerous_urls": dangerous_count,
        "urls": results,
        "overall_risk": max_risk
    }
