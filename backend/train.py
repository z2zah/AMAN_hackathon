"""
🧠 سكربت تدريب نموذج أمان
===========================

هذا الملف لتدريب نموذج ML لكشف الاحتيال

طريقة الاستخدام:
    python train.py

الخطوات:
1. يقرأ بيانات التدريب من data/training_data.csv
2. يدرب النموذج (Random Forest + TF-IDF)
3. يحفظ النموذج في models/
4. يعرض نتائج الدقة
"""

from ml_model import FraudDetectionModel

def main():
    print("=" * 60)
    print("🛡️  تدريب نموذج أمان لكشف الاحتيال")
    print("=" * 60)
    
    # إنشاء النموذج
    model = FraudDetectionModel()
    
    # التدريب
    print("\n📚 بدء التدريب...")
    results = model.train("data/training_data.csv")
    
    # حفظ النموذج
    print("\n💾 حفظ النموذج...")
    model.save()
    
    # اختبار سريع
    print("\n" + "=" * 60)
    print("🧪 اختبار النموذج:")
    print("=" * 60)
    
    test_cases = [
        ("تم إيقاف بطاقتك، حدث بياناتك: bank.xyz", "🚨 متوقع: احتيال"),
        ("مبروك! ربحت مليون ريال", "🚨 متوقع: احتيال"),
        ("اجتماع الفريق غداً الساعة 10", "✅ متوقع: آمن"),
        ("Your account suspended. Click: verify.top", "🚨 متوقع: احتيال"),
    ]
    
    for text, expected in test_cases:
        result = model.predict(text)
        status = "🚨 احتيال" if result["is_fraud"] else "✅ آمن"
        print(f"\n{expected}")
        print(f"   النتيجة: {status} ({result['risk_score']}%)")
        print(f"   النص: {text[:40]}...")
    
    # أهم الكلمات
    print("\n" + "=" * 60)
    print("📊 أهم 15 كلمة في التصنيف:")
    print("=" * 60)
    
    words = model.get_important_words(15)
    for i, w in enumerate(words, 1):
        bar = "█" * int(w['importance'] * 200)
        print(f"{i:2}. {w['word']:15} {bar}")
    
    print("\n" + "=" * 60)
    print("✅ تم التدريب بنجاح!")
    print("   الدقة: {:.1f}%".format(results['accuracy'] * 100))
    print("=" * 60)


if __name__ == "__main__":
    main()
