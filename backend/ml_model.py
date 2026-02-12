"""
نموذج تعلم الآلة لكشف الاحتيال
Machine Learning Model for Fraud Detection

هذا الملف يشرح كيف نبني نموذج ML للمشروع
"""

import os
import pickle
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

# المسارات
DATA_PATH = "data/training_data.csv"
MODEL_PATH = "models/fraud_model.pkl"
VECTORIZER_PATH = "models/vectorizer.pkl"


class FraudDetectionModel:
    """
    نموذج كشف الاحتيال باستخدام Random Forest + TF-IDF
    
    الخطوات:
    1. تحويل النص إلى أرقام (TF-IDF)
    2. تدريب Random Forest على التصنيف
    3. حفظ النموذج للاستخدام لاحقاً
    """
    
    def __init__(self):
        # TF-IDF: يحول النص إلى vector من الأرقام
        # - max_features: أقصى عدد كلمات
        # - ngram_range: كلمات فردية وثنائية
        self.vectorizer = TfidfVectorizer(
            max_features=3000,
            ngram_range=(1, 2),  # "بطاقة" + "بطاقة مجمدة"
            min_df=1
        )
        
        # Random Forest: خوارزمية التصنيف
        # - n_estimators: عدد الأشجار
        # - class_weight: لموازنة البيانات
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            class_weight='balanced',
            random_state=42
        )
        
        self.is_trained = False
    
    def train(self, data_path: str = DATA_PATH):
        """
        تدريب النموذج
        
        Args:
            data_path: مسار ملف CSV
        
        Returns:
            dict: نتائج التدريب (accuracy, report)
        """
        print("📚 جاري تحميل البيانات...")
        
        # قراءة البيانات
        df = pd.read_csv(data_path)
        print(f"   عدد السجلات: {len(df)}")
        print(f"   احتيال: {len(df[df['label']==1])}")
        print(f"   آمن: {len(df[df['label']==0])}")
        
        # تقسيم البيانات (80% تدريب، 20% اختبار)
        X = df['text']
        y = df['label']
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, 
            test_size=0.2, 
            random_state=42,
            stratify=y  # للحفاظ على نسبة التصنيفات
        )
        
        print("\n🔄 جاري تحويل النص إلى أرقام (TF-IDF)...")
        X_train_vec = self.vectorizer.fit_transform(X_train)
        X_test_vec = self.vectorizer.transform(X_test)
        
        print(f"   شكل البيانات: {X_train_vec.shape}")
        
        print("\n🧠 جاري تدريب النموذج...")
        self.model.fit(X_train_vec, y_train)
        
        # تقييم النموذج
        print("\n📊 تقييم النموذج:")
        y_pred = self.model.predict(X_test_vec)
        
        accuracy = accuracy_score(y_test, y_pred)
        report = classification_report(y_test, y_pred, target_names=['آمن', 'احتيال'])
        
        print(f"\n   الدقة: {accuracy * 100:.1f}%")
        print(f"\n{report}")
        
        self.is_trained = True
        
        return {
            "accuracy": accuracy,
            "report": report,
            "train_size": len(X_train),
            "test_size": len(X_test)
        }
    
    def predict(self, text: str) -> dict:
        """
        تحليل نص جديد
        
        Args:
            text: النص المراد تحليله
        
        Returns:
            dict: نتيجة التحليل
        """
        if not self.is_trained:
            return {
                "is_fraud": False,
                "confidence": 0,
                "risk_score": 0,
                "error": "النموذج غير مدرب"
            }
        
        # تحويل النص إلى vector
        text_vec = self.vectorizer.transform([text])
        
        # التنبؤ
        prediction = self.model.predict(text_vec)[0]
        probabilities = self.model.predict_proba(text_vec)[0]
        
        # احتمالية الاحتيال
        fraud_prob = probabilities[1] if len(probabilities) > 1 else 0
        
        return {
            "is_fraud": bool(prediction),
            "confidence": float(max(probabilities)),
            "fraud_probability": float(fraud_prob),
            "risk_score": int(fraud_prob * 100)
        }
    
    def save(self, model_path: str = MODEL_PATH, vectorizer_path: str = VECTORIZER_PATH):
        """حفظ النموذج"""
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        
        with open(model_path, 'wb') as f:
            pickle.dump(self.model, f)
        
        with open(vectorizer_path, 'wb') as f:
            pickle.dump(self.vectorizer, f)
        
        print(f"✅ تم حفظ النموذج في: {model_path}")
        print(f"✅ تم حفظ الـ Vectorizer في: {vectorizer_path}")
    
    def load(self, model_path: str = MODEL_PATH, vectorizer_path: str = VECTORIZER_PATH):
        """تحميل النموذج"""
        try:
            with open(model_path, 'rb') as f:
                self.model = pickle.load(f)
            
            with open(vectorizer_path, 'rb') as f:
                self.vectorizer = pickle.load(f)
            
            self.is_trained = True
            print("✅ تم تحميل النموذج بنجاح")
            return True
        except FileNotFoundError:
            print("⚠️ النموذج غير موجود، يرجى التدريب أولاً")
            return False
    
    def get_important_words(self, top_n: int = 20):
        """أهم الكلمات في التصنيف"""
        if not self.is_trained:
            return []
        
        feature_names = self.vectorizer.get_feature_names_out()
        importances = self.model.feature_importances_
        
        # ترتيب حسب الأهمية
        indices = importances.argsort()[::-1][:top_n]
        
        words = []
        for i in indices:
            words.append({
                "word": feature_names[i],
                "importance": float(importances[i])
            })
        
        return words


# ==================== للتشغيل المباشر ====================
if __name__ == "__main__":
    print("=" * 50)
    print("🛡️ تدريب نموذج أمان لكشف الاحتيال")
    print("=" * 50)
    
    # إنشاء النموذج
    model = FraudDetectionModel()
    
    # التدريب
    results = model.train()
    
    # حفظ النموذج
    model.save()
    
    # اختبار
    print("\n" + "=" * 50)
    print("🧪 اختبار النموذج:")
    print("=" * 50)
    
    test_texts = [
        "تم إيقاف بطاقتك، حدث بياناتك فوراً عبر الرابط: bank.xyz",
        "مبروك! ربحت مليون ريال، أرسل بياناتك",
        "تذكير: اجتماع الفريق غداً الساعة 10",
        "Your account suspended. Click here: verify.top"
    ]
    
    for text in test_texts:
        result = model.predict(text)
        status = "🚨 احتيال" if result["is_fraud"] else "✅ آمن"
        print(f"\n{status} ({result['risk_score']}%)")
        print(f"   النص: {text[:50]}...")
    
    # أهم الكلمات
    print("\n" + "=" * 50)
    print("📊 أهم 10 كلمات في التصنيف:")
    print("=" * 50)
    
    words = model.get_important_words(10)
    for w in words:
        print(f"   {w['word']}: {w['importance']:.4f}")
