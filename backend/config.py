"""
إعدادات المشروع
"""
import os

# API Keys
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")

# المسارات
DATA_PATH = "data/training_data.csv"
MODEL_PATH = "models/fraud_model.pkl"
VECTORIZER_PATH = "models/vectorizer.pkl"

# أوزان التحليل
RULE_WEIGHT = 0.4      # 40% للقواعد
ML_WEIGHT = 0.4        # 40% للـ ML
AI_WEIGHT = 0.2        # 20% للـ AI (Groq)

# حدود الخطر
HIGH_RISK = 70
MEDIUM_RISK = 40
