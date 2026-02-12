"""
سجل التحليلات والإحصائيات
Analytics Store
"""

from datetime import datetime
from typing import Dict, List


class AnalyticsStore:
    """تخزين وتتبع إحصائيات التحليل"""
    
    def __init__(self):
        self.total_analyzed = 0
        self.high_risk_count = 0
        self.medium_risk_count = 0
        self.low_risk_count = 0
        self.threat_types: Dict[str, int] = {}
        self.recent_analyses: List[Dict] = []
        self.start_time = datetime.now()
    
    def record(self, score: int, threat_type: str):
        """تسجيل تحليل جديد"""
        self.total_analyzed += 1
        
        # تصنيف حسب الخطورة
        if score >= 70:
            self.high_risk_count += 1
        elif score >= 40:
            self.medium_risk_count += 1
        else:
            self.low_risk_count += 1
        
        # تسجيل نوع التهديد
        if threat_type != "رسالة عادية":
            self.threat_types[threat_type] = self.threat_types.get(threat_type, 0) + 1
        
        # حفظ آخر 100 تحليل
        self.recent_analyses.append({
            "timestamp": datetime.now().isoformat(),
            "score": score,
            "threat_type": threat_type
        })
        
        if len(self.recent_analyses) > 100:
            self.recent_analyses.pop(0)
    
    def get_stats(self) -> dict:
        """الحصول على الإحصائيات"""
        uptime = (datetime.now() - self.start_time).total_seconds()
        
        return {
            "total_analyzed": self.total_analyzed,
            "high_risk": self.high_risk_count,
            "medium_risk": self.medium_risk_count,
            "low_risk": self.low_risk_count,
            "threats_blocked": self.high_risk_count + self.medium_risk_count,
            "threat_breakdown": self.threat_types,
            "uptime_hours": round(uptime / 3600, 2),
            "protection_rate": round(
                (self.high_risk_count + self.medium_risk_count) / max(self.total_analyzed, 1) * 100, 
                1
            )
        }


# إنشاء instance واحد للاستخدام في كل المشروع
analytics = AnalyticsStore()
