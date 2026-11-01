from typing import List, Dict, Any

class RiskEngine:
    @staticmethod
    def calculate_org_risk(scan_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculates an aggregate cybersecurity risk score based on exposed assets."""
        risk_weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 5, "LOW": 1, "INFO": 0, "NONE": 0}
        total_score = 0
        highest_risk = "NONE"
        
        for res in scan_results:
            if res.get("status") == "OPEN":
                r_level = res.get("risk_level", "INFO")
                score = risk_weights.get(r_level, 0)
                total_score += score
                
                if score > risk_weights.get(highest_risk, 0):
                    highest_risk = r_level

        # Normalize score (Cap at 100)
        normalized_score = min(total_score, 100)
        
        if normalized_score >= 50:
            grade = "F (Critical Exposure)"
        elif normalized_score >= 25:
            grade = "D (High Risk)"
        elif normalized_score >= 10:
            grade = "C (Moderate Risk)"
        elif normalized_score > 0:
            grade = "B (Low Risk)"
        else:
            grade = "A (Secure Baseline)"

        return {
            "aggregate_score": normalized_score,
            "overall_grade": grade,
            "highest_exposure": highest_risk
        }