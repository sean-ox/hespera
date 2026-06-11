"""Scoring system for prioritization of URLs."""
from typing import List, Dict, Any


class ScoreCalculator:
    """Calculate priority score for URLs based on various indicators."""
    
    # Base scores per category
    CATEGORY_SCORES = {
        "admin": 90,
        "api": 70,
        "ssrf": 80,
        "redirect": 80,
        "idor": 75,
        "xss": 65,
        "js": 60,
        "parameterized": 50,
        "static": 10,
        "other": 20
    }
    
    # Additional score for specific parameter names
    HIGH_VALUE_PARAMS = {
        "id": 15,
        "user_id": 20,
        "password": 30,
        "token": 25,
        "secret": 30,
        "key": 25,
        "callback": 20,
        "url": 25,
        "redirect": 25,
        "document": 20,
        "file": 20
    }
    
    def score_urls(self, classified_urls: List[Dict[str, Any]], raw_urls: List[str] = None) -> List[Dict[str, Any]]:
        """Add a 'score' field to each URL."""
        scored = []
        for item in classified_urls:
            categories = item.get("categories", [])
            params = item.get("params", [])
            
            # Base score from highest category
            base_score = 0
            for cat in categories:
                base_score = max(base_score, self.CATEGORY_SCORES.get(cat, 20))
            
            # Parameter bonus
            param_bonus = 0
            for param in params:
                param_bonus += self.HIGH_VALUE_PARAMS.get(param, 0)
            param_bonus = min(param_bonus, 30)  # cap bonus
            
            # URL length penalty (very long URLs often low value)
            url_len = len(item["url"])
            length_penalty = 0
            if url_len > 200:
                length_penalty = 10
            elif url_len > 500:
                length_penalty = 20
            
            # Final score
            score = base_score + param_bonus - length_penalty
            score = max(0, min(100, score))  # clamp to 0-100
            
            item["score"] = score
            scored.append(item)
        
        # Sort by score descending
        scored.sort(key=lambda x: x["score"], reverse=True)
        return scored