import math
from typing import List

def normalize_score(retriever_type: str, score: float, query_scores: List[float]) -> float:
    # Predefined baseline maxima from historical analysis
    BASELINES = {
        "sparse": 1250.0,  
        "graph": 2.8,        
        "dense": 1.0        # Already normalized
    }
    
    baseline = BASELINES[retriever_type]
    
    # Simple normalization using baselines
    if retriever_type == "sparse":
        return min(score / baseline, 1.0)
        
    elif retriever_type == "graph":
        # Simple baseline normalization capped at 1.0
        return min(score / baseline, 1.0)
        
    else: # dense
        return min(score, 1.0)  # Cap dense scores at 1.0 for safety
