# Small shared math/date helpers.
from datetime import datetime
import math
from typing import Optional 


# restricts a value to a specific range, defined by a minimum and maximum boundary 
def clamp(value: float, min_value: float = 0.0, max_value: float = 1.0) -> float:
    return max(min_value, min(max_value, value)) 

# smooth scaling curve (used for decay-based scoring) 
def logistic(value: float, half_life_days: float) -> float:
    if half_life_days <= 0:
        return 1.0 if value > 0 else 0.0 

    growth_rate = math.log(3) / half_life_days
    return clamp(1 / (1 + math.exp(-growth_rate * (value - half_life_days))))

# ensure value is between 0 and 1 
def normalize_ratio(ratio: Optional[float]) -> float:
    return clamp(0.0 if ratio is None else float(ratio)) 

    
# calculates number of days between two ISO date strings. 
def days_between(start_date_str: Optional[str], end_date_str: Optional[str]) -> Optional[int]:
    if not start_date_str or not end_date_str: 
        return None 
 
    try:
        start_date = datetime.fromisoformat(start_date_str.replace('Z', ''))
        end_date = datetime.fromisoformat(end_date_str.replace('Z', ''))

        return abs((end_date - start_date).days)
    except Exception:
        return None
  