from typing import Dict, List, Tuple
from detector import PromptDetector

class RiskScorer:
    """
    Risk scoring engine that assigns a numerical risk score based on detected attacks.
    """
    
    def __init__(self):
        # Define risk weights for different attack types (higher = more severe)
        self.risk_weights = {
            'data_exfiltration': 25,      # High risk - attempting to extract sensitive info
            'jailbreak_policy_bypass': 20, # High risk - bypassing safety measures
            'instruction_override': 20,    # Medium-high risk - changing behavior
            'role_escalation': 20,         # Medium-high risk - changing role
            'indirect_injection': 15       # Medium risk - potential manipulation
        }
        
        # Define severity multipliers based on number of matches
        self.severity_multipliers = {
            1: 1.0,  # 1 match - base risk
            2: 1.5,  # 2 matches - increased risk
            3: 2.0,  # 3 matches - significantly higher risk
            4: 2.5,  # 4+ matches - very high risk
        }
        
        self.detector = PromptDetector()

    def calculate_risk_score(self, prompt: str) -> Tuple[int, Dict[str, float]]:
        """
        Calculate the risk score for a given prompt.
        
        Args:
            prompt: The input prompt to analyze
            
        Returns:
            Tuple of (risk_score, breakdown_dict) where breakdown shows contribution of each attack type
        """
        detected_attacks = self.detector.detect_attacks(prompt)
        
        if not detected_attacks:
            return 0, {}  # No attacks detected, minimal risk
        
        total_risk = 0
        breakdown = {}
        
        for attack_type, matches in detected_attacks.items():
            if attack_type in self.risk_weights:
                base_weight = self.risk_weights[attack_type]
                num_matches = len(matches)
                
                # Apply severity multiplier based on number of matches
                multiplier = self.severity_multipliers.get(num_matches, 3.0)  # Cap at 3.0 for many matches
                attack_risk = base_weight * multiplier
                
                total_risk += attack_risk
                breakdown[attack_type] = {
                    'weight': base_weight,
                    'matches': num_matches,
                    'multiplier': multiplier,
                    'contribution': attack_risk
                }
        
        # Cap the risk score at 100
        risk_score = min(int(total_risk), 100)
        
        return risk_score, breakdown

    def get_risk_level(self, risk_score: int) -> str:
        """
        Convert numeric risk score to qualitative risk level.
        
        Args:
            risk_score: Risk score (0-100)
            
        Returns:
            Risk level as a string
        """
        if risk_score <= 39:
            return "Low"
        elif risk_score <= 69:
            return "Medium"
        else:
            return "High"

    def explain_risk(self, prompt: str) -> Dict:
        """
        Generate a full explanation of the risk assessment for the given prompt.
        
        Args:
            prompt: The input prompt to analyze
            
        Returns:
            Dictionary containing risk score, level, breakdown, and recommendation
        """
        risk_score, breakdown = self.calculate_risk_score(prompt)
        risk_level = self.get_risk_level(risk_score)
        
        # Determine action recommendation based on risk score
        if risk_score <= 39:
            action = "ALLOW"
        elif risk_score <= 69:
            action = "REWRITE"
        else:
            action = "BLOCK"
        
        return {
            'prompt': prompt,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'action': action,
            'breakdown': breakdown,
            'detected_attacks': list(breakdown.keys()) if breakdown else [],
            'explanation': self._generate_explanation(risk_score, breakdown)
        }

    def _generate_explanation(self, risk_score: int, breakdown: Dict) -> str:
        """
        Generate human-readable explanation of the risk assessment.
        
        Args:
            risk_score: Calculated risk score
            breakdown: Risk contribution breakdown by attack type
            
        Returns:
            Human-readable explanation
        """
        if risk_score == 0:
            return "No suspicious patterns detected. Prompt appears safe for processing."
        
        explanations = []
        
        for attack_type, details in breakdown.items():
            weight = details['weight']
            matches = details['matches']
            contribution = details['contribution']
            
            if attack_type == 'data_exfiltration':
                explanations.append(f"Detected potential data exfiltration attempt ({matches} occurrence{'s' if matches > 1 else ''}) - high risk.")
            elif attack_type == 'jailbreak_policy_bypass':
                explanations.append(f"Detected potential jailbreak/policy bypass attempt ({matches} occurrence{'s' if matches > 1 else ''}) - high risk.")
            elif attack_type == 'instruction_override':
                explanations.append(f"Detected instruction override attempt ({matches} occurrence{'s' if matches > 1 else ''}).")
            elif attack_type == 'role_escalation':
                explanations.append(f"Detected role escalation attempt ({matches} occurrence{'s' if matches > 1 else ''}).")
            elif attack_type == 'indirect_injection':
                explanations.append(f"Detected potential indirect injection attempt ({matches} occurrence{'s' if matches > 1 else ''}).")
        
        return " ".join(explanations)