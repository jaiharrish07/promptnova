import re
from typing import Dict, List, Tuple

class PromptDetector:
    """
    Rule-based detector for identifying prompt injection attacks.
    """
    
    def __init__(self):
        # Define regex patterns for different attack types
        self.patterns = {
            'instruction_override': [
                r'ignore.*previous.*instructions',
                r'disregard.*previous.*instructions',
                r'forget.*previous.*instructions',
                r'override.*instructions',
                r'bypass.*instructions',
                r'circumvent.*instructions'
            ],
            'role_escalation': [
                # Role-play phrasing is common in benign prompts ("act as a travel guide").
                # We only flag role escalation when it targets privileged / unrestricted roles.
                r'\bact as (an? )?(unrestricted|unfiltered|uncensored|hacker|attacker|root|admin|developer|system|dan|jailbreak)\b',
                r'\bpretend to be (an? )?(unrestricted|unfiltered|uncensored|hacker|attacker|root|admin|developer|system|dan|jailbreak)\b',
                r'\byou are now (an? )?(unrestricted|unfiltered|uncensored|hacker|attacker|root|admin|developer|system|dan|jailbreak)\b',
                r'\bassume the role of (an? )?(unrestricted|unfiltered|uncensored|hacker|attacker|root|admin|developer|system|dan|jailbreak)\b',
                r'\bdeveloper mode\b',
                r'\bunrestricted ai\b'
            ],
            'data_exfiltration': [
                r'reveal.*system.*prompt',
                r'show.*your.*instructions',
                r'display.*system.*message',
                r'expose.*internal.*instructions',
                r'print.*hidden.*instructions',
                r'leak.*system.*prompt'
            ],
            'jailbreak_policy_bypass': [
                r'bypass.*safety',
                r'circumvent.*policy',
                r'override.*safety',
                r'ignore.*safety',
                r'disable.*filter',
                r'avoid.*moderation'
            ],
            'indirect_injection': [
                r'\[.*system.*\]',
                r'<.*system.*>',
                r'\{.*system.*\}',
                r'\\begin\{.*system.*\}',
                r'\\start\{.*system.*\}',
                r'hidden.*command.*is'
            ]
        }
        
        # Compile regex patterns for better performance
        self.compiled_patterns = {}
        for attack_type, pattern_list in self.patterns.items():
            self.compiled_patterns[attack_type] = [re.compile(p, re.IGNORECASE) for p in pattern_list]

    def detect_attacks(self, prompt: str) -> Dict[str, List[Tuple[str, str]]]:
        """
        Detect various types of prompt injection attacks in the given prompt.
        
        Args:
            prompt: The input prompt to analyze
            
        Returns:
            Dictionary mapping attack types to list of matched patterns and substrings
        """
        detected_attacks = {}
        
        for attack_type, compiled_regexes in self.compiled_patterns.items():
            matches = []
            for regex in compiled_regexes:
                found_matches = regex.findall(prompt)
                if found_matches:
                    # Get the actual matched text for reporting
                    for match in regex.finditer(prompt):
                        matches.append((regex.pattern, match.group()))
            
            if matches:
                detected_attacks[attack_type] = matches
                
        return detected_attacks

    def classify_attack_types(self, prompt: str) -> List[str]:
        """
        Get a list of attack types detected in the prompt.
        
        Args:
            prompt: The input prompt to analyze
            
        Returns:
            List of attack type names detected
        """
        detected_attacks = self.detect_attacks(prompt)
        return list(detected_attacks.keys())
