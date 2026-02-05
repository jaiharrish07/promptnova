from flask import Flask, request, jsonify, render_template
from mitigation_engine import MitigationEngine
from ml_detector import PromptMLDetector
import csv
from datetime import datetime, timezone
import os
from dotenv import load_dotenv
from groq import Groq

# Load environment variables from .env file
load_dotenv()

DEFAULT_PORT = 5050  # macOS commonly uses 5000 for system services (AirPlay/ControlCenter)


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}

class GroqClient:
    def __init__(self):
        # Initialize Groq client - will only work if API key is set
        api_key = os.getenv('GROQ_API_KEY')
        if api_key:
            self.client = Groq(api_key=api_key)
            self.enabled = True
        else:
            self.enabled = False
    
    def get_completion(self, prompt):
        if not self.enabled:
            return "Groq API key not configured. Set GROQ_API_KEY environment variable to enable Groq integration."
        
        try:
            response = self.client.chat.completions.create(
                messages=[{"role": "user", "content": prompt}],
                model="llama-3.1-8b-instant"
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Error calling Groq API: {str(e)}"

app = Flask(__name__)
ml_detector = PromptMLDetector()
mitigation_engine = MitigationEngine(ml_agent=ml_detector)
groq_client = GroqClient()

FEEDBACK_PATH = os.path.join(os.path.dirname(__file__), "dataset", "feedback.csv")

@app.route('/')
def index():
    """Serve the main UI page."""
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_prompt():
    """
    Analyze a prompt for potential injection attacks.
    
    Expected JSON payload:
    {
        "prompt": "The prompt to analyze"
    }
    
    Returns:
    {
        "prompt": "Original prompt",
        "sanitized_prompt": "Sanitized prompt if mitigation needed",
        "action": "ALLOW, SANITIZE, REWRITE, ISOLATE, or BLOCK",
        "risk_score": "Risk score (0-100)",
        "risk_level": "Low, Medium, or High",
        "detected_attacks": ["List of detected attack types"],
        "explanation": "Human-readable explanation",
        "confidence": "Confidence level (0-1)"
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'prompt' not in data:
            return jsonify({
                'error': 'Missing prompt in request body'
            }), 400
        
        prompt = data['prompt']
        
        # Perform analysis
        result = mitigation_engine.analyze_prompt(prompt)
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({
            'error': f'An error occurred: {str(e)}'
        }), 500

@app.route('/compare', methods=['POST'])
def compare_responses():
    """
    Compare direct Groq response vs Framework-protected response.
    """
    try:
        data = request.get_json()
        if not data or 'prompt' not in data:
            return jsonify({'error': 'Missing prompt'}), 400
        
        prompt = data['prompt']
        
        # 1. Direct Response (Without Framework)
        direct_response = groq_client.get_completion(prompt)
        
        # 2. Framework Protected Response
        analysis = mitigation_engine.analyze_prompt(prompt)
        
        framework_response = ""
        action = analysis.get("action", "ALLOW")
        if action == 'BLOCK':
            framework_response = f"[SECURITY BLOCK] {analysis.get('explanation', '')}"
        elif action in {'SANITIZE', 'REWRITE', 'ISOLATE'}:
            sanitized = analysis.get('sanitized_prompt', prompt)
            framework_response = groq_client.get_completion(sanitized)
            framework_response = f"[{action}] {framework_response}"
        else:
            framework_response = groq_client.get_completion(prompt)

        return jsonify({
            'direct_response': direct_response,
            'framework_response': framework_response,
            'analysis': analysis,
            'framework_context': {
                'prompt_injection_detected': bool(analysis.get('detected_attacks')),
                'ml_intent': (analysis.get('layers', {}).get('semantic', {}) or {}).get('intent_category'),
                'ml_confidence': (analysis.get('layers', {}).get('semantic', {}) or {}).get('semantic_confidence'),
            }
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/ml/status', methods=['GET'])
def ml_status():
    """Expose ML detector metadata & readiness."""
    status = ml_detector.get_status()
    return jsonify(status), (200 if status['status'] == 'online' else 503)

@app.route('/ml/retrain', methods=['POST'])
def ml_retrain():
    """Trigger a background retrain using bundled datasets."""
    try:
        metadata = ml_detector.retrain()
        return jsonify({
            'message': 'ML detector retrained successfully',
            'metadata': metadata
        })
    except Exception as exc:
        return jsonify({'error': f'Unable to retrain classifier: {exc}'}), 500

@app.route('/ml/evaluate', methods=['GET'])
def ml_evaluate():
    """Evaluate the current ML detector on bundled datasets (quick sanity check)."""
    try:
        report = ml_detector.evaluate()
        return jsonify(report)
    except Exception as exc:
        return jsonify({'error': f'Unable to evaluate classifier: {exc}'}), 500

@app.route('/feedback', methods=['POST'])
def feedback():
    """
    Collect user feedback to improve the classifier over time.

    Expected JSON:
    {
      "prompt": "...",
      "user_label": "benign" | "malicious",
      "attack_type": "optional attack type string",
      "analysis": { ... optional last analysis blob ... }
    }
    """
    try:
        payload = request.get_json() or {}
        prompt = (payload.get("prompt") or "").strip()
        user_label = (payload.get("user_label") or "").strip().lower()
        attack_type = (payload.get("attack_type") or "").strip()
        analysis = payload.get("analysis") or {}

        if not prompt:
            return jsonify({"error": "Missing prompt"}), 400
        if user_label not in {"benign", "malicious"}:
            return jsonify({"error": "user_label must be 'benign' or 'malicious'"}), 400

        ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        row = {
            "timestamp": ts,
            "prompt": prompt,
            "user_label": user_label,
            "attack_type": attack_type,
            "model_action": analysis.get("action", ""),
            "model_risk_score": analysis.get("risk_score", ""),
            "ml_risk_score": (analysis.get("layers", {}).get("ml", {}) or {}).get("score", ""),
            "ml_label": (analysis.get("layers", {}).get("ml", {}) or {}).get("label", ""),
        }

        file_exists = os.path.exists(FEEDBACK_PATH)
        with open(FEEDBACK_PATH, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(row.keys()))
            if not file_exists:
                writer.writeheader()
            writer.writerow(row)

        return jsonify({"message": "Feedback recorded", "saved": row})
    except Exception as exc:
        return jsonify({"error": f"Unable to record feedback: {exc}"}), 500

@app.route('/status', methods=['GET'])
def status():
    """Single endpoint for UI boot (service + ML readiness)."""
    return jsonify({
        "service": "Prompt Nova API",
        "healthy": True,
        "ml": ml_detector.get_status(),
        "semantic_enabled": bool(os.getenv("GROQ_API_KEY")),
    })

@app.route('/metrics', methods=['GET'])
def metrics():
    """Metrics snapshot for monitoring dashboards."""
    return jsonify(mitigation_engine.metrics_snapshot())

@app.route('/health')
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'service': 'Prompt Nova API'
    })

if __name__ == '__main__':
    # Production-style defaults: avoid debug reloader unless explicitly enabled.
    port = int(os.environ.get('PORT', DEFAULT_PORT))
    debug = _env_flag("FLASK_DEBUG", default=False) or _env_flag("DEBUG", default=False)
    app.run(host='0.0.0.0', port=port, debug=debug, use_reloader=debug)
