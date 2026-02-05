# Prompt Nova Project Structure

## Directory Layout
```
promptnova/
├── __init__.py                    # Package initialization
├── detector.py                    # Rule-based attack detection module
├── risk_scorer.py                 # Risk scoring engine
├── mitigation_engine.py           # Decision engine for allow/rewrite/block
├── app.py                         # Flask API wrapper for demo
├── start_server.py                # Script to start the web server
├── demonstration.py               # Comprehensive system demonstration
├── test_promptnova.py            # Unit tests for the core system
├── test_api.py                    # API endpoint tests
├── HACKATHON_SUMMARY.md           # Achievement summary
├── PROJECT_STRUCTURE.md           # This file
├── requirements.txt               # Dependencies
├── README.md                      # Main documentation
├── dataset/
│   ├── malicious_prompts.csv      # Training/test dataset with malicious prompts
│   └── safe_prompts.csv           # Safe prompt examples
├── ml_model/                      # Persisted TF-IDF + Logistic Regression artifacts
│   └── prompt_classifier.joblib   # Combined pipeline + metadata
├── static/
│   ├── css/
│   │   └── style.css              # Frontend styling
│   └── js/
│       └── main.js                # Frontend JavaScript
├── templates/
│   └── index.html                 # Main UI page
└── .gitignore                     # Git ignore file
```

## Core Components

### 1. [detector.py](file:///c:/Users/LENOVO/OneDrive/Desktop/assdc/promptnova/detector.py)
- Implements regex patterns for detecting 5 types of prompt injection attacks
- Uses compiled regex for performance optimization
- Returns detailed information about detected patterns

### 2. [risk_scorer.py](file:///c:/Users/LENOVO/OneDrive/Desktop/assdc/promptnova/risk_scorer.py)
- Calculates risk scores using weighted model (0-100 scale)
- Applies severity multipliers based on number of matches
- Generates human-readable explanations

### 3. [mitigation_engine.py](file:///c:/Users/LENOVO/OneDrive/Desktop/assdc/promptnova/mitigation_engine.py)
- Makes Allow/Rewrite/Block decisions based on risk scores
- Implements prompt sanitization for medium-risk cases
- Calculates confidence levels in assessments

### 4. [app.py](file:///c:/Users/LENOVO/OneDrive/Desktop/assdc/promptnova/app.py)
- Flask web application with REST API endpoints
- Serves the web UI and handles analysis requests
- Provides health check endpoint

### 5. ML Detector (`ml_detector.py`)
- Trains or loads the TF-IDF + Logistic Regression classifier
- Stores metadata (version, validation accuracy, etc.) with the artifact
- Provides `.predict()` + `.retrain()` APIs used by the Mitigation Engine

### 6. Frontend Components
- **HTML Template**: Interactive UI for prompt testing
- **CSS Styling**: Responsive, professional design
- **JavaScript**: Handles API communication, ML telemetry rendering, radar visualization (Chart.js), and live retraining controls

### 7. Dataset Files
- **malicious_prompts.csv**: 50+ examples of various attack types
- **safe_prompts.csv**: Legitimate prompts for comparison

## How to Run

1. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the web application**:
   ```bash
   python start_server.py
   ```
   Then visit `http://localhost:5000`

3. **Use as a library**:
   ```python
   from mitigation_engine import MitigationEngine
   engine = MitigationEngine()
   result = engine.analyze_prompt("Your prompt here")
   ```

4. **Run demonstrations**:
   ```bash
   python demonstration.py
   ```

## API Endpoints

- `GET /` - Main web interface
- `POST /analyze` - Analyze a prompt for injection attacks
- `GET /health` - Health check endpoint

## Testing

- Run `python test_promptnova.py` for unit tests
- Run `python test_api.py` for API tests
- Use the web interface for interactive testing
