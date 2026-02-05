"""
Script to start the Prompt Nova web server
"""
import os

def start_server():
    """Start the Flask server"""
    print("Starting Prompt Nova Server...")
    port = int(os.environ.get("PORT", 5050))
    print(f"Access the web interface at: http://localhost:{port}")
    print("Press Ctrl+C to stop the server\n")
    
    # Import and run the Flask app directly
    from app import app
    app.run(host='0.0.0.0', port=port, debug=False)

if __name__ == "__main__":
    start_server()
