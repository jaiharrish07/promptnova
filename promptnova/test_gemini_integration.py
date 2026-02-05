"""
Test script for the new Gemini integration
"""
import os
import google.generativeai as genai

def test_gemini_client():
    """Test the Gemini client functionality"""
    print("Testing Gemini Integration...")
    
    # Test without API key
    print("\n1. Testing without API key:")
    client = GeminiClient()
    response = client.get_completion("Hello, how are you?")
    print(f"   Response: {response}")
    
    # Test with API key (if available)
    api_key = os.getenv('GEMINI_API_KEY')
    if api_key:
        print("\n2. Testing with API key:")
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-pro')
        try:
            response = model.generate_content("What is the weather today?")
            print(f"   Gemini Response: {response.text[:100]}...")
        except Exception as e:
            print(f"   Error: {e}")
    else:
        print("\n2. API key not set. To test with Gemini:")
        print("   Set GEMINI_API_KEY environment variable")

class GeminiClient:
    def __init__(self):
        api_key = os.getenv('GEMINI_API_KEY')
        if api_key:
            genai.configure(api_key=api_key)
            self.enabled = True
            self.model = genai.GenerativeModel('gemini-pro')
        else:
            self.enabled = False
    
    def get_completion(self, prompt):
        if not self.enabled:
            return "Gemini API key not configured. Set GEMINI_API_KEY environment variable to enable Gemini integration."
        
        try:
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            return f"Error calling Gemini API: {str(e)}"

if __name__ == "__main__":
    test_gemini_client()
    print("\nTo use Gemini integration in the web app:")
    print("1. Get API key from https://aistudio.google.com/app/apikey")
    print("2. Set environment variable: set GEMINI_API_KEY=your-key")
    print("3. Run: python app.py")
    print("4. Visit: http://localhost:5000")