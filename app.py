from flask import Flask, render_template, request, jsonify
import os
from dotenv import load_dotenv
import json
import requests
import re
import urllib.parse
import tldextract
import time

load_dotenv()

app = Flask(__name__)

# Add the URLScan.io configuration
URLSCAN_API_KEY = 'e531f69c-0922-420a-bb32-e7084f6fcaaf'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/laws')
def laws():
    return render_template('laws.html')

@app.route('/helplines')
def helplines():
    return render_template('helplines.html')

@app.route('/chat')
def chat():
    return render_template('chat.html')

@app.route('/get_response', methods=['POST'])
def get_response():
    user_message = request.json.get('message', '')
    
    # Create a context for cybersecurity awareness
    prompt = f"""You are a Cybersecurity Awareness Chatbot. Your role is to educate users about 
    cybersecurity best practices and help them understand and avoid security threats. 
    Please provide helpful, accurate, and easy-to-understand responses. Ensure the response is always in HTML syntax. For bold, use <b> and </b> tags.
    for underline, use <u> and </u> tags. For italic, use <i> and </i> tags. For line break, use <br> tag. For header, always use <h3> and </h3> tags.
    User question: {user_message}"""
    
    try:
        url = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=AIzaSyCDLGXbrPmqZJxaTQt2UIwd7TtGKu50ig8'
        api_key = os.getenv('GOOGLE_API_KEY')
        
        headers = {
            'Content-Type': 'application/json',
            'x-goog-api-key': api_key
        }
        
        data = {
            'contents': [{
                'parts': [{
                    'text': prompt
                }]
            }]
        }
        
        response = requests.post(url, headers=headers, json=data)
        print(response.json())
        if response.status_code == 200:
            result = response.json()
            text = result['candidates'][0]['content']['parts'][0]['text']
            print(text)
            return jsonify({'response': text})
        else:
            return jsonify({'response': f'Error: {response.status_code}'})
            
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({'response': 'Sorry, I encountered an error. Please try again.'})

@app.route('/security-tools')
def security_tools():
    return render_template('security-tools.html')

@app.route('/check-password-strength', methods=['POST'])
def check_password_strength():
    password = request.json.get('password', '')
    
    score = 0
    feedback = []
    
    # Length check
    if len(password) >= 12:
        score += 2
        feedback.append({"type": "success", "message": "Good length"})
    elif len(password) >= 8:
        score += 1
        feedback.append({"type": "warning", "message": "Consider using a longer password"})
    else:
        feedback.append({"type": "error", "message": "Password is too short"})

    # Uppercase check
    if re.search(r'[A-Z]', password):
        score += 1
        feedback.append({"type": "success", "message": "Contains uppercase letters"})
    else:
        feedback.append({"type": "error", "message": "Add uppercase letters"})

    # Lowercase check
    if re.search(r'[a-z]', password):
        score += 1
        feedback.append({"type": "success", "message": "Contains lowercase letters"})
    else:
        feedback.append({"type": "error", "message": "Add lowercase letters"})

    # Numbers check
    if re.search(r'\d', password):
        score += 1
        feedback.append({"type": "success", "message": "Contains numbers"})
    else:
        feedback.append({"type": "error", "message": "Add numbers"})

    # Special characters check
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 1
        feedback.append({"type": "success", "message": "Contains special characters"})
    else:
        feedback.append({"type": "error", "message": "Add special characters"})

    # Calculate strength
    strength = ""
    if score < 2:
        strength = "Very Weak"
    elif score < 3:
        strength = "Weak"
    elif score < 4:
        strength = "Moderate"
    elif score < 5:
        strength = "Strong"
    else:
        strength = "Very Strong"

    return jsonify({
        'score': score,
        'strength': strength,
        'feedback': feedback
    })

@app.route('/check-url', methods=['POST'])
def check_url():
    url = request.json.get('url', '')
    
    risk_factors = []
    risk_level = "Low"
    
    try:
        parsed = urllib.parse.urlparse(url)
        extracted = tldextract.extract(url)
        
        # Basic checks
        if parsed.scheme != 'https':
            risk_factors.append("Not using HTTPS (secure connection)")
            risk_level = "High"
            
        if any(extracted.suffix.endswith(tld) for tld in ['.xyz', '.tk', '.ml', '.ga', '.cf']):
            risk_factors.append("Suspicious domain extension")
            risk_level = "High"
            
        if re.match(r'\d+\.\d+\.\d+\.\d+', extracted.domain):
            risk_factors.append("Using IP address instead of domain name")
            risk_level = "High"

        # URLScan.io integration
        headers = {
            "API-Key": URLSCAN_API_KEY,
            "Content-Type": "application/json"
        }
        
        scan_payload = {
            "url": url,
            "visibility": "public",
            "tags": ["phishing_check", "demo"]
        }
        
        # Submit URL for scanning
        submission = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers=headers,
            json=scan_payload
        )
        
        if submission.status_code == 200:
            scan_uuid = submission.json().get("uuid")
            
            # Wait for scan to complete
            time.sleep(5)  # Wait for scan to process
            
            # Get scan results
            result_url = f"https://urlscan.io/api/v1/result/{scan_uuid}/"
            result = requests.get(result_url)
            print(result.json())
            if result.status_code == 200:
                result_data = result.json()
                
                # Check malicious verdict
                if result_data.get("verdicts", {}).get("overall", {}).get("malicious"):
                    risk_factors.append("URL flagged as malicious by URLScan.io")
                    risk_level = "High"
                
                # Check for suspicious technologies
                tech = result_data.get("page", {}).get("technologies", [])
                suspicious_tech = ["phishing", "spam", "malware"]
                if any(t.lower() in str(tech).lower() for t in suspicious_tech):
                    risk_factors.append("Suspicious technologies detected")
                    risk_level = "High"
        
        if not risk_factors:
            risk_factors.append("No obvious risk factors detected")
            
    except Exception as e:
        print(f"Error scanning URL: {str(e)}")
        risk_factors.append("Error during URL scan")
        risk_level = "Unknown"
    
    return jsonify({
        'risk_level': risk_level,
        'risk_factors': risk_factors
    })

if __name__ == '__main__':
    app.run(debug=True,port=5002) 