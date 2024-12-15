from flask import Flask, request, session, jsonify
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences
import pickle
import re
from urllib.parse import urlparse
from tld import get_tld
from groq import Groq
from urlextract import URLExtract
import os
from flask import Flask, render_template
import numpy as np
import pytesseract
from PIL import Image
from tkinter import Tk
from tkinter.filedialog import askopenfilename
import subprocess
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import requests
import json
import datetime
import csv
import json
from werkzeug.utils import secure_filename
import logging
from io import BytesIO
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import make_response
from email.mime.base import MIMEBase
from email import encoders

# Initialize Flask app
app = Flask(__name__)
app.secret_key = '123002'

# Configure the upload folder
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

csv_file_reports = 'Reports.csv'

csv_file_contact = "Contact.csv"

# Set your API key here
API_KEY = "e77731e153294c278b8f8d1f5ee28684"
HEADERS = {
    "hibp-api-key": API_KEY,
    "User-Agent": "Python Script"
}

# Gmail SMTP server
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
GMAIL_USER = "ligtasbanko@gmail.com"
GMAIL_PASSWORD = "atsb vwiv kgom fsbu"

# Email content
email_subject = "Thank you for contacting us!"

attachment_path = "../LigtasBanko/static/assets/ligtasbanko-header.png"

# Initialize Groq client with the API key
client = Groq(api_key=os.environ.get("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"))

# Load the pre-trained model and tokenizer
model = load_model('trained_modelCNN.h5')
with open('tokenizer.pkl', 'rb') as tokenizer_file:
    tokenizer = pickle.load(tokenizer_file)

# Define headers for API requests, including the HIBP API key
HEADERS = {
    'User-Agent': 'LigtasBankoApp',
    'hibp-api-key': 'e77731e153294c278b8f8d1f5ee28684'  # Replace with your actual HIBP API key
}

# Determine the hosts file path based on the operating system
if os.name == 'nt':  # Windows
    HOSTS_PATH = r"C:\Windows\System32\drivers\etc\hosts"
else:  # macOS/Linux
    HOSTS_PATH = "/etc/hosts"

REDIRECT_IP = "127.0.0.1"
BLOCKED_WEBSITES_FILE = "blocked_websites.json"

# Function to check email breaches
def check_email_breaches(email, truncate_response=True, include_unverified=True, fetch_all_breaches=False):
    query_params = []
    
    # Ensure full breach data is returned by setting truncateResponse to false
    if not truncate_response:
        query_params.append("truncateResponse=false")
    
    if not include_unverified:
        query_params.append("IncludeUnverified=false")
        
    query_string = f"?{'&'.join(query_params)}" if query_params else ""

    # Use the URL for checking email breaches
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}{query_string}"

    # Define headers with your API key (replace YOUR_API_KEY with your actual key)
    HEADERS = {
        "hibp-api-key": "e77731e153294c278b8f8d1f5ee28684"
    }

    try:
        response = requests.get(url, headers=HEADERS)

        # If fetch_all_breaches is True, call the breaches API endpoint
        if fetch_all_breaches:
            all_breaches_url = "https://haveibeenpwned.com/api/v3/dataclasses"
            all_breaches_response = requests.get(all_breaches_url, headers=HEADERS)
            if all_breaches_response.status_code == 200:
                # Print and parse the response to check for all data classes
                data_classes = all_breaches_response.json()
                print("Data Classes:", data_classes)
                return {"data_classes": data_classes, "status_code": 200}
            else:
                return {"error": f"Error fetching data classes: {all_breaches_response.status_code} - {all_breaches_response.text}"}

        # If specific email breaches are found
        if response.status_code == 404:
            print("NO BREACH FOUND")
            return {"message": f"No breaches found for {email}.", "status_code": 404}
        
        if response.status_code == 200:
            breaches = response.json()
            results = []

            # Loop through each breach and retrieve complete data
            for breach in breaches:
                # Ensure DataClasses is returned as a list (it may sometimes be None)
                compromised_data = breach.get("DataClasses", [])
                if not compromised_data:
                    compromised_data = ["No compromised data"]

                # Collect breach information
                results.append({
                    "name": breach.get("Name", "Unknown Name"),
                    "domain": breach.get("Domain", "Unknown domain"),
                    "description": breach.get("Description", "No description available."),
                    "logo": breach.get("LogoPath", ""),
                    "compromised_data": compromised_data,  # DataClasses
                })

            total_breaches = len(breaches)
                
            return {"message": "Breaches found", "data": results, "total_breaches": total_breaches, "status_code": 200}
        else:
            return {"error": f"Error: {response.status_code} - {response.text}"}

    except Exception as e:
        return {"error": str(e)}

    
    

# Function to preprocess input URL
def preprocess_url(url):
    url = re.sub(r"[^a-zA-Z0-9]", " ", url).lower()
    sequences = tokenizer.texts_to_sequences([url])
    X_text = pad_sequences(sequences, maxlen=100, padding='post')
    return X_text

# Global variables for explanations

# Function to explain URL
def explain_url(url):
    global phishing_explanations, benign_explanations
    global phishing_features, benign_features
    global feature_names

    # Clear previous explanations
    phishing_explanations.clear()
    benign_explanations.clear()

    features = {}
    phishing_feature_values = []
    benign_feature_values = []
    phishing_features = {}
    benign_features = {}
    feature_names = {}

    # Example feature extraction functions (you need to define these functions)
    def having_ip_address(url):
        return 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0
    
    def count_atrate(url):
        return url.count('@')

    def url_length(url):
        return len(url)

    def no_of_embed(url):
        return url.count('//') - 1

    def count_https(url):
        return url.count('https:')

    def count_http(url):
        return url.count('http:')

    def shortening_service(url):
        shorteners = ["bit.ly", "tinyurl", "is.gd", "t.co"]
        return 1 if any(shortener in url for shortener in shorteners) else 0

    def count_dot(url):
        return url.count('.')

    def count_www(url):
        return url.count('www')

    def count_per(url):
        return url.count('%')

    def count_ques(url):
        return url.count('?')

    def count_hyphen(url):
        return url.count('-')

    def count_equal(url):
        return url.count('=')

    def digit_count(url):
        return sum(c.isdigit() for c in url)

    def letter_count(url):
        return sum(c.isalpha() for c in url)

    def abnormal_url(url):
        hostname = urlparse(url).hostname
        return 0 if hostname and get_tld(hostname, fix_protocol=True) else 1

    def hostname_length(url):
        hostname = urlparse(url).hostname
        return len(hostname) if hostname else 0

    def fd_length(url):
        urlpath= urlparse(url).path
        try:
            return len(urlpath.split('/')[1])
        except:
            return 0

    def tld_length(url):
        try:
            hostname = urlparse(url).netloc
            tld = get_tld(hostname, fix_protocol=True)
            return len(tld)
        except Exception as e:
            print("Error processing URL:", e)
            return 0


    features = {}

    # Helper function to extend feature values safely
    def extend_feature_values(feature_values_list, features, key, name):
        feature_values_list.append((key, features[key]))
        feature_names[key] = name  # Save the feature name in the dictionary

    # Use of IP address
    features['use_of_ip'] = having_ip_address(url)
    if features['use_of_ip'] == 1:
        phishing_explanations.append(f"The presence of an IP address in the URL suggests phishing.")
        extend_feature_values(phishing_feature_values, features, 'use_of_ip', 'use_of_ip')
    else:
        benign_explanations.append(f"No IP address found in the URL, indicating benign.")
        extend_feature_values(benign_feature_values, features, 'use_of_ip', 'use_of_ip')

    # Count of @ symbol
    features['count@'] = count_atrate(url)
    if features['count@'] > 0:
        phishing_explanations.append(f"The presence of '@' in the URL suggests phishing.")
        extend_feature_values(phishing_feature_values, features, 'count@', 'count@')
    else:
        benign_explanations.append(f"No '@' symbol found in the URL, indicating benign.")
        extend_feature_values(benign_feature_values, features, 'count@', 'count@')

    # URL Length
    features['url_length'] = url_length(url)
    if 50 <= features['url_length'] <= 75:
        benign_explanations.append(f"The URL length falls within the typical range for benign URLs.")
        extend_feature_values(benign_feature_values, features, 'url_length', 'url_length')
    elif features['url_length'] < 50:
        benign_explanations.append(f"The URL length is short, which is common in benign URLs.")
        extend_feature_values(benign_feature_values, features, 'url_length', 'url_length')
    else:
        phishing_explanations.append(f"The URL length is relatively long, which can be indicative of phishing.")
        extend_feature_values(phishing_feature_values, features, 'url_length', 'url_length')

    # Count of embedded domains
    features['count_embed_domain'] = no_of_embed(url)
    if features['count_embed_domain'] > 0:
        phishing_explanations.append(f"The presence of embedded domains in the URL suggests phishing.")
        extend_feature_values(phishing_feature_values, features, 'count_embed_domain', 'count_embed_domain')
    else:
        benign_explanations.append(f"No embedded domains found in the URL, indicating benign.")
        extend_feature_values(benign_feature_values, features, 'count_embed_domain', 'count_embed_domain')

    # HTTPS count
    features['count-https:'] = count_https(url)
    if features['count-https:'] > 0:
        benign_explanations.append(f"The URL uses HTTPS, which is common in benign URLs.")
        extend_feature_values(benign_feature_values, features, 'count-https:', 'count-https:')
    else:
        phishing_explanations.append(f"The absence of HTTPS in the URL may suggest phishing.")
        extend_feature_values(phishing_feature_values, features, 'count-https:', 'count-https:')

    # HTTP count
    features['count-http:'] = count_http(url)
    if features['count-http:'] > 0:
        phishing_explanations.append(f"The presence of HTTP in the URL suggests phishing.")
        extend_feature_values(phishing_feature_values, features, 'count-http:', 'count-http:')
    else:
        benign_explanations.append(f"The absence of HTTP in the URL is common in benign URLs.")
        extend_feature_values(benign_feature_values, features, 'count-http:', 'count-http:')

    # Shortening service detection
    features['short_url'] = shortening_service(url)
    if features['short_url'] == 1:
        phishing_explanations.append(f"The presence of a URL shortening service suggests phishing.")
        extend_feature_values(phishing_feature_values, features, 'short_url', 'short_url')
    else:
        benign_explanations.append(f"No URL shortening service detected, common in benign URLs.")
        extend_feature_values(benign_feature_values, features, 'short_url', 'short_url')

    # Count of dots
    features['count.'] = count_dot(url)
    if features['count.'] <= 2:
        benign_explanations.append(f"The number of dots in the URL is within the typical range for benign URLs.")
        extend_feature_values(benign_feature_values, features, 'count.', 'count.')
    else:
        phishing_explanations.append(f"The number of dots in the URL is relatively high, which can be indicative of phishing.")
        extend_feature_values(phishing_feature_values, features, 'count.', 'count.')

    # Count of 'www'
    features['count-www'] = count_www(url)
    if features['count-www'] == 1:
        benign_explanations.append(f"The presence of 'www' in the URL is common in benign URLs.")
        extend_feature_values(benign_feature_values, features, 'count-www', 'count-www')
    else:
        phishing_explanations.append(f"The absence or multiple occurrences of 'www' may suggest phishing.")
        extend_feature_values(phishing_feature_values, features, 'count-www', 'count-www')

    # Count of percentage symbol
    features['count%'] = count_per(url)
    if features['count%'] > 0:
        phishing_explanations.append(f"The presence of '%' in the URL suggests phishing.")
        extend_feature_values(phishing_feature_values, features, 'count%', 'count%')
    else:
        benign_explanations.append(f"No '%' symbol found in the URL, indicating benign.")
        extend_feature_values(benign_feature_values, features, 'count%', 'count%')
                              
    # Count of question mark
    features['count?'] = count_ques(url)
    if features['count?'] > 0:
        phishing_explanations.append(f"The presence of '?' in the URL suggests phishing.")
        extend_feature_values(phishing_feature_values, features, 'count?', 'count?')
    else:
        benign_explanations.append(f"No '?' symbol found in the URL, indicating benign.")
        extend_feature_values(benign_feature_values, features, 'count?', 'count?')

    # Count of hyphen
    features['count-'] = count_hyphen(url)
    if features['count-'] > 0:
        phishing_explanations.append(f"The presence of hyphens in the URL suggests phishing.")
        extend_feature_values(phishing_feature_values, features, 'count-', 'count-')
    else:
        benign_explanations.append(f"No hyphens found in the URL, indicating benign.")
        extend_feature_values(benign_feature_values, features, 'count-', 'count-')

    # Count of equal symbol
    features['count='] = count_equal(url)
    if features['count='] > 0:
        phishing_explanations.append(f"The presence of equal symbols in the URL suggests phishing.")
        extend_feature_values(phishing_feature_values, features, 'count=', 'count=')
    else:
        benign_explanations.append(f"No equal symbols found in the URL, indicating benign.")
        extend_feature_values(benign_feature_values, features, 'count=', 'count=')

    # Count of digits
    features['count-digits'] = digit_count(url)
    if features['count-digits'] > 5:
        phishing_explanations.append(f"The number of digits in the URL is relatively high, which can be indicative of phishing.")
        extend_feature_values(phishing_feature_values, features, 'count-digits', 'count-digits')
    else:
        benign_explanations.append(f"The number of digits in the URL is within the typical range for benign URLs.")
        extend_feature_values(benign_feature_values, features, 'count-digits', 'count-digits')

    # Count of letters
    features['count-letters'] = letter_count(url)
    if features['count-letters'] < 45:
        benign_explanations.append(f"The number of letters in the URL is within the typical range for benign URLs.")
        extend_feature_values(benign_feature_values, features, 'count-letters', 'count-letters')
    else:
        phishing_explanations.append(f"The number of letters in the URL is relatively high, which can be indicative of phishing.")
        extend_feature_values(phishing_feature_values, features, 'count-letters', 'count-letters')

    # Abnormal URL detection
    features['abnormal_url'] = abnormal_url(url)
    if features['abnormal_url'] == 1:
        phishing_explanations.append(f"The presence of abnormal URL patterns suggests phishing.")
        extend_feature_values(phishing_feature_values, features, 'abnormal_url', 'abnormal_url')
    else:
        benign_explanations.append(f"No abnormal URL patterns detected, common in benign URLs.")
        extend_feature_values(benign_feature_values, features, 'abnormal_url', 'abnormal_url')

    # Hostname length
    features['hostname_length'] = hostname_length(url)
    if 16 <= features['hostname_length'] <= 24:
        benign_explanations.append(f"The length of the hostname falls within the typical range for benign URLs.")
        extend_feature_values(benign_feature_values, features, 'hostname_length', 'hostname_length')
    else:
        phishing_explanations.append(f"The length of the hostname is relatively long, which can be indicative of phishing.")
        extend_feature_values(phishing_feature_values, features, 'hostname_length', 'hostname_length')

    # First directory length
    features['fd_length'] = fd_length(url)
    if features['fd_length'] < 6:
        benign_explanations.append(f"The length of the first directory in the URL is within the typical range for benign URLs.")
        extend_feature_values(benign_feature_values, features, 'fd_length', 'fd_length')
    else:
        phishing_explanations.append(f"The length of the first directory in the URL is relatively long, which may suggest phishing.")
        extend_feature_values(phishing_feature_values, features, 'fd_length', 'fd_length')

    # Length of top-level domain
    features['tld_length'] = tld_length(url)
    if 4 <= features['tld_length'] <= 5:
        benign_explanations.append(f"The length of the top-level domain falls within the typical range for benign URLs.")
        extend_feature_values(benign_feature_values, features, 'tld_length', 'tld_length')
    else:
        phishing_explanations.append(f"The length of the top-level domain is relatively long, which can be indicative of phishing.")
        extend_feature_values(phishing_feature_values, features, 'tld_length', 'tld_length')

    # Append feature values to the global dictionaries
    if phishing_explanations:
        phishing_features[url] = dict(phishing_feature_values)
    if benign_explanations:
        benign_features[url] = dict(benign_feature_values)

    return features, phishing_explanations, benign_explanations, phishing_feature_values, benign_feature_values, feature_names




    # Set up Chrome options for Selenium WebDriver
def test_website(url):
    # Set up Chrome options
    options = Options()
    options.add_argument("--headless")  # Run in headless mode
    options.add_argument('--disable-gpu')  # Disable GPU for headless mode (optional)
    
    # Set custom headers by adding a User-Agent string
    options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

    # Initialize WebDriver with the options
    driver = webdriver.Chrome(options=options)

    try:
        driver.get(url)
        # You can add more specific checks here, like:
        # - Checking for specific elements on the page
        # - Interacting with elements (e.g., clicking buttons, filling forms)
        # - Capturing screenshots or taking other actions
        print(f"The website {url} is accessible.")
        return "Website is reachable"
    except Exception as e:
        print(f"Error accessing the website {url}: {e}")
        return "Website not reachable"
    finally:
        driver.quit()
        
# Calculate summary statistics
feature_columns = ['use_of_ip', 'count@', 'url_length', 'count_embed_domain', 'count-https:',
                   'count-http:', 'short_url', 'count.', 'count-www', 'count%', 'count?',
                   'count-', 'count=', 'count-digits', 'count-letters', 'abnormal_url',
                    'hostname_length', 'fd_length', 'tld_length']

summary_stats = {
        "benign": {
            "use_of_ip": 0.0,
            "count@": 0.001825,
            "url_length": 59.172041,
            "count_embed_domain": 0.008366,
            "count-https:": 0.968360,
            "count-http:": 0.032400,
            "short_url": 0.002890,
            "count.": 2.616215,
            "count-www": 0.784606,
            "count%": 0.127319,
            "count?": 0.107392,
            "count-": 1.657438,
            "count=": 0.134164,
            "count-digits": 1.690447,
            "count-letters": 46.963948,
            "abnormal_url": 0.999543,
            "google_index": 1.0,
            "hostname_length": 16.648767,
            "fd_length": 8.525859,
            "tld_length": 4.313203
        },
        "phishing": {
            "use_of_ip": 0.0016,
            "count@": 0.018,
            "url_length": 57.6232,
            "count_embed_domain": 0.001,
            "count-https:": 0.8807,
            "count-http:": 0.1305,
            "short_url": 0.072,
            "count.": 2.1222,
            "count-www": 0.0587,
            "count%": 0.0473,
            "count?": 0.1493,
            "count-": 0.896,
            "count=": 0.323,
            "count-digits": 6.2044,
            "count-letters": 42.7717,
            "abnormal_url": 0.9998,
            "google_index": 1.0,
            "hostname_length": 24.3379,
            "fd_length": 5.3494,
            "tld_length": 5.7942
        }
}



# Global variables for explanations
phishing_explanations = []
benign_explanations = []

import pytesseract
from PIL import Image
from tkinter import Tk
from tkinter.filedialog import askopenfilename
import subprocess

# Function to extract text from an image
def extract_text_from_image(image):
    # Ensure the image is in a compatible format for OCR
    image = image.convert('RGB')  # Convert to RGB in case it's in another mode
    text = pytesseract.image_to_string(image)  # Extract text using pytesseract
    text = ' '.join(text.split())  # Clean up extra whitespace
    return text


# Function to handle image upload and text extraction
def handle_image_upload():
    Tk().withdraw()  # Prevents the Tk window from appearing
    image_path = askopenfilename(title='Select an image', filetypes=[('Image files', '*.png;*.jpg;*.jpeg;*.bmp;*.tiff')])
    if image_path:  # Proceed if a file was selected
        extracted_text = extract_text_from_image(image_path)
        return extracted_text
    else:
        return None
    

@app.route('/submission_method', methods=['POST'])
def set_submission_method():
    submission_method = request.json.get('submission_method', '')
    if submission_method:
        session['submission_method'] = submission_method
        print(f"Submission Method Set: {submission_method}")
        return jsonify({'message': 'Submission method updated'})
    else:
        return jsonify({'error': 'Invalid submission method'}), 400



@app.route('/analyze_url', methods=['POST'])
def analyze_url():
    # Get inputs from the form data
    url_input = request.form.get('urlInput')
    msg_input = request.form.get('msgInput')
    screenshot_data = request.form.get('screenshotData')
    file = request.files.get('screenshotUpload')  # Access uploaded file
    print(f"This is request files: {request.files}")
    

    
    # Initialize user_input to None
    user_input = None

    # Check if screenshot data is present
    if screenshot_data:
        print("Received screenshot extracted text:", screenshot_data)
        user_input = screenshot_data  # Use the extracted text as user input
    elif file:  # Process the screenshot file if no extracted text is available
        try:
            # Read the image from the file in memory
            image = Image.open(BytesIO(file.read()))
            
            # Extract text from the uploaded image
            user_input = extract_text_from_image(image)

            if user_input:
                print("User Input (Screenshot):", user_input)
            else:
                return jsonify({'error': 'No text found in the image'}), 400

        except Exception as e:
            return jsonify({'error': f'Error processing the image: {str(e)}'}), 500

    # Handle URL input if it's provided
    elif url_input:
        user_input = url_input
        print("User Input (URL):", user_input)

    # Handle Message input if it's provided
    elif msg_input:
        user_input = msg_input
        print("User Input (Text Message):", user_input)

    # If no valid user input is found, return an error
    if not user_input:
        return jsonify({'error': 'Invalid input type'}), 400

    print("Final User Input:", user_input)

    # Extract URLs from the user input
    extractor = URLExtract()
    urls = extractor.find_urls(user_input)

    results = []

    url_features_list = []  # Initialize outside the loop

    for url in urls:
         # Check the website status
        website_status = test_website(url)  # Check if the website is reachable
        
        processed_url = preprocess_url(url)
        prediction = model.predict(processed_url)[0][0]
        url_features = explain_url(url)
        url_features_list.append(url_features)

        features = {}


        if website_status == "Website not reachable":
            result = {
                'url': url,
                'prediction': 'UNREACHABLE',
                'confidence': 'N/A',
                'explanation': 'Website is not reachable.',
                'chat_completion': "This URL '{url}' is not reachable. The website does not exist or is down."
            }
            results.append(result)
        elif website_status == "Website is reachable" and prediction > 0.5:
            print("Prediction value is:", prediction)
            # Add the URL to the blocked websites list
            with open("blocked_websites.json", "r+") as file:
                try:
                    blocked_websites = json.load(file)
                except json.JSONDecodeError:
                    blocked_websites = []

                if url not in blocked_websites:
                    blocked_websites.append(url)
                    print(f"Adding {url} to the block list.")
                else:
                    print(f"{url} is already in the block list.")

                # Save updated block list
                file.seek(0)
                json.dump(blocked_websites, file)
                file.truncate()

            # Update the system hosts file to block the URL
            with open(HOSTS_PATH, "r+") as hosts_file:
                hosts_content = hosts_file.read()
                if f"{REDIRECT_IP} {url}" not in hosts_content:
                    hosts_file.write(f"{REDIRECT_IP} {url}\n")
                    print(f"Blocked {url} by redirecting to {REDIRECT_IP}.")
            features = explain_url(url)
            content = f"This text message or URL '{user_input}' is predicted to be phishing. Kindly explain why in 1 paragraph: 1. Explain more what that URL or text message all about. 2. And explain why that URL or text message is considered as phishing. 3. talk in 1st person and act like a bank security expert 4. don't use her/him. 5. And just go straight to the answer"
            chat_completion = client.chat.completions.create(
                messages=[{
                    "role": "user", 
                    "content": content}],
                model="llama-3.1-70b-versatile",
            )
            phishing_combined = []

            # Check if phishing features exist and print the top 5 with the smallest absolute differences
            phishing_sorted_features = []
            if phishing_features:
                for url, features in phishing_features.items():
                    # Initialize a dictionary to store the absolute differences
                    differences = {}
                    for feature, value in features.items():
                        if feature in summary_stats['phishing']:
                            # Calculate the absolute difference between the feature value and mean value
                            diff = abs(value - summary_stats['phishing'][feature])
                            differences[feature] = diff
                    # Sort the features based on the absolute differences
                    sorted_features = sorted(differences.items(), key=lambda x: x[1])
                    # Print the top 5 features with the smallest differences
                    for feature, _ in sorted_features[:5]:
                        phishing_sorted_features.append(feature)
            for feature_name, explanation in zip(phishing_features[url].items(), phishing_explanations):
                feature_name, feature_value = feature_name
                if feature_name in phishing_sorted_features:
                    phishing_combined.append(f"<b>{feature_name}</b>: {explanation}")

            phishing_combined_output = []

            for item in phishing_combined:
                phishing_combined_output.append(item)


            result = {
                'url': url,
                'prediction': 'PHISHING',
                'confidence': f"{prediction * 100:.2f}%",
                'explanation': phishing_combined_output,
                'chat_completion': chat_completion.choices[0].message.content
            }
            results.append(result)
        elif website_status == "Website is reachable" and prediction < 0.5:
            print("Prediction value is:", prediction)
            features = explain_url(url)
            content = f"This text message or URL '{user_input}' is predicted to be benign. Kindly explain why in 1 paragraph: 1. Explain more what that URL or text message all about. 2. And explain why that URL or text message is considered as benign. 3. talk in 1st person and act like a bank security expert 4. don't use her/him. 5. And just go straight to the answer"
            chat_completion = client.chat.completions.create(
                messages=[{
                    "role": "user", 
                    "content": content}],
                model="llama-3.1-70b-versatile",
            )

            benign_combined = []

            # Check if benign features exist and print the top 5 with the smallest absolute differences
            benign_sorted_features = []
            if benign_features:
                for url, features in benign_features.items():
                    # Initialize a dictionary to store the absolute differences
                    differences = {}
                    for feature, value in features.items():
                        if feature in summary_stats['benign']:
                            # Calculate the absolute difference between the feature value and mean value
                            diff = abs(value - summary_stats['benign'][feature])
                            differences[feature] = diff
                    # Sort the features based on the absolute differences
                    sorted_features = sorted(differences.items(), key=lambda x: x[1])
                    # Print the top 5 features with the smallest differences
                    for feature, _ in sorted_features[:5]:
                        benign_sorted_features.append(feature)
            for feature_name, explanation in zip(benign_features[url].items(), benign_explanations):
                feature_name, feature_value = feature_name
                if feature_name in benign_sorted_features:
                    benign_combined.append(f"<b>{feature_name}</b>: {explanation}")

            benign_combined_output = []

            for item in benign_combined:
                benign_combined_output.append(item)

            result = {
                'url': url,
                'prediction': 'BENIGN',
                'confidence': f"{(1 - prediction) * 100:.2f}%",
                'explanation': benign_combined_output,
                'chat_completion': chat_completion.choices[0].message.content
            }
            results.append(result)
            # Store the results in session or return them for use in the send_message route
        session['analysis_results'] = results  # Store the analysis results in the session
        print("Analysis results in session:", session.get('analysis_results'))

    print(results)
    return jsonify(results)

from flask import render_template, redirect, url_for

# Model details
models = {
    "mixtral-8x7b-32768": {"name": "Mixtral-8x7b-Instruct-v0.1", "tokens": 32768, "developer": "Mistral"}
}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/index1')
def index1():
    session.clear()  # Clear the entire session to ensure all data is removed
    print("Session cleared on index route.")
    # Initialize chat history and selected model in session
    if "messages" not in session:
        session.clear()
        session["messages"] = []
    if "selected_model" not in session:
        session["selected_model"] = "mixtral-8x7b-32768"  # Default model

    # Get the selected model and token limit
    selected_model = session["selected_model"]
    max_tokens = models[selected_model]["tokens"]

    return render_template('index1.html', models=models, selected_model=selected_model, max_tokens=max_tokens)

@app.route('/send_message', methods=['POST'])
def send_message():
    try:
        # Ensure session["messages"] is initialized
        if "messages" not in session:
            session["messages"] = []

        # Get the user message and max tokens
        user_message = request.form['message']
        max_tokens = int(request.form['max_tokens'])
        selected_model = session.get("selected_model", "mixtral-8x7b-32768")  # Default model if not set
        
        # Get the analysis results from the session
        analysis_results = session.get('analysis_results')  # Get the analysis results
        print("Analysis results are:", analysis_results)

        if analysis_results:
            # Extract details from the analysis results
            user_input = analysis_results[0]['url']  # Example: use the first URL
            prediction = analysis_results[0]['prediction']  # BENIGN or PHISHING
            explanation = analysis_results[0]['explanation']  # Explanation of prediction

            # Update the prompt to include the prediction and explanation
            prompt = f"You are a helpful cybersecurity assistant. Please provide detailed and accurate responses regarding phishing and cybersecurity. Also understand that '{user_input}' is '{prediction}' because '{explanation}'. Limit your words in less than 30 words."
            print("Prompt:", prompt)
        else:
            prompt = f"You are a helpful cybersecurity assistant. Please provide detailed and accurate responses regarding phishing and cybersecurity. Limit your word to less than 30 words."
            print("Prompt:", prompt)
        # Append the prompt to the messages
        session['messages'].append({"role": "system", "content": prompt})

        # Append user message to session
        session['messages'].append({"role": "user", "content": user_message})

        # Get the response from the API
        chat_completion = client.chat.completions.create(
            model=selected_model,
            messages=[{"role": m["role"], "content": m["content"]} for m in session["messages"]],
            max_tokens=max_tokens,
            stream=True
        )

        response = ''
        for chunk in chat_completion:
            if chunk.choices[0].delta.content:
                response += chunk.choices[0].delta.content

        # Append bot response to session
        session['messages'].append({"role": "assistant", "content": response})

        session.pop('analysis_results', None)

        return jsonify({'response': response})

    except Exception as e:
        # Log the error
        app.logger.error(f"Error in send_message: {e}")
        return jsonify({'error': str(e)}), 500

    

@app.route('/clear_messages', methods=['POST'])
def clear_messages():
    # Clear the messages in the session
    session['messages'] = []
    return jsonify({'status': 'Messages cleared successfully'})

@app.route('/index2')
def index2():
    return render_template('index2.html')

@app.route('/detect_phishing')
def detect_phishing():
    return render_template('index1.html')

@app.route('/report_phishing')
def report_phishing():
    return render_template('index2.html')

@app.route('/FAQs')
def FAQs():
    return render_template('FAQs.html')

from flask import redirect, url_for

@app.route("/email_pwn", methods=["GET", "POST"])
def email_pwn():
    password_url = "https://myaccount.google.com/intro/signinoptions/password"  # Default to Gmail's password URL
    twofa_url = "https://myaccount.google.com/signinoptions/two-step-verification"  # Default to Gmail's 2FA URL

    if request.method == "POST":
        email = request.form["email"]
        result = check_email_breaches(email, truncate_response=False, include_unverified=True)
        print("result: ", result)

        breaches = result.get("data", [])
        total_breaches = result.get("total_breaches", "")
        hide_parent_email2 = bool(breaches) or result.get("status_code") == 404

        # Extract domain from the email
        domain = email.split('@')[1] if '@' in email else ''

        # Set URLs based on the domain
        if domain == "gmail.com":
            password_url = "https://myaccount.google.com/intro/signinoptions/password"
            twofa_url = "https://myaccount.google.com/signinoptions/two-step-verification"
        elif domain == "yahoo.com":
            password_url = "https://login.yahoo.com/myaccount/security/?.lang=en-US&.intl=us&.src=yhelp&.scrumb=WGDrhd8EJT8&anchorId=changePasswordCard"
            twofa_url = "https://login.yahoo.com/myaccount/security/?.lang=en-US&.intl=us&.src=yhelp&.scrumb=WGDrhd8EJT8&anchorId=changePasswordCard"
        else:
            # Default URLs for any other domain
            password_url = "https://account.live.com/password/Change"
            twofa_url = "https://account.live.com/proofs/EnableTfa"

        # Store data temporarily in session
        session["result"] = result
        session["breaches"] = breaches
        session["email"] = email
        session["total_breaches"] = total_breaches
        session["hide_parent_email2"] = hide_parent_email2
        session["password_url"] = password_url
        session["twofa_url"] = twofa_url

        return redirect(url_for("email_pwn"))  # Redirect to avoid resubmission

    # Handle GET request or redirected state
    result = session.pop("result", None)
    breaches = session.pop("breaches", None)
    email = session.pop("email", None)
    total_breaches = session.pop("total_breaches", 0)
    hide_parent_email2 = session.pop("hide_parent_email2", False)
    password_url = session.pop("password_url", "")
    twofa_url = session.pop("twofa_url", "")

    return render_template(
        "email.html",
        result=result,
        breaches=breaches,
        email=email,
        total_breaches=total_breaches,
        hide_parent_email2=hide_parent_email2,
        password_url=password_url,
        twofa_url=twofa_url
    )





from threading import Thread
from flask import current_app


def handle_image_upload_with_thread():
    with current_app.app_context():
        extracted_text = handle_image_upload()
        print("Extracted text:", extracted_text)
        return extracted_text

@app.route('/upload_file', methods=['POST'])
def upload_file():
    file = request.files.get('screenshotUpload')
    
    if file is None:
        return jsonify({'message': 'No file named screenshotUpload found in the request.'}), 400
    if 'screenshotUpload' not in request.files:
        return jsonify({'message': 'No file part'}), 400

    file = request.files['screenshotUpload']
    if file.filename == '':
        return jsonify({'message': 'No selected file'}), 400

    # Process the file (e.g., save it or analyze it)
    # Example: Save the file
    file.save(f"./uploads/{file.filename}")
    
    return jsonify({'message': 'File uploaded successfully', 'filename': file.filename}), 200


@app.route("/submit-report", methods=["POST"])
def submit_report():
    # Get the data from the form (using .get() to handle missing fields gracefully)
    name = request.form.get("reporter_name")
    email = request.form.get("reporter_email")
    phishing_type = request.form.get("phishing_type")  # Get phishing type from form
    url = request.form.get("phishing_url")
    accept_terms = request.form.get("accept_terms")  # Ensure terms acceptance is checked

    if not name or not email or phishing_type == "Type of Phishing" or not url or not accept_terms:
        return render_template("index2.html", message="Report not submitted. Missing or invalid required fields.", success=False)


    # Prepare data to write to CSV
    report = {
        "name": name,
        "email": email,
        "phishingType": phishing_type,
        "url": url,
    }

    # Append data to the CSV file
    try:
        with open('reports.csv', mode='a', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=["name", "email", "phishingType", "url"])
            writer.writerow(report)
        return render_template("index2.html", success=True)
    except Exception as e:
        print(f"Error saving the report: {e}")
        return render_template("index2.html", message="Error saving the report.", success=False)



@app.route("/submit-contact", methods=["POST"])
def submit_contact():
    try:
        # Get the JSON data from the request
        data = request.get_json()

        # Extract the necessary fields
        name = data.get("name")
        email = data.get("email")
        subject = data.get("subject")
        message = data.get("message")

        # Validate input data
        if not name or not email or subject == "Select a subject" or not message:
            return make_response('', 400)  # Empty response with a 400 status code

        # Prepare email body dynamically
        body = f"""\
        <p>Dear {name},</p>

        <p>Thank you for taking the time to share your concerns/inquiries about our system. 
        We truly value your feedback as it helps us improve and provide you with a better experience.</p>

        <p>Please rest assured that we are actively looking into the issue you raised. 
        Our team is committed to resolving it as quickly as possible and ensuring that your experience with us remains positive.</p>

        <p>Should you have any additional information or questions, please don’t hesitate to contact us again. 
        Your input is always appreciated!</p>

        <p>Thank you once again for reaching out to us.</p>

        <p>Best regards,<br>
        """

        # Path to the image to embed
        inline_image_path = "../LigtasBanko/static/assets/ligtasbanko-header.png"

        # Send email
        if not send_email(email, email_subject, body, inline_image_path):
            return make_response('Failed to send email', 500)

        # Prepare data to write to CSV
        contact_data = {
            "name": name,
            "email": email,
            "subject": subject,
            "message": message,
        }

        # Append data to the CSV file
        with open(csv_file_contact, mode='a', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=["name", "email", "subject", "message"])
            writer.writerow(contact_data)

        return make_response('', 200)

    except Exception as e:
        print(f"Error: {e}")  # Log error
        return make_response('', 500)  # Empty response with a 500 status code


def send_email(to_email, subject, body, inline_image_path=None):
    from email.mime.image import MIMEImage

    msg = MIMEMultipart('related')
    msg['From'] = GMAIL_USER
    msg['To'] = to_email
    msg['Subject'] = subject

    # Create the alternative MIME part for plain text and HTML
    msg_alternative = MIMEMultipart('alternative')
    msg.attach(msg_alternative)

    # Add the HTML body with a placeholder for the inline image
    html_body = f"""\
    <html>
    <body>
        <p>Dear Valued Bank Customer,</p>

        <p>Thank you for taking the time to share your concerns/inquiries about our system. 
        We truly value your feedback as it helps us improve and provide you with a better experience.</p>

        <p>Please rest assured that we are actively looking into the issue you raised. 
        Our team is committed to resolving it as quickly as possible and ensuring that your experience with us remains positive.</p>

        <p>Should you have any additional information or questions, please don’t hesitate to contact us again. 
        Your input is always appreciated!</p>

        <p>Thank you once again for reaching out to us.</p>

        <p>Best regards,<br>
        {f'<img src="cid:inline_image" alt="LigtasBanko Header" width="134" height="43">' if inline_image_path else ''}
    </body>
    </html>
    """
    msg_alternative.attach(MIMEText(html_body, 'html'))

    # Embed the image if the path is provided
    if inline_image_path:
        try:
            print(f"Embedding image from path: {inline_image_path}")
            with open(inline_image_path, 'rb') as img_file:
                img = MIMEImage(img_file.read())
                img.add_header('Content-ID', '<inline_image>')
                img.add_header("Content-Disposition", "inline", filename="header.png")
                msg.attach(img)
            print("Image embedded successfully.")
        except FileNotFoundError:
            print(f"Image file not found: {inline_image_path}")
            return False
        except Exception as e:
            print(f"Error embedding image: {e}")
            return False

    try:
        print("Attempting to connect to SMTP server...")
        # Connect to the Gmail SMTP server
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.set_debuglevel(1)  # Set debug level for detailed SMTP communication
        server.starttls()  # Secure the connection
        print("Connection to SMTP server established.")

        print("Logging into Gmail server...")
        server.login(GMAIL_USER, GMAIL_PASSWORD)
        print("Login successful.")

        # Send the email
        print(f"Sending email to {to_email}...")
        server.sendmail(GMAIL_USER, to_email, msg.as_string())
        print(f"Email sent successfully to {to_email}")

        # Disconnect from the server
        server.quit()
        print("Disconnected from SMTP server.")

    except smtplib.SMTPAuthenticationError as auth_error:
        print(f"SMTP Authentication error: {auth_error}")
        return False
    except smtplib.SMTPException as smtp_error:
        print(f"SMTP error occurred: {smtp_error}")
        return False
    except Exception as e:
        print(f"Unexpected error occurred: {e}")
        return False

    return True








if __name__ == '__main__':
    app.run(debug=True)