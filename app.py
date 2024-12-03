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


# Initialize Flask app
app = Flask(__name__)
app.secret_key = '123002'
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Set your API key here
API_KEY = "e77731e153294c278b8f8d1f5ee28684"
HEADERS = {
    "hibp-api-key": API_KEY,
    "User-Agent": "Python Script"
}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

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
            all_breaches_url = "https://haveibeenpwned.com/api/v3/breaches"
            all_breaches_response = requests.get(all_breaches_url, headers=HEADERS)
            if all_breaches_response.status_code == 200:
                all_breaches = all_breaches_response.json()
                return {"message": "All breaches", "data": all_breaches}
            else:
                return {"error": f"Error fetching all breaches: {all_breaches_response.status_code} - {all_breaches_response.text}"}

        # If specific email breaches are found
        if response.status_code == 404:
            print("NO BREACH FOUND")
            return {"message": f"No breaches found for {email}.", "status_code":404}
        
        if response.status_code == 200:
            breaches = response.json()
            results = []
            

            # Loop through each breach and retrieve complete data
            for breach in breaches:
                results.append({
                    "name": breach.get("Name", "Unknown Name"),
                    "domain": breach.get("Domain", "Unknown domain"),
                    "description": breach.get("Description", "No description available."),
                    "logo": breach.get("LogoPath", ""),  # Add LogoPath to each breach
                    "compromised_data": breach.get("DataClasses", []),
                })

            total_breaches = len(breaches)
                
            return {"message": "Breaches found", "data": results, "total_breaches": total_breaches, "status_code":200}
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
    chrome_options = Options()
    chrome_options.add_argument("--headless")  # Run in headless mode (no GUI)

    # Initialize the WebDriver (Make sure ChromeDriver is installed and path is correct)
    driver = webdriver.Chrome(options=chrome_options)

    try:
        # Check if the website is reachable using requests
        response = requests.get(url, timeout=10)
        if response.status_code >= 400:
            print(f"The website {url} does not exist.")
            return "Website not reachable"
        
        # Interact with the website (for future use)
        driver.get(url)
        print(f"Successfully accessed {url}")
        return "Website is reachable"

    except requests.RequestException:
        print(f"The website {url} does not exist.")
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

def extract_text_from_image(image_path):
    image = Image.open(image_path)
    text = pytesseract.image_to_string(image)
    text = ' '.join(text.split())
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
    data = request.json
    submission_method = data.get('submission_method', '')
    session['submission_method'] = submission_method
    print("Submission Method:", submission_method)
    return jsonify({'message': 'Received submission method'})


# Route to handle URL analysis
@app.route('/analyze_url', methods=['POST'])
def analyze_url():
    data = request.json
    submission_methodAnalyze = session.get('submission_method')
    print("Submission method:", submission_methodAnalyze)

# Function to extract text from image
    if submission_methodAnalyze == "Screenshot":
        extracted_text = handle_image_upload()
        user_input = extracted_text
        print("YOU ARE IN SS")
    elif submission_methodAnalyze == 'URL':
        user_input = data.get('user_input', '')
        print("YOU ARE IN URL")
    else:
        user_input = data.get('user_input', '')
        print("YOU ARE IN TEXT MESSAGE")

    print("Final User Input (after extraction):", user_input)


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
    session.clear()
    try:
        # Ensure session["messages"] is initialized
        if "messages" not in session:
            session.clear()
            session["messages"] = []

        # Get the user message and max tokens
        user_message = request.form['message']
        max_tokens = int(request.form['max_tokens'])
        selected_model = session.get("selected_model", "mixtral-8x7b-32768")  # Default model if not set
        
        # Example of adding a custom prompt before the user's message
        prompt = "You are a helpful cybersecurity assistant. Please provide detailed and accurate responses. Make your answers very short and not exceed 60 words, and do not talk about anything else but cybersecurity related and phishing related."

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

        return jsonify({'response': response})

    except Exception as e:
        # Log the error
        app.logger.error(f"Error in send_message: {e}")
        return jsonify({'error': str(e)}), 500
    

@app.route('/index2')
def index2():
    return render_template('index2.html')

@app.route('/detect_phishing')
def detect_phishing():
    return render_template('index1.html')

@app.route('/report_phishing')
def report_phishing():
    return render_template('index2.html')

@app.route("/email_pwn", methods=["GET", "POST"])
def email_pwn():
    result = None
    email = None
    breaches = None
    total_breaches = 0

    if request.method == "POST":
        email = request.form["email"]
        result = check_email_breaches(email, truncate_response=False, include_unverified=True)
        print("result: ", result)

        breaches = result.get("data", [])
        total_breaches = result.get("total_breaches", "")


        print(f"Breaches count: {len(breaches)}")


        if "data" in result:
            breaches = result["data"]
    return render_template("email.html", result=result, breaches=breaches, email=email, total_breaches=total_breaches)

from threading import Thread
from flask import current_app


def handle_image_upload_with_thread():
    with current_app.app_context():
        extracted_text = handle_image_upload()
        print("Extracted text:", extracted_text)
        return extracted_text

@app.route('/upload_file', methods=['POST'])
def upload_file():
    if 'screenshotUpload' not in request.files:
        return jsonify({'status': 'error', 'message': 'No file part'}), 400

    file = request.files['screenshotUpload']
    if file.filename == '':
        return jsonify({'status': 'error', 'message': 'No selected file'}), 400

    # Save the file
    filename = file.filename
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)

    return jsonify({'status': 'success', 'file_path': file_path})

if __name__ == '__main__':
    app.run(debug=True)