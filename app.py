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


# Initialize Flask app
app = Flask(__name__)
app.secret_key = '123002'
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Initialize Groq client with the API key
client = Groq(api_key=os.environ.get("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"))

# Load the pre-trained model and tokenizer
model = load_model('trained_modelCNN.h5')
with open('tokenizer.pkl', 'rb') as tokenizer_file:
    tokenizer = pickle.load(tokenizer_file)

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
        return url.count('https')

    def count_http(url):
        return url.count('http')

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
    features['count-https'] = count_https(url)
    if features['count-https'] > 0:
        benign_explanations.append(f"The URL uses HTTPS, which is common in benign URLs.")
        extend_feature_values(benign_feature_values, features, 'count-https', 'count-https')
    else:
        phishing_explanations.append(f"The absence of HTTPS in the URL may suggest phishing.")
        extend_feature_values(phishing_feature_values, features, 'count-https', 'count-https')

    # HTTP count
    features['count-http'] = count_http(url)
    if features['count-http'] > 0:
        phishing_explanations.append(f"The presence of HTTP in the URL suggests phishing.")
        extend_feature_values(phishing_feature_values, features, 'count-http', 'count-http')
    else:
        benign_explanations.append(f"The absence of HTTP in the URL is common in benign URLs.")
        extend_feature_values(benign_feature_values, features, 'count-http', 'count-http')

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




# Calculate summary statistics
feature_columns = ['use_of_ip', 'count@', 'url_length', 'count_embed_domain', 'count-https',
                   'count-http', 'short_url', 'count.', 'count-www', 'count%', 'count?',
                   'count-', 'count=', 'count-digits', 'count-letters', 'abnormal_url',
                    'hostname_length', 'fd_length', 'tld_length']

summary_stats = {
        "benign": {
            "use_of_ip": 0.0,
            "count@": 0.0018253726802555522,
            "url_length": 59.172041375114084,
            "count_embed_domain": 0.00836629145117128,
            "count-https": 0.9694250076057195,
            "count-http": 0.03240036507453605,
            "short_url": 0.002890173410404624,
            "count.": 2.6162153939762702,
            "count-www": 0.7846060237298449,
            "count%": 0.12731974444782476,
            "count?": 0.10739275935503499,
            "count-": 1.6574383936720414,
            "count=": 0.1341648919987831,
            "count-digits": 1.6904472163066626,
            "count-letters": 46.96394888956495,
            "abnormal_url": 0.9995436568299361,
            "google_index": 1.0,
            "hostname_length": 16.64876787344083,
            "fd_length": 8.52585944630362,
            "tld_length": 4.313203529053848
        },
        "phishing": {
            "use_of_ip": 0.0016,
            "count@": 0.018,
            "url_length": 57.6232,
            "count_embed_domain": 0.001,
            "count-https": 0.8821,
            "count-http": 0.1323,
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
        processed_url = preprocess_url(url)
        prediction = model.predict(processed_url)[0][0]
        url_features = explain_url(url)
        url_features_list.append(url_features)

        features = {}
        if prediction > 0.5:
            features = explain_url(url)
            content = f"This text message or URL '{user_input}' is predicted to be phishing. Kindly explain why in 1 paragraph: 1. Explain more what that URL or text message all about. 2. And explain why that URL or text message is considered as phishing. 3. talk in 3rd person 4. don't use her/him. 5. And just go straight to the answer"
            chat_completion = client.chat.completions.create(
                messages=[{
                    "role": "user", 
                    "content": content}],
                model="llama3-70b-8192",
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
        else:
            features = explain_url(url)
            content = f"This text message or URL '{user_input}' is predicted to be benign. Kindly explain why in 1 paragraph: 1. Explain more what that URL or text message all about. 2. And explain why that URL or text message is considered as benign. 3. talk in 3rd person 4. don't use her/him. 5. And just go straight to the answer"
            chat_completion = client.chat.completions.create(
                messages=[{
                    "role": "user", 
                    "content": content}],
                model="llama3-70b-8192",
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

    return jsonify(results)

from flask import render_template, redirect, url_for

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/index1')
def index1():
    return render_template('index1.html')

@app.route('/index2')
def index2():
    return render_template('index2.html')

@app.route('/detect_phishing')
def detect_phishing():
    return render_template('index1.html')

@app.route('/report_phishing')
def report_phishing():
    return render_template('index2.html')

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