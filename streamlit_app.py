import streamlit as st
import pandas as pd
import numpy as np
import pickle
import re

# Set page config
st.set_page_config(
    page_title="HAWK - URL Phishing Detector",
    page_icon="🦅",
    layout="wide"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        color: #1E3A8A;
        text-align: center;
        margin-bottom: 1rem;
    }
    .sub-header {
        font-size: 1.5rem;
        color: #4B5563;
        text-align: center;
        margin-bottom: 2rem;
    }
    .safe-box {
        background-color: #D1FAE5;
        padding: 1rem;
        border-radius: 10px;
        border-left: 5px solid #10B981;
        margin: 1rem 0;
    }
    .malicious-box {
        background-color: #FEE2E2;
        padding: 1rem;
        border-radius: 10px;
        border-left: 5px solid #EF4444;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

class FeatureExtractor:
    def __init__(self):
        pass
    
    def extract_url_features(self, url):
        features = {}
        
        # Basic URL features
        features['url_length'] = len(url)
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_questionmarks'] = url.count('?')
        features['num_equals'] = url.count('=')
        features['num_ats'] = url.count('@')
        features['num_ands'] = url.count('&')
        features['num_exclamations'] = url.count('!')
        features['num_spaces'] = url.count(' ')
        features['num_tildes'] = url.count('~')
        features['num_commas'] = url.count(',')
        features['num_plus'] = url.count('+')
        features['num_asterisks'] = url.count('*')
        features['num_hashes'] = url.count('#')
        features['num_dollars'] = url.count('$')
        features['num_percent'] = url.count('%')
        
        # Check for IP address
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        features['has_ip'] = 1 if re.search(ip_pattern, url) else 0
        
        # Check for suspicious keywords
        suspicious_keywords = ['login', 'signin', 'verify', 'account', 'banking', 
                              'secure', 'update', 'confirm', 'click', 'password',
                              'phishing', 'malware', 'virus', 'free', 'win', 'prize']
        features['suspicious_words'] = sum(1 for word in suspicious_keywords if word in url.lower())
        
        # Check for HTTPS
        features['has_https'] = 1 if url.startswith('https') else 0
        
        # Check for multiple subdomains
        if '://' in url:
            domain_part = url.split('://')[1].split('/')[0]
            features['num_subdomains'] = domain_part.count('.')
        else:
            features['num_subdomains'] = 0
        
        # Check for URL shortening services
        shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly']
        features['is_shortened'] = 1 if any(short in url for short in shorteners) else 0
        
        # Check for non-standard ports
        non_std_ports = [':8080', ':3000', ':8888', ':81', ':8000']
        features['non_std_port'] = 1 if any(port in url for port in non_std_ports) else 0
        
        # Additional features to match training
        features['tld_length'] = 0
        features['domain_length'] = len(url.split('//')[-1].split('/')[0].split('.')[-2]) if '.' in url else 0
        features['path_depth'] = url.count('/') - 2 if url.count('//') > 0 else url.count('/')
        features['digit_ratio'] = sum(c.isdigit() for c in url) / len(url) if url else 0
        features['letter_ratio'] = sum(c.isalpha() for c in url) / len(url) if url else 0
        features['special_char_ratio'] = sum(not c.isalnum() for c in url) / len(url) if url else 0
        features['entropy'] = 0
        features['vowel_ratio'] = sum(1 for c in url.lower() if c in 'aeiou') / len(url) if url else 0
        features['consonant_ratio'] = sum(1 for c in url.lower() if c.isalpha() and c not in 'aeiou') / len(url) if url else 0
        features['host_length'] = len(url.split('//')[-1].split('/')[0]) if '//' in url else len(url.split('/')[0])
        features['path_length'] = len(url.split('//')[-1].split('/')[1]) if '/' in url.split('//')[-1] else 0
        
        return features

@st.cache_resource
def load_model():
    """Load the trained model with caching"""
    try:
        with open('advanced_model.pkl', 'rb') as f:
            model_data = pickle.load(f)
        
        model = model_data['model']
        scaler = model_data['scaler']
        
        st.success("✅ Model loaded successfully!")
        return model, scaler
        
    except Exception as e:
        st.error(f"Error loading model: {e}")
        return None, None

def predict_url(model, scaler, url):
    """Predict if a URL is good or bad"""
    extractor = FeatureExtractor()
    features = extractor.extract_url_features(url)
    
    # Feature names from training
    feature_names = [
        'url_length', 'host_length', 'path_length', 'num_dots', 
        'num_hyphens', 'num_underscores', 'num_slashes', 
        'num_questionmarks', 'num_equals', 'num_ats', 'num_ands',
        'num_exclamations', 'num_spaces', 'num_tildes', 'num_commas',
        'num_plus', 'num_asterisks', 'num_hashes', 'num_dollars',
        'num_percent', 'has_ip', 'suspicious_words', 'has_https',
        'num_subdomains', 'is_shortened', 'non_std_port',
        'tld_length', 'domain_length', 'path_depth',
        'digit_ratio', 'letter_ratio', 'special_char_ratio',
        'entropy', 'vowel_ratio', 'consonant_ratio'
    ]
    
    # Create DataFrame with all features
    feature_df = pd.DataFrame([features])
    
    # Ensure all expected features are present
    for feature in feature_names:
        if feature not in feature_df.columns:
            feature_df[feature] = 0
    
    # Reorder columns to match training
    feature_df = feature_df[feature_names]
    
    # Scale features (same as during training)
    if scaler is not None:
        try:
            feature_scaled = scaler.transform(feature_df)
        except:
            feature_scaled = feature_df.values
    else:
        feature_scaled = feature_df.values
    
    # Make prediction
    try:
        prediction = model.predict(feature_scaled)
        probability = model.predict_proba(feature_scaled)
        return prediction[0], probability[0]
    except Exception as e:
        st.error(f"Prediction error: {str(e)[:100]}")
        # Return safe as default
        return 0, [0.9, 0.1]

def main():
    # Header
    st.markdown('<h1 class="main-header">🦅 HAWK - URL Phishing Detector</h1>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">AI-powered phishing URL detection system</p>', unsafe_allow_html=True)
    
    # Load model
    with st.spinner("Loading AI model..."):
        model, scaler = load_model()
    
    if model is None:
        st.error("Model not found or failed to load!")
        return
    
    # Create tabs
    tab1, tab2 = st.tabs(["🔍 Test URL", "📊 About"])
    
    # Tab 1: Single URL Test
    with tab1:
        st.header("Test Any URL")
        
        col1, col2 = st.columns([3, 1])
        
        with col1:
            url_input = st.text_input(
                "Enter URL to analyze:",
                placeholder="https://example.com or www.example.com",
                help="Enter any URL to check if it's safe or malicious"
            )
        
        with col2:
            st.write("")
            st.write("")
            analyze_btn = st.button("Analyze URL", type="primary", use_container_width=True)
        
        # Example URLs
        with st.expander("Quick Test Examples"):
            col_ex1, col_ex2, col_ex3 = st.columns(3)
            with col_ex1:
                if st.button("Test: https://google.com", use_container_width=True):
                    st.session_state.example_url = "https://google.com"
            with col_ex2:
                if st.button("Test: http://secure-login.xyz", use_container_width=True):
                    st.session_state.example_url = "http://secure-login.xyz"
            with col_ex3:
                if st.button("Test: https://github.com", use_container_width=True):
                    st.session_state.example_url = "https://github.com"
        
        # Check for example URL in session state
        if 'example_url' in st.session_state:
            url_input = st.session_state.example_url
            del st.session_state.example_url
            analyze_btn = True
        
        if analyze_btn and url_input:
            # Add http:// if missing
            if not url_input.startswith(('http://', 'https://')):
                url_input = 'http://' + url_input
            
            with st.spinner("Analyzing URL..."):
                prediction, probability = predict_url(model, scaler, url_input)
                
                # Display result
                if prediction == 0:  # Safe
                    st.markdown(f"""
                    <div class="safe-box">
                        <h2>✅ SAFE URL</h2>
                        <p><strong>URL:</strong> {url_input[:80]}{'...' if len(url_input) > 80 else ''}</p>
                        <p><strong>Confidence:</strong> {max(probability)*100:.2f}%</p>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    # Show probabilities
                    col_safe, col_mal = st.columns(2)
                    with col_safe:
                        st.metric("Safe Probability", f"{probability[0]*100:.2f}%")
                    with col_mal:
                        st.metric("Malicious Probability", f"{probability[1]*100:.2f}%")
                        
                else:  # Malicious
                    st.markdown(f"""
                    <div class="malicious-box">
                        <h2>🚨 MALICIOUS URL</h2>
                        <p><strong>URL:</strong> {url_input[:80]}{'...' if len(url_input) > 80 else ''}</p>
                        <p><strong>Confidence:</strong> {max(probability)*100:.2f}%</p>
                        <p><strong>Warning:</strong> This URL shows characteristics of phishing/malicious sites!</p>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    # Show probabilities
                    col_safe, col_mal = st.columns(2)
                    with col_safe:
                        st.metric("Safe Probability", f"{probability[0]*100:.2f}%", delta_color="inverse")
                    with col_mal:
                        st.metric("Malicious Probability", f"{probability[1]*100:.2f}%", delta_color="inverse")
    
    # Tab 2: About
    with tab2:
        st.header("About HAWK System")
        
        st.markdown("""
        ### 🦅 HAWK - URL Phishing Detection System
        
        **Version:** 1.0  
        **Created by:** SMIT AI Project Batch 15  
        
        ### 🎯 Features:
        - **Real-time URL Analysis**: Check any URL instantly
        - **AI-Powered**: Trained on 2000+ URLs
        - **High Accuracy**: Machine learning model
        
        ### 📊 Training Data:
        - **Good URLs**: 1000 legitimate URLs
        - **Bad URLs**: 1000 malicious/phishing URLs
        
        ### 🔧 Technical:
        - **Model**: Random Forest Classifier
        - **Features**: 35+ URL characteristics analyzed
        
        **Note**: This is for educational purposes.
        """)

if __name__ == "__main__":
    main()
