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
    .warning-box {
        background-color: #FEF3C7;
        padding: 1rem;
        border-radius: 10px;
        border-left: 5px solid #F59E0B;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

class FeatureExtractor:
    def __init__(self):
        # Phishing keyword lists
        self.suspicious_keywords = [
            'login', 'signin', 'verify', 'account', 'banking', 'secure', 
            'update', 'confirm', 'click', 'password', 'phishing', 'malware',
            'virus', 'free', 'win', 'prize', 'bonus', 'offer', 'gift',
            'reward', 'cash', 'money', 'alert', 'warning', 'urgent',
            'important', 'security', 'unsubscribe', 'suspend', 'limited',
            'exclusive', 'access', 'validation', 'authenticate', 'wallet'
        ]
        
        self.payment_keywords = [
            'payment', 'card', 'credit', 'debit', 'billing', 'invoice',
            'checkout', 'pay', 'transaction', 'fund', 'transfer', 'bank',
            'financial', 'money', 'cash', 'wallet', 'gateway', 'stripe',
            'paypal', 'visa', 'mastercard', 'amex', 'cvv', 'pin', 'otp'
        ]
        
        self.urgency_words = [
            'urgent', 'immediate', 'now', 'verify now', 'act fast',
            'instant', 'quick', 'hurry', 'limited time', 'expire',
            'today only', 'last chance', 'final', 'emergency'
        ]
        
        self.suspicious_tlds = ['.xyz', '.top', '.club', '.gq', '.ml', '.tk', 
                               '.cf', '.ga', '.men', '.work', '.loan', '.click']
        
        self.popular_brands = [
            'facebook', 'paypal', 'amazon', 'google', 'microsoft', 'apple',
            'netflix', 'instagram', 'whatsapp', 'twitter', 'linkedin',
            'bank', 'wellsfargo', 'chase', 'citi', 'boa', 'hsbc',
            'ebay', 'aliexpress', 'walmart', 'target', 'bestbuy'
        ]
    
    def calculate_entropy(self, text):
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0
        entropy = 0
        for char in set(text):
            p_x = text.count(char) / len(text)
            entropy += -p_x * np.log2(p_x)
        return entropy
    
    def check_brand_typos(self, url):
        """Check for brand name typosquatting"""
        url_lower = url.lower()
        
        for brand in self.popular_brands:
            if brand in url_lower:
                # Common typosquatting patterns
                patterns = [
                    brand.replace('o', '0'),      # faceb00k
                    brand.replace('i', '1'),      # paypa1
                    brand.replace('e', '3'),      # fac3book
                    brand.replace('a', '4'),      # p4ypal
                    brand.replace('s', '5'),      # 5ecurity
                    brand + '-',                  # facebook-
                    '-' + brand,                  # -facebook
                    brand + '1', '1' + brand,     # facebook1, 1facebook
                    brand[:len(brand)-1],         # faceboo (missing letter)
                    brand + 's',                  # facebooks (extra s)
                ]
                
                for pattern in patterns:
                    if pattern in url_lower and pattern != brand:
                        return 1  # Has typo
        return 0
    
    def check_brand_in_domain(self, url):
        """Check if popular brand is in domain name"""
        try:
            domain = url.split('//')[-1].split('/')[0].split('.')[-2].lower()
            for brand in self.popular_brands:
                if brand in domain:
                    return 1
        except:
            pass
        return 0
    
    def calculate_randomness_score(self, text):
        """Calculate randomness in string"""
        if len(text) < 5:
            return 0
        
        repeat_count = 0
        for i in range(len(text) - 2):
            if text[i] == text[i+1] == text[i+2]:
                repeat_count += 1
        
        alt_count = 0
        for i in range(len(text) - 3):
            if text[i] == text[i+2] and text[i+1] == text[i+3]:
                alt_count += 1
        
        return (repeat_count + alt_count) / len(text)
    
    def extract_url_features(self, url):
        """Extract all features from a URL"""
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
        
        # Keyword-based features
        url_lower = url.lower()
        features['suspicious_words'] = sum(1 for word in self.suspicious_keywords if word in url_lower)
        features['payment_keywords'] = sum(1 for word in self.payment_keywords if word in url_lower)
        features['urgency_words'] = sum(1 for word in self.urgency_words if word in url_lower)
        
        # Protocol features
        features['has_https'] = 1 if url.lower().startswith('https') else 0
        
        # Subdomain analysis
        if '://' in url:
            domain_part = url.split('://')[1].split('/')[0]
            features['num_subdomains'] = domain_part.count('.')
        else:
            features['num_subdomains'] = 0
        
        # URL shortening detection
        shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly']
        features['is_shortened'] = 1 if any(short in url for short in shorteners) else 0
        
        # Port detection
        non_std_ports = [':8080', ':3000', ':8888', ':81', ':8000']
        features['non_std_port'] = 1 if any(port in url for port in non_std_ports) else 0
        
        # Additional features
        features['tld_length'] = 0
        try:
            features['domain_length'] = len(url.split('//')[-1].split('/')[0].split('.')[-2])
        except:
            features['domain_length'] = 0
        
        features['path_depth'] = url.count('/') - 2 if url.count('//') > 0 else url.count('/')
        features['digit_ratio'] = sum(c.isdigit() for c in url) / len(url) if url else 0
        features['letter_ratio'] = sum(c.isalpha() for c in url) / len(url) if url else 0
        features['special_char_ratio'] = sum(not c.isalnum() for c in url) / len(url) if url else 0
        features['entropy'] = self.calculate_entropy(url)
        
        # Vowel/Consonant ratio
        letters_only = re.sub(r'[^a-zA-Z]', '', url)
        vowels = sum(1 for char in letters_only.lower() if char in 'aeiou')
        features['vowel_ratio'] = vowels / len(letters_only) if letters_only else 0
        features['consonant_ratio'] = (len(letters_only) - vowels) / len(letters_only) if letters_only else 0
        
        features['host_length'] = len(url.split('//')[-1].split('/')[0]) if '//' in url else len(url.split('/')[0])
        
        if '/' in url.split('//')[-1]:
            features['path_length'] = len(url.split('//')[-1].split('/')[1])
        else:
            features['path_length'] = 0
        
        # Brand analysis
        features['has_brand_typo'] = self.check_brand_typos(url)
        features['brand_in_domain'] = self.check_brand_in_domain(url)
        
        # TLD analysis
        features['suspicious_tld'] = 1 if any(url_lower.endswith(tld) for tld in self.suspicious_tlds) else 0
        
        # Entropy and randomness
        domain_part = url.split('//')[-1].split('/')[0] if '//' in url else url.split('/')[0]
        features['url_entropy'] = self.calculate_entropy(domain_part)
        features['random_char_score'] = self.calculate_randomness_score(domain_part)
        
        # Token analysis
        tokens = re.findall(r'[a-zA-Z]+', url)
        features['avg_token_length'] = np.mean([len(t) for t in tokens]) if tokens else 0
        
        # Symbol count
        symbols = re.findall(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>/?~]', url)
        features['symbol_count'] = len(symbols)
        
        # Estimate redirects
        features['num_redirects'] = url.count('redirect') + url.count('url=')
        
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
    
    # Feature names from training (45+ features)
    feature_names = [
        'url_length', 'host_length', 'path_length', 'num_dots', 
        'num_hyphens', 'num_underscores', 'num_slashes', 
        'num_questionmarks', 'num_equals', 'num_ats', 'num_ands',
        'num_exclamations', 'num_spaces', 'num_tildes', 'num_commas',
        'num_plus', 'num_asterisks', 'num_hashes', 'num_dollars',
        'num_percent', 'has_ip', 'has_https',
        'num_subdomains', 'is_shortened', 'non_std_port',
        'tld_length', 'domain_length', 'path_depth',
        'digit_ratio', 'letter_ratio', 'special_char_ratio',
        'entropy', 'vowel_ratio', 'consonant_ratio',
        'suspicious_words', 'payment_keywords', 'urgency_words',
        'has_brand_typo', 'suspicious_tld', 'brand_in_domain',
        'num_redirects', 'url_entropy', 'random_char_score',
        'avg_token_length', 'symbol_count'
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
        return prediction[0], probability[0], features
    except Exception as e:
        st.error(f"Prediction error: {str(e)[:100]}")
        # Return safe as default
        return 0, [0.9, 0.1], features

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
            col_ex1, col_ex2, col_ex3, col_ex4 = st.columns(4)
            with col_ex1:
                if st.button("Google", use_container_width=True):
                    st.session_state.example_url = "https://google.com"
            with col_ex2:
                if st.button("Phishing Test", use_container_width=True):
                    st.session_state.example_url = "http://secure-login-verify-payment.xyz"
            with col_ex3:
                if st.button("GitHub", use_container_width=True):
                    st.session_state.example_url = "https://github.com"
            with col_ex4:
                if st.button("Bank Phish", use_container_width=True):
                    st.session_state.example_url = "http://bank-login-secure-account.top"
        
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
                prediction, probability, features = predict_url(model, scaler, url_input)
                
                # Calculate risk score
                risk_score = probability[1] * 100
                
                # Display result
                if prediction == 0 and risk_score < 30:  # Safe
                    st.markdown(f"""
                    <div class="safe-box">
                        <h2>✅ SAFE URL</h2>
                        <p><strong>URL:</strong> {url_input[:80]}{'...' if len(url_input) > 80 else ''}</p>
                        <p><strong>Risk Score:</strong> {risk_score:.1f}/100 (Low Risk)</p>
                    </div>
                    """, unsafe_allow_html=True)
                    
                elif prediction == 0 and risk_score >= 30:  # Warning
                    st.markdown(f"""
                    <div class="warning-box">
                        <h2>⚠️ SUSPICIOUS URL</h2>
                        <p><strong>URL:</strong> {url_input[:80]}{'...' if len(url_input) > 80 else ''}</p>
                        <p><strong>Risk Score:</strong> {risk_score:.1f}/100 (Medium Risk)</p>
                        <p>Exercise caution with this URL.</p>
                    </div>
                    """, unsafe_allow_html=True)
                    
                else:  # Malicious
                    st.markdown(f"""
                    <div class="malicious-box">
                        <h2>🚨 MALICIOUS URL</h2>
                        <p><strong>URL:</strong> {url_input[:80]}{'...' if len(url_input) > 80 else ''}</p>
                        <p><strong>Risk Score:</strong> {risk_score:.1f}/100 (High Risk)</p>
                        <p><strong>Warning:</strong> This URL shows characteristics of phishing/malicious sites!</p>
                    </div>
                    """, unsafe_allow_html=True)
                
                # Show probabilities
                col_safe, col_mal = st.columns(2)
                with col_safe:
                    st.metric("Safe Probability", f"{probability[0]*100:.1f}%")
                with col_mal:
                    st.metric("Malicious Probability", f"{probability[1]*100:.1f}%", 
                             delta=f"+{probability[1]*100:.1f}%" if prediction == 1 else None,
                             delta_color="inverse")
                
                # Show key risk factors
                with st.expander("View Risk Factors"):
                    risk_factors = []
                    
                    if features.get('payment_keywords', 0) > 0:
                        risk_factors.append(f"Contains {features['payment_keywords']} payment-related keywords")
                    
                    if features.get('suspicious_words', 0) > 3:
                        risk_factors.append(f"Contains {features['suspicious_words']} suspicious keywords")
                    
                    if features.get('has_brand_typo', 0) == 1:
                        risk_factors.append("Brand name typosquatting detected")
                    
                    if features.get('suspicious_tld', 0) == 1:
                        risk_factors.append("Uses suspicious domain extension")
                    
                    if features.get('has_ip', 0) == 1:
                        risk_factors.append("Contains IP address instead of domain")
                    
                    if features.get('is_shortened', 0) == 1:
                        risk_factors.append("URL shortening service detected")
                    
                    if features.get('urgency_words', 0) > 0:
                        risk_factors.append(f"Contains {features['urgency_words']} urgency keywords")
                    
                    if risk_factors:
                        st.write("**High-risk indicators found:**")
                        for factor in risk_factors:
                            st.write(f"• {factor}")
                    else:
                        st.write("No obvious risk factors detected. Decision based on ML model analysis.")
    
    # Tab 2: About
    with tab2:
        st.header("About HAWK System")
        
        st.markdown("""
        ### 🦅 HAWK - Advanced Phishing Detection System
        
        **Version:** 2.0 (Enhanced)  
        **Created by:** SMIT AI Project Batch 15  
        
        ### 🎯 Enhanced Features:
        - **45+ URL characteristics** analyzed
        - **Brand typosquatting detection** (faceb00k.com, paypa1.com)
        - **Payment keyword analysis** (card, payment, banking)
        - **Urgency language detection** (urgent, immediate, act fast)
        - **Suspicious TLD detection** (.xyz, .top, .loan)
        - **Randomness analysis** for generated domains
        
        ### 📊 Training Data:
        - **Good URLs**: 1000 legitimate URLs
        - **Bad URLs**: 1000 malicious/phishing URLs
        - **Total**: 2000 URLs with enhanced features
        
        ### 🔧 Detection Capabilities:
        1. **Payment/Financial Phishing**
        2. **Brand Impersonation**
        3. **Credential Harvesting**
        4. **Malware Distribution Sites**
        
        **Note**: This is for educational purposes. Always verify with official sources.
        """)

if __name__ == "__main__":
    main()