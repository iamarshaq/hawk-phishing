import streamlit as st
import pandas as pd
import numpy as np
import pickle
import re
import warnings
warnings.filterwarnings('ignore')

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
    .result-box {
        background-color: #F3F4F6;
        padding: 1.5rem;
        border-radius: 10px;
        margin: 1rem 0;
    }
    .feature-importance {
        background-color: #E0F2FE;
        padding: 1rem;
        border-radius: 10px;
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
        
        # Additional features
        features['tld_length'] = 0
        if '.' in url:
            parts = url.split('//')[-1].split('/')[0].split('.')
            features['domain_length'] = len(parts[-2]) if len(parts) >= 2 else 0
        else:
            features['domain_length'] = 0
        
        features['path_depth'] = url.count('/') - 2 if url.count('//') > 0 else url.count('/')
        features['digit_ratio'] = sum(c.isdigit() for c in url) / len(url) if url else 0
        features['letter_ratio'] = sum(c.isalpha() for c in url) / len(url) if url else 0
        features['special_char_ratio'] = sum(not c.isalnum() for c in url) / len(url) if url else 0
        features['entropy'] = 0
        
        vowels = sum(1 for c in url.lower() if c in 'aeiou')
        features['vowel_ratio'] = vowels / len(url) if url else 0
        features['consonant_ratio'] = sum(1 for c in url.lower() if c.isalpha() and c not in 'aeiou') / len(url) if url else 0
        
        features['host_length'] = len(url.split('//')[-1].split('/')[0]) if '//' in url else len(url.split('/')[0])
        
        if '/' in url.split('//')[-1]:
            features['path_length'] = len(url.split('//')[-1].split('/')[1])
        else:
            features['path_length'] = 0
        
        return features

@st.cache_resource
def load_model():
    """Load the trained model with caching"""
    try:
        with open('advanced_model.pkl', 'rb') as f:
            model_data = pickle.load(f)
        
        model = model_data['model']
        scaler = model_data['scaler']
        
        # Load feature importance
        try:
            feature_importance = pd.read_csv('feature_importance.csv')
        except:
            feature_importance = None
        
        return model, scaler, feature_importance
        
    except Exception as e:
        st.error(f"Error loading model: {e}")
        return None, None, None

@st.cache_data
def load_dataset():
    """Load dataset with caching"""
    try:
        df = pd.read_csv('advanced_dataset.csv')
        return df
    except:
        return None

def predict_url(model, scaler, url):
    """Predict if a URL is good or bad"""
    extractor = FeatureExtractor()
    features = extractor.extract_url_features(url)
    
    # Feature names in correct order
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
    
    # Create DataFrame
    feature_df = pd.DataFrame([features])
    
    # Ensure all features are present
    for feature in feature_names:
        if feature not in feature_df.columns:
            feature_df[feature] = 0
    
    feature_df = feature_df[feature_names]
    
    # Scale features
    if scaler:
        feature_scaled = scaler.transform(feature_df)
    else:
        feature_scaled = feature_df.values
    
    # Make prediction
    prediction = model.predict(feature_scaled)
    probability = model.predict_proba(feature_scaled)
    
    return prediction[0], probability[0]

def main():
    # Header
    st.markdown('<h1 class="main-header">🦅 HAWK - URL Phishing Detector</h1>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">AI-powered phishing URL detection system</p>', unsafe_allow_html=True)
    
    # Load model and data
    with st.spinner("Loading AI model..."):
        model, scaler, feature_importance = load_model()
        dataset = load_dataset()
    
    if model is None:
        st.error("Model not found! Please run train_advanced.py first.")
        return
    
    # Create tabs
    tab1, tab2, tab3, tab4 = st.tabs(["🔍 Single URL Test", "📁 Batch Test", "📊 Dashboard", "ℹ️ About"])
    
    # Tab 1: Single URL Test
    with tab1:
        st.header("Test Single URL")
        
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
                if st.button("Test: http://secure-login-verify.xyz", use_container_width=True):
                    st.session_state.example_url = "http://secure-login-verify.xyz"
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
                    
                    # Show suspicious indicators
                    with st.expander("Why is this URL suspicious?"):
                        extractor = FeatureExtractor()
                        features = extractor.extract_url_features(url_input)
                        
                        suspicious_features = []
                        if features['suspicious_words'] > 0:
                            suspicious_features.append(f"Contains {features['suspicious_words']} suspicious keywords")
                        if features['has_ip'] == 1:
                            suspicious_features.append("Contains IP address")
                        if features['is_shortened'] == 1:
                            suspicious_features.append("URL shortening service detected")
                        if features['num_subdomains'] > 2:
                            suspicious_features.append(f"Too many subdomains ({features['num_subdomains']})")
                        
                        if suspicious_features:
                            for feature in suspicious_features:
                                st.write(f"• {feature}")
                        else:
                            st.write("AI model detected patterns associated with malicious URLs")
                
                # Show feature analysis
                with st.expander("View Technical Analysis"):
                    extractor = FeatureExtractor()
                    features = extractor.extract_url_features(url_input)
                    
                    # Convert to DataFrame for display
                    features_df = pd.DataFrame.from_dict(features, orient='index', columns=['Value'])
                    features_df = features_df.sort_index()
                    
                    st.dataframe(features_df, use_container_width=True)
    
    # Tab 2: Batch Test
    with tab2:
        st.header("Batch URL Testing")
        
        uploaded_file = st.file_uploader("Upload a text file with URLs (one per line)", type=['txt'])
        
        if uploaded_file is not None:
            urls = [line.decode('utf-8').strip() for line in uploaded_file if line.strip()]
            
            if urls:
                st.success(f"Loaded {len(urls)} URLs from file")
                
                if st.button("Analyze All URLs", type="primary"):
                    results = []
                    progress_bar = st.progress(0)
                    
                    for i, url in enumerate(urls):
                        if not url.startswith(('http://', 'https://')):
                            url = 'http://' + url
                        
                        prediction, probability = predict_url(model, scaler, url)
                        results.append({
                            'URL': url,
                            'Status': 'SAFE' if prediction == 0 else 'MALICIOUS',
                            'Safe Score': f"{probability[0]*100:.2f}%",
                            'Malicious Score': f"{probability[1]*100:.2f}%",
                            'Confidence': f"{max(probability)*100:.2f}%"
                        })
                        
                        progress_bar.progress((i + 1) / len(urls))
                    
                    # Display results
                    results_df = pd.DataFrame(results)
                    st.dataframe(results_df, use_container_width=True)
                    
                    # Statistics
                    col1, col2, col3 = st.columns(3)
                    safe_count = sum(1 for r in results if r['Status'] == 'SAFE')
                    malicious_count = len(results) - safe_count
                    
                    with col1:
                        st.metric("Total URLs", len(results))
                    with col2:
                        st.metric("Safe URLs", safe_count)
                    with col3:
                        st.metric("Malicious URLs", malicious_count)
                    
                    # Download button
                    csv = results_df.to_csv(index=False)
                    st.download_button(
                        label="Download Results as CSV",
                        data=csv,
                        file_name="hawk_url_analysis.csv",
                        mime="text/csv"
                    )
    
    # Tab 3: Dashboard
    with tab3:
        st.header("System Dashboard")
        
        if dataset is not None:
            # Dataset stats
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Total URLs", len(dataset))
            
            if 'label' in dataset.columns:
                safe_count = (dataset['label'] == 0).sum()
                malicious_count = (dataset['label'] == 1).sum()
                
                with col2:
                    st.metric("Safe URLs", safe_count)
                with col3:
                    st.metric("Malicious URLs", malicious_count)
                with col4:
                    st.metric("Balance Ratio", f"{safe_count/malicious_count:.1f}:1")
            
            # Feature importance
            if feature_importance is not None:
                st.subheader("Top 10 Most Important Features")
                
                top_features = feature_importance.head(10)
                
                # Display as bar chart
                st.bar_chart(top_features.set_index('feature')['importance'])
                
                # Display as table
                st.dataframe(top_features, use_container_width=True)
            
            # Model info
            st.subheader("Model Information")
            
            col_info1, col_info2 = st.columns(2)
            
            with col_info1:
                st.info(f"**Model Type:** {type(model).__name__}")
                st.info(f"**Features Used:** {len(feature_names) if 'feature_names' in locals() else '35'}")
            
            with col_info2:
                if hasattr(model, 'n_estimators'):
                    st.info(f"**Number of Trees:** {model.n_estimators}")
                if hasattr(model, 'max_depth'):
                    st.info(f"**Max Depth:** {model.max_depth}")
    
    # Tab 4: About
    with tab4:
        st.header("About HAWK System")
        
        st.markdown("""
        ### 🦅 HAWK - URL Phishing Detection System
        
        **Version:** 1.0  
        **Created by:** SMIT AI Project Batch 15  
        **Model:** Advanced Machine Learning Classifier
        
        ### 🎯 Features:
        - **Real-time URL Analysis**: Check any URL instantly
        - **35+ Feature Extraction**: Comprehensive URL analysis
        - **Batch Processing**: Test multiple URLs at once
        - **High Accuracy**: Trained on 2000+ URLs (balanced dataset)
        - **Confidence Scores**: See how confident the AI is
        
        ### 📊 Training Data:
        - **Good URLs**: 1000 legitimate URLs from `massive_good.txt`
        - **Bad URLs**: 1000 malicious/phishing URLs from `massive_bad.txt`
        - **Total**: 2000 URLs for training
        
        ### 🔧 Technical Details:
        - **Feature Extraction**: URL length, character analysis, keyword detection, etc.
        - **Model**: Ensemble classifier (Random Forest/Gradient Boosting)
        - **Framework**: Scikit-learn, Streamlit, Pandas, NumPy
        
        ### 📁 Project Files (Hawk System):
        ```
        advanced_dataset.csv      # Extracted features dataset
        advanced_model.pkl        # Trained AI model
        feature_extractor_advanced.py  # Feature extraction script
        final_app.py              # Command-line interface
        generate_dataset.py       # Dataset generation
        massive_good.txt          # Good URLs dataset
        massive_bad.txt           # Bad URLs dataset
        train_advanced.py         # Model training script
        streamlit_app.py          # This web application
        ```
        
        ### 🚀 How to Use:
        1. **Single Test**: Enter any URL in the first tab
        2. **Batch Test**: Upload a text file with multiple URLs
        3. **View Dashboard**: See statistics and model details
        
        **Note**: This is for educational purposes. Always verify with other security tools.
        """)

if __name__ == "__main__":
    main()