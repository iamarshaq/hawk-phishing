import pandas as pd
import numpy as np
import pickle
import re
import warnings
warnings.filterwarnings('ignore')

class FeatureExtractor:
    def __init__(self):
        self.features = []
    
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
        
        # Additional features from training
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

def load_model():
    """Load the trained model from Hawk files"""
    try:
        with open('advanced_model.pkl', 'rb') as f:
            model_data = pickle.load(f)
        
        # Extract the actual model from the dictionary
        model = model_data['model']
        scaler = model_data['scaler']
        
        print("✓ Model loaded successfully from advanced_model.pkl")
        return model, scaler
        
    except FileNotFoundError:
        print("✗ Model file not found. Please run train_advanced.py first.")
        return None, None
    except Exception as e:
        print(f"✗ Error loading model: {e}")
        return None, None

def load_dataset():
    """Load the dataset for reference (optional)"""
    try:
        df = pd.read_csv('advanced_dataset.csv')
        print(f"✓ Dataset loaded: {len(df)} records")
        return df
    except FileNotFoundError:
        print("⚠ Dataset file not found. Continuing without dataset...")
        return None

def predict_url(model, scaler, url):
    """Predict if a URL is good or bad"""
    extractor = FeatureExtractor()
    features = extractor.extract_url_features(url)
    
    # Feature names in the correct order (from training)
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
    
    # Reorder columns
    feature_df = feature_df[feature_names]
    
    # Scale features (same as during training)
    if scaler:
        feature_scaled = scaler.transform(feature_df)
    else:
        feature_scaled = feature_df.values
    
    # Make prediction
    prediction = model.predict(feature_scaled)
    probability = model.predict_proba(feature_scaled)
    
    return prediction[0], probability[0]

def main():
    print("=" * 60)
    print("HAWK - URL Phishing Detector")
    print("=" * 60)
    
    # Load model and dataset
    model, scaler = load_model()
    if model is None:
        return
    
    dataset = load_dataset()
    
    print("\n" + "=" * 60)
    print("PREDICTION MODE")
    print("=" * 60)
    
    while True:
        print("\nOptions:")
        print("1. Test a single URL")
        print("2. Test multiple URLs from file")
        print("3. Show dataset statistics")
        print("4. Exit")
        
        choice = input("\nEnter choice (1-4): ").strip()
        
        if choice == '1':
            url = input("\nEnter URL to test: ").strip()
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            if url:
                prediction, probability = predict_url(model, scaler, url)
                print("\n" + "=" * 40)
                print(f"URL: {url[:60]}..." if len(url) > 60 else f"URL: {url}")
                print(f"Prediction: {'🚨 MALICIOUS' if prediction == 1 else '✅ SAFE'}")
                print(f"Confidence: {max(probability)*100:.2f}%")
                print(f"Safe probability: {probability[0]*100:.2f}%")
                print(f"Malicious probability: {probability[1]*100:.2f}%")
                
                # Add explanation
                if prediction == 1:
                    print("\n⚠ Warning: This URL shows characteristics of phishing/malicious sites!")
                else:
                    print("\n✓ This URL appears to be safe.")
                print("=" * 40)
        
        elif choice == '2':
            filename = input("\nEnter filename with URLs (one per line): ").strip()
            try:
                with open(filename, 'r') as f:
                    urls = [line.strip() for line in f if line.strip()]
                
                print(f"\nTesting {len(urls)} URLs...")
                results = []
                
                for url in urls:
                    if not url.startswith(('http://', 'https://')):
                        url = 'http://' + url
                    
                    prediction, probability = predict_url(model, scaler, url)
                    results.append({
                        'url': url,
                        'prediction': 'MALICIOUS' if prediction == 1 else 'SAFE',
                        'confidence': max(probability) * 100,
                        'safe_prob': probability[0] * 100,
                        'malicious_prob': probability[1] * 100
                    })
                    print(f"{'🔴' if prediction == 1 else '🟢'} {url[:50]}...")
                
                # Save results
                results_df = pd.DataFrame(results)
                results_df.to_csv('url_predictions.csv', index=False)
                print(f"\n✓ Results saved to url_predictions.csv")
                
                # Show summary
                malicious_count = sum(1 for r in results if r['prediction'] == 'MALICIOUS')
                print(f"\nSummary:")
                print(f"Total URLs: {len(urls)}")
                print(f"Safe URLs: {len(urls) - malicious_count}")
                print(f"Malicious URLs: {malicious_count}")
                
            except FileNotFoundError:
                print(f"✗ File '{filename}' not found.")
            except Exception as e:
                print(f"✗ Error: {e}")
        
        elif choice == '3' and dataset is not None:
            print("\n" + "=" * 40)
            print("DATASET STATISTICS")
            print("=" * 40)
            print(f"Total records: {len(dataset)}")
            if 'label' in dataset.columns:
                safe_count = (dataset['label'] == 0).sum()
                malicious_count = (dataset['label'] == 1).sum()
                print(f"Safe URLs (label 0): {safe_count}")
                print(f"Malicious URLs (label 1): {malicious_count}")
                print(f"Ratio: {safe_count/malicious_count:.2f}:1" if malicious_count > 0 else "No malicious URLs")
            
            print("\nFirst 5 records:")
            print(dataset.head().to_string())
        
        elif choice == '4':
            print("\nExiting HAWK URL Detector. Goodbye!")
            break
        
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()