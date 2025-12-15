import pandas as pd
import numpy as np
import re
import tldextract
from urllib.parse import urlparse
import warnings
warnings.filterwarnings('ignore')

class AdvancedFeatureExtractor:
    def __init__(self):
        self.feature_names = [
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
    
    def calculate_entropy(self, text):
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0
        entropy = 0
        for char in set(text):
            p_x = text.count(char) / len(text)
            entropy += -p_x * np.log2(p_x)
        return entropy
    
    def extract_features(self, url):
        """Extract all features from a URL"""
        features = {}
        
        # Basic length features
        features['url_length'] = len(url)
        
        # Parse URL components
        parsed = urlparse(url)
        extracted = tldextract.extract(url)
        
        features['host_length'] = len(parsed.netloc) if parsed.netloc else 0
        features['path_length'] = len(parsed.path) if parsed.path else 0
        features['tld_length'] = len(extracted.suffix) if extracted.suffix else 0
        features['domain_length'] = len(extracted.domain) if extracted.domain else 0
        
        # Character counts
        chars = ['.', '-', '_', '/', '?', '=', '@', '&', '!', ' ', '~', ',', '+', '*', '#', '$', '%']
        char_names = ['dots', 'hyphens', 'underscores', 'slashes', 'questionmarks', 
                     'equals', 'ats', 'ands', 'exclamations', 'spaces', 'tildes', 
                     'commas', 'plus', 'asterisks', 'hashes', 'dollars', 'percent']
        
        for char, name in zip(chars, char_names):
            features[f'num_{name}'] = url.count(char)
        
        # IP address detection
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        features['has_ip'] = 1 if re.search(ip_pattern, url) else 0
        
        # Suspicious keywords
        suspicious_keywords = [
            'login', 'signin', 'verify', 'account', 'banking', 'secure', 
            'update', 'confirm', 'click', 'password', 'phishing', 'malware',
            'virus', 'free', 'win', 'prize', 'bonus', 'offer', 'gift',
            'reward', 'cash', 'money', 'alert', 'warning', 'urgent',
            'important', 'security', 'unsubscribe', 'suspend', 'limited',
            'exclusive', 'access', 'verify', 'validation', 'authenticate'
        ]
        features['suspicious_words'] = sum(1 for word in suspicious_keywords if word in url.lower())
        
        # Protocol features
        features['has_https'] = 1 if url.lower().startswith('https') else 0
        
        # Subdomain analysis
        if parsed.netloc:
            subdomains = parsed.netloc.split('.')
            features['num_subdomains'] = max(0, len(subdomains) - 2)
        else:
            features['num_subdomains'] = 0
        
        # URL shortening detection
        shorteners = [
            'bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
            'shorturl', 'shorte.st', 'bc.vc', 'adf.ly', 'bitly.com',
            'cutt.ly', 'short.cm', 'tiny.cc', 'url.ie'
        ]
        features['is_shortened'] = 1 if any(short in parsed.netloc.lower() for short in shorteners) else 0
        
        # Port detection
        non_std_ports = [':8080', ':3000', ':8888', ':81', ':8000', ':8081',
                        ':8443', ':9000', ':9090', ':10000']
        features['non_std_port'] = 1 if any(port in url for port in non_std_ports) else 0
        
        # Path depth
        if parsed.path:
            features['path_depth'] = parsed.path.strip('/').count('/')
        else:
            features['path_depth'] = 0
        
        # Character ratios
        chars_only = re.sub(r'[^a-zA-Z0-9]', '', url)
        digits_only = re.sub(r'[^0-9]', '', url)
        letters_only = re.sub(r'[^a-zA-Z]', '', url)
        special_chars = len(url) - len(chars_only)
        
        features['digit_ratio'] = len(digits_only) / len(url) if url else 0
        features['letter_ratio'] = len(letters_only) / len(url) if url else 0
        features['special_char_ratio'] = special_chars / len(url) if url else 0
        
        # Entropy
        features['entropy'] = self.calculate_entropy(url)
        
        # Vowel/Consonant ratio (in letters only)
        vowels = sum(1 for char in letters_only.lower() if char in 'aeiou')
        features['vowel_ratio'] = vowels / len(letters_only) if letters_only else 0
        features['consonant_ratio'] = (len(letters_only) - vowels) / len(letters_only) if letters_only else 0
        
        return features
    
    def extract_batch_features(self, urls, labels=None):
        """Extract features from multiple URLs"""
        features_list = []
        valid_urls = []
        valid_labels = []
        
        print(f"Processing {len(urls)} URLs...")
        
        for idx, url in enumerate(urls):
            try:
                features = self.extract_features(url)
                features_list.append(features)
                valid_urls.append(url)
                
                if labels is not None:
                    valid_labels.append(labels[idx])
                
                if (idx + 1) % 100 == 0:
                    print(f"  Processed {idx + 1}/{len(urls)} URLs")
                    
            except Exception as e:
                print(f"  Error processing URL {idx}: {str(e)[:50]}")
                continue
        
        # Create DataFrame
        df = pd.DataFrame(features_list)
        
        # Ensure all features are present
        for feature in self.feature_names:
            if feature not in df.columns:
                df[feature] = 0
        
        # Reorder columns
        df = df[self.feature_names]
        
        # Add URL and label if provided
        df['url'] = valid_urls
        if labels is not None:
            df['label'] = valid_labels
        
        print(f"✓ Successfully processed {len(valid_urls)} URLs")
        print(f"✓ Extracted {len(self.feature_names)} features")
        
        return df

def load_urls_from_files():
    """Load URLs from Hawk's massive_good.txt and massive_bad.txt"""
    try:
        # Load good URLs
        with open('massive_good.txt', 'r', encoding='utf-8', errors='ignore') as f:
            good_urls = [line.strip() for line in f if line.strip()]
        print(f"✓ Loaded {len(good_urls)} good URLs from massive_good.txt")
        
        # Load bad URLs
        with open('massive_bad.txt', 'r', encoding='utf-8', errors='ignore') as f:
            bad_urls = [line.strip() for line in f if line.strip()]
        print(f"✓ Loaded {len(bad_urls)} bad URLs from massive_bad.txt")
        
        # Combine with labels
        urls = good_urls + bad_urls
        labels = [0] * len(good_urls) + [1] * len(bad_urls)  # 0 = good, 1 = bad
        
        print(f"✓ Total URLs: {len(urls)} (Good: {len(good_urls)}, Bad: {len(bad_urls)})")
        
        return urls, labels
        
    except FileNotFoundError as e:
        print(f"✗ Error: File not found - {e}")
        print("Please ensure massive_good.txt and massive_bad.txt are in the current directory.")
        return [], []
    except Exception as e:
        print(f"✗ Error loading files: {e}")
        return [], []

def main():
    print("=" * 60)
    print("HAWK - Advanced Feature Extractor")
    print("=" * 60)
    
    # Load URLs from Hawk files
    urls, labels = load_urls_from_files()
    
    if not urls:
        print("\n⚠ No URLs loaded. Exiting...")
        return
    
    # Extract features
    extractor = AdvancedFeatureExtractor()
    df = extractor.extract_batch_features(urls, labels)
    
    # Save to CSV
    output_file = 'advanced_dataset.csv'
    df.to_csv(output_file, index=False)
    
    print("\n" + "=" * 60)
    print("FEATURE EXTRACTION COMPLETE")
    print("=" * 60)
    print(f"✓ Saved dataset to: {output_file}")
    print(f"✓ Total records: {len(df)}")
    print(f"✓ Features extracted: {len(extractor.feature_names)}")
    
    # Show dataset info
    print("\nDataset Summary:")
    print(df.info())
    
    print("\nFirst 5 rows:")
    print(df.head())
    
    if 'label' in df.columns:
        print(f"\nClass distribution:")
        print(f"  Good URLs (0): {(df['label'] == 0).sum()}")
        print(f"  Bad URLs (1): {(df['label'] == 1).sum()}")
    
    print("\n" + "=" * 60)
    print("✓ Feature extraction complete!")
    print("  Next step: Run train_advanced.py to train the model")
    print("=" * 60)

if __name__ == "__main__":
    main()