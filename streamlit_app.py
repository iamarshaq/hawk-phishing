import streamlit as st
import re
import pandas as pd

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

class RuleBasedPhishingDetector:
    def __init__(self):
        # High-risk keywords
        self.suspicious_keywords = [
            'login', 'signin', 'verify', 'account', 'banking', 'secure',
            'update', 'confirm', 'password', 'phishing', 'malware',
            'virus', 'free', 'win', 'prize', 'bonus', 'offer'
        ]
        
        # Payment/financial keywords (HIGH RISK)
        self.payment_keywords = [
            'payment', 'card', 'credit', 'debit', 'billing', 'invoice',
            'checkout', 'pay', 'transaction', 'bank', 'financial',
            'cvv', 'pin', 'otp', 'wallet', 'gateway'
        ]
        
        # Urgency keywords
        self.urgency_words = [
            'urgent', 'immediate', 'now', 'verify now', 'act fast',
            'hurry', 'limited time', 'expire', 'today only'
        ]
        
        # Suspicious TLDs
        self.suspicious_tlds = ['.xyz', '.top', '.club', '.gq', '.ml', '.tk', 
                               '.cf', '.ga', '.loan', '.click', '.men']
        
        # Legitimate domains (auto-safe)
        self.legitimate_domains = [
            'google.com', 'facebook.com', 'github.com', 'wikipedia.org',
            'amazon.com', 'netflix.com', 'youtube.com', 'twitter.com',
            'linkedin.com', 'microsoft.com', 'apple.com'
        ]
    
    def analyze_url(self, url):
        """Analyze URL using rule-based system"""
        url_lower = url.lower()
        score = 0
        reasons = []
        
        # Check 1: Contains payment keywords (HIGH RISK)
        payment_count = sum(1 for word in self.payment_keywords if word in url_lower)
        if payment_count > 0:
            score += 30
            reasons.append(f"Contains {payment_count} payment-related keyword(s)")
        
        # Check 2: Contains suspicious keywords
        suspicious_count = sum(1 for word in self.suspicious_keywords if word in url_lower)
        if suspicious_count > 2:
            score += 20
            reasons.append(f"Contains {suspicious_count} suspicious keyword(s)")
        
        # Check 3: Urgency language
        urgency_count = sum(1 for word in self.urgency_words if word in url_lower)
        if urgency_count > 0:
            score += 15
            reasons.append(f"Contains urgency language")
        
        # Check 4: Suspicious TLD
        if any(url_lower.endswith(tld) for tld in self.suspicious_tlds):
            score += 25
            reasons.append("Uses suspicious domain extension")
        
        # Check 5: Brand typosquatting
        if self.has_brand_typo(url_lower):
            score += 40
            reasons.append("Brand typosquatting detected")
        
        # Check 6: No HTTPS for sensitive sites
        if payment_count > 0 and not url_lower.startswith('https'):
            score += 35
            reasons.append("Payment site without HTTPS")
        
        # Check 7: IP address instead of domain
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        if re.search(ip_pattern, url_lower):
            score += 30
            reasons.append("Uses IP address instead of domain")
        
        # Check 8: URL shortening
        shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly']
        if any(short in url_lower for short in shorteners):
            score += 20
            reasons.append("URL shortening service detected")
        
        # Check 9: Excessive length
        if len(url) > 100:
            score += 10
            reasons.append("Excessively long URL")
        
        # Check 10: Legitimate domain (SAFE)
        if any(domain in url_lower for domain in self.legitimate_domains):
            score -= 50  # Subtract points for legitimate sites
            reasons.append("Legitimate domain recognized")
        
        # Cap score
        score = max(0, min(100, score))
        
        # Determine verdict
        if score >= 70:
            verdict = "🚨 MALICIOUS"
            confidence = min(90 + (score - 70), 99)
        elif score >= 40:
            verdict = "⚠️ SUSPICIOUS"
            confidence = 50 + (score - 40)
        else:
            verdict = "✅ SAFE"
            confidence = max(85 - score, 60)
        
        return {
            'verdict': verdict,
            'score': score,
            'confidence': confidence,
            'reasons': reasons,
            'payment_keywords': payment_count,
            'suspicious_keywords': suspicious_count
        }
    
    def has_brand_typo(self, url):
        """Check for brand name typosquatting"""
        brands = ['facebook', 'paypal', 'amazon', 'google', 'microsoft', 
                 'apple', 'netflix', 'instagram', 'whatsapp', 'bank']
        
        for brand in brands:
            if brand in url:
                # Check for common typos
                patterns = [
                    brand.replace('o', '0'),  # faceb00k
                    brand.replace('i', '1'),  # paypa1
                    brand.replace('e', '3'),  # fac3book
                    brand.replace('a', '4'),  # p4ypal
                    brand + '-',              # facebook-
                    '-' + brand,              # -facebook
                    brand + '1',              # facebook1
                ]
                if any(pattern in url for pattern in patterns):
                    return True
        return False

def main():
    # Header
    st.markdown('<h1 class="main-header">🦅 HAWK - URL Phishing Detector</h1>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">Rule-Based Phishing Detection System</p>', unsafe_allow_html=True)
    
    detector = RuleBasedPhishingDetector()
    
    # Create tabs
    tab1, tab2 = st.tabs(["🔍 Test URL", "📊 About"])
    
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
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                if st.button("✅ Google", use_container_width=True):
                    st.session_state.demo_url = "https://google.com"
            with col2:
                if st.button("🚨 Payment Phish", use_container_width=True):
                    st.session_state.demo_url = "http://secure-payment-verify-login.xyz"
            with col3:
                if st.button("✅ GitHub", use_container_width=True):
                    st.session_state.demo_url = "https://github.com"
            with col4:
                if st.button("🚨 Bank Phish", use_container_width=True):
                    st.session_state.demo_url = "http://bank-account-update-secure.top"
        
        # Check for example URL
        if 'demo_url' in st.session_state:
            url_input = st.session_state.demo_url
            del st.session_state.demo_url
            analyze_btn = True
        
        if analyze_btn and url_input:
            # Add http:// if missing
            if not url_input.startswith(('http://', 'https://')):
                url_input = 'http://' + url_input
            
            with st.spinner("Analyzing URL..."):
                result = detector.analyze_url(url_input)
                
                # Display result
                if "MALICIOUS" in result['verdict']:
                    st.markdown(f"""
                    <div class="malicious-box">
                        <h2>{result['verdict']}</h2>
                        <p><strong>URL:</strong> {url_input[:80]}{'...' if len(url_input) > 80 else ''}</p>
                        <p><strong>Risk Score:</strong> {result['score']}/100</p>
                        <p><strong>Confidence:</strong> {result['confidence']:.1f}%</p>
                        <p><strong>Warning:</strong> High probability of phishing/malicious site</p>
                    </div>
                    """, unsafe_allow_html=True)
                    
                elif "SUSPICIOUS" in result['verdict']:
                    st.markdown(f"""
                    <div class="malicious-box">
                        <h2>{result['verdict']}</h2>
                        <p><strong>URL:</strong> {url_input[:80]}{'...' if len(url_input) > 80 else ''}</p>
                        <p><strong>Risk Score:</strong> {result['score']}/100</p>
                        <p><strong>Confidence:</strong> {result['confidence']:.1f}%</p>
                        <p>Exercise caution with this URL.</p>
                    </div>
                    """, unsafe_allow_html=True)
                    
                else:
                    st.markdown(f"""
                    <div class="safe-box">
                        <h2>{result['verdict']}</h2>
                        <p><strong>URL:</strong> {url_input[:80]}{'...' if len(url_input) > 80 else ''}</p>
                        <p><strong>Risk Score:</strong> {result['score']}/100</p>
                        <p><strong>Confidence:</strong> {result['confidence']:.1f}%</p>
                    </div>
                    """, unsafe_allow_html=True)
                
                # Show risk factors
                if result['reasons']:
                    st.subheader("🔍 Risk Factors Detected:")
                    for reason in result['reasons']:
                        st.write(f"• {reason}")
                
                # Show metrics
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Risk Score", f"{result['score']}/100")
                with col2:
                    st.metric("Confidence", f"{result['confidence']:.1f}%")
                with col3:
                    st.metric("Payment Keywords", result['payment_keywords'])
    
    with tab2:
        st.header("About HAWK System")
        
        st.markdown("""
        ### 🦅 HAWK - Rule-Based Phishing Detector
        
        **Version:** 2.0 (Rule-Based Engine)  
        **Created by:** SMIT AI Project Batch 15  
        
        ### 🎯 Detection Rules:
        1. **Payment Keywords**: card, payment, bank, CVV, PIN
        2. **Suspicious TLDs**: .xyz, .top, .loan, .click
        3. **Brand Typosquatting**: faceb00k.com, paypa1.com
        4. **Urgency Language**: urgent, immediate, act fast
        5. **No HTTPS**: Payment sites without encryption
        6. **IP Addresses**: Using IP instead of domain
        7. **URL Shorteners**: bit.ly, tinyurl masking
        
        ### ✅ Safe Sites:
        - google.com, facebook.com, github.com
        - amazon.com, netflix.com, youtube.com
        
        ### 🚨 High-Risk Indicators:
        - Payment sites on .xyz domains
        - Bank login pages without HTTPS
        - URLs with "secure-payment-verify"
        


if __name__ == "__main__":
    main()

