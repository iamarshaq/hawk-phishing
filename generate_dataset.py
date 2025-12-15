import random

# 1. Generate 1000 LEGITIMATE URLs (Patterns)
legit_patterns = [
    "https://www.{}.com",
    "https://{}.com", 
    "https://www.{}.org",
    "https://{}.edu",
    "https://{}.gov",
    "https://{}.net",
    "https://blog.{}.com",
    "https://shop.{}.com",
    "https://news.{}.com",
    "https://app.{}.com"
]

legit_keywords = [
    "google", "amazon", "facebook", "netflix", "youtube", "wikipedia", "github", 
    "twitter", "instagram", "linkedin", "microsoft", "apple", "adobe", "spotify",
    "reddit", "quora", "stackoverflow", "medium", "wordpress", "wix", "shopify",
    "paypal", "stripe", "zoom", "slack", "dropbox", "notion", "figma", "canva",
    "airbnb", "uber", "ola", "swiggy", "zomato", "flipkart", "myntra", "ajio",
    "irctc", "makemytrip", "goibibo", "bookmyshow", "hotstar", "sonyliv", "voot",
    "hdfc", "icici", "sbi", "axis", "kotak", "yesbank", "indusind", "pnb"
]

# 2. Generate 1000 PHISHING URLs (Patterns)
phish_patterns = [
    "http://{}-login-secure.com",
    "http://secure-{}-verify.net", 
    "http://{}-account-confirm.xyz",
    "http://{}-password-reset.top",
    "http://update-{}-banking.club",
    "http://{}-wallet-approval.info",
    "http://verify-{}-identity.online",
    "http://{}-payment-update.work",
    "http://security-{}-alert.site",
    "http://{}-recovery-authorize.space"
]

phish_keywords = [
    "login", "secure", "verify", "account", "banking", "confirm", "update",
    "password", "wallet", "paypal", "signin", "validation", "alert", "recovery",
    "reset", "activation", "block", "payment", "transfer", "transaction", "fund",
    "card", "credit", "debit", "pin", "otp", "authorize", "authenticate", "access",
    "profile", "settings", "billing", "subscription", "premium", "offer", "deal",
    "discount", "free", "win", "prize", "reward", "bonus", "cashback", "refund"
]

# Generate URLs
print("Generating 2000 URLs dataset...")

with open('massive_good.txt', 'w') as f:
    for _ in range(1000):
        pattern = random.choice(legit_patterns)
        keyword = random.choice(legit_keywords)
        # Add some variations
        if random.random() > 0.5:
            keyword = keyword + str(random.randint(1, 99))
        url = pattern.format(keyword)
        f.write(url + '\n')

with open('massive_bad.txt', 'w') as f:
    for _ in range(1000):
        pattern = random.choice(phish_patterns)
        keyword = random.choice(phish_keywords)
        # Mix with legit keywords sometimes (makes it harder)
        if random.random() > 0.7:
            keyword = random.choice(legit_keywords) + "-" + keyword
        url = pattern.format(keyword)
        f.write(url + '\n')

print("✅ Created massive_good.txt (1000 legit URLs)")
print("✅ Created massive_bad.txt (1000 phishing URLs)")