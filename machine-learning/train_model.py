import os
import joblib
import pandas as pd
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

def generate_synthetic_data():
    """Generate raw HTTP strings and corresponding labels."""
    data = []
    
    # Normal Traffic
    normal_payloads = [
        "GET / HTTP/1.1",
        "GET /index.php HTTP/1.1",
        "GET /about.html HTTP/1.1",
        "GET /images/logo.png HTTP/1.1",
        "GET /css/style.css HTTP/1.1",
        "POST /login.php?user=test HTTP/1.1",
        "GET /search?q=apple HTTP/1.1",
        "GET /products.php?id=10 HTTP/1.1",
        "GET /api/v1/users HTTP/1.1"
    ]
    data.extend([(payload, "Normal") for payload in normal_payloads * 20])
    
    # SQL Injection
    sqli_payloads = [
        "GET /search.php?q=' OR '1'='1 HTTP/1.1",
        "GET /login.php?user=admin'-- HTTP/1.1",
        "GET /items?id=1 UNION SELECT 1,2,3-- HTTP/1.1",
        "POST /auth?pass=' AND 1=1-- HTTP/1.1",
        "GET /delete?id='; DROP TABLE users-- HTTP/1.1",
        "GET /product?q=' OR 'a'='a HTTP/1.1",
        "GET /search?q=1; EXEC xp_cmdshell('dir') HTTP/1.1"
    ]
    data.extend([(payload, "SQL Injection") for payload in sqli_payloads * 20])
    
    # XSS
    xss_payloads = [
        "GET /search.php?q=<script>alert('XSS')</script> HTTP/1.1",
        "GET /profile?bio=<body onload=alert('XSS')> HTTP/1.1",
        "GET /view?img=<img src=x onerror=alert('XSS')> HTTP/1.1",
        "GET /link?url=javascript:alert('XSS') HTTP/1.1",
        "POST /comment?text=<svg/onload=alert(1)> HTTP/1.1",
        "GET /search?q=hello<script src=http://evil.com/xss.js></script> HTTP/1.1"
    ]
    data.extend([(payload, "XSS") for payload in xss_payloads * 20])
    
    # Path Traversal
    traversal_payloads = [
        "GET /../../../etc/passwd HTTP/1.1",
        "GET /../../windows/win.ini HTTP/1.1",
        "GET /../config.php HTTP/1.1",
        "GET /....//....//....//etc/passwd HTTP/1.1",
        "GET /download?file=../../../../etc/shadow HTTP/1.1",
        "GET /view?path=..\\..\\..\\windows\\system32\\cmd.exe HTTP/1.1"
    ]
    data.extend([(payload, "Path Traversal") for payload in traversal_payloads * 20])
    
    # We do not train DoS via ML payloads, DoS is handled by RateLimiter
    
    df = pd.DataFrame(data, columns=["payload", "label"])
    return df

def main():
    print("[*] Generating synthetic HTTP string dataset...")
    df = generate_synthetic_data()
    
    X = df["payload"]
    y = df["label"]
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("[*] Building the NLP Pipeline...")
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(analyzer='char_wb', ngram_range=(2, 5))),
        ('clf', RandomForestClassifier(n_estimators=100, random_state=42))
    ])
    
    print("[*] Training the pipeline...")
    pipeline.fit(X_train, y_train)
    
    print("[*] Evaluating the model...")
    y_pred = pipeline.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"Accuracy: {acc:.4f}")
    print(classification_report(y_test, y_pred))
    
    backend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "backend")
    os.makedirs(backend_dir, exist_ok=True)
    model_path = os.path.join(backend_dir, "ml_pipeline.pkl")
    
    print(f"[*] Saving unified pipeline to {model_path}...")
    joblib.dump(pipeline, model_path)
    print("[+] Done!")

if __name__ == "__main__":
    main()
