from flask import Flask, render_template, request
import re, secrets, string, hashlib, requests, bcrypt

app = Flask(__name__)

def calculate_entropy(password):
    charset = 0
    if re.search(r"[a-z]", password): charset += 26
    if re.search(r"[A-Z]", password): charset += 26
    if re.search(r"[0-9]", password): charset += 10
    if re.search(r"[^A-Za-z0-9]", password): charset += 32
    return len(password) * (charset.bit_length())

def check_pwned(password):
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
    return suffix in response.text

def suggest_password(length=16):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(chars) for _ in range(length))

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    suggestions = []
    entropy = 0
    generated = None

    if request.method == "POST":
        password = request.form["password"]
        score = 0

        # Length
        if len(password) >= 12: score += 2
        else: suggestions.append("Use at least 12 characters.")

        # Complexity
        if re.search(r"[A-Z]", password): score += 1
        else: suggestions.append("Add uppercase letters.")
        if re.search(r"[a-z]", password): score += 1
        else: suggestions.append("Add lowercase letters.")
        if re.search(r"[0-9]", password): score += 1
        else: suggestions.append("Include numbers.")
        if re.search(r"[^A-Za-z0-9]", password): score += 1
        else: suggestions.append("Include special characters.")

        # Entropy
        entropy = calculate_entropy(password)
        if entropy < 50:
            suggestions.append("Increase randomness for higher entropy.")

        # Breach check
        if check_pwned(password):
            suggestions.append("This password has appeared in breaches!")
            score = 0

        result = "Weak" if score <= 2 else "Moderate" if score <= 4 else "Strong"
        generated = suggest_password()

    return render_template("index.html", result=result, entropy=entropy,
                           suggestions=suggestions, generated=generated)

if __name__ == "__main__":
    app.run(debug=True)
