from flask import Flask, render_template, request, redirect,send_file
import json
import os
import math
import hashlib
from datetime import datetime
import csv
from zxcvbn import zxcvbn



app = Flask(__name__)

@app.route('/check', methods=['GET', 'POST'])
def check_password():
    if request.method == 'POST':
        password = request.form.get('password')

        # Check if password is in generated wordlist
        with open('static/wordlist.txt', 'r') as file:
            wordlist = set(line.strip() for line in file)

        found = password in wordlist
        entropy = calculate_entropy(password)

        # ✅ Get accurate zxcvbn score on backend (not default 0)
        z_result = zxcvbn(password)
        z_score = z_result['score']

        # 👇 Save result in the log file
        log_result(
            user_id="anonymous",  # Replace with email if available
            password=password,
            found=found,
            score=z_score,
            entropy=entropy
        )

        return render_template('check_result.html', found=found, password=password, entropy=entropy)

    return render_template('check_password.html')


def expand_variations(word):
    variations = set()
    if not word:
        return variations

    base = word.lower()
    upper = word.upper()
    title = word.title()

    substitutions = {
        'a': ['4', '@'],
        'e': ['3'],
        'i': ['1'],
        'o': ['0'],
        's': ['5'],
        'l': ['1']
    }

    variations.update([base, upper, title])

    def leetify(w):
        for char, reps in substitutions.items():
            for rep in reps:
                w = w.replace(char, rep)
        return w

    variations.add(leetify(base))
    variations.add(leetify(title))

    return variations

def calculate_entropy(password):
    charset = 0
    if any(c.islower() for c in password):
        charset += 26
    if any(c.isupper() for c in password):
        charset += 26
    if any(c.isdigit() for c in password):
        charset += 10
    if any(c in "!@#$%^&*()-_=+[{]}\|;:'\",<.>/?`~" for c in password):
        charset += 32  # special characters

    length = len(password)
    if charset == 0:
        return 0
    entropy = length * math.log2(charset)
    return round(entropy, 2)


def generate_passwords(data):
    passwords = []
    special_char = "@#!$*"
    common_suffixes = ["123", "@123", "007", "2024", "#", "!"]

    fields = [
        data.get("name", ""),
        data.get("nickname", ""),
        data.get("dob", ""),
        data.get("pet_name", ""),
        data.get("spouse_name", ""),
        data.get("mother_name", ""),
        data.get("father_name", ""),
        data.get("phone_number", ""),
        data.get("email", ""),
        data.get("social_media", ""),
        data.get("vehicle_number", "")
    ]

    raw_fields = [field for field in fields if field]
    fields = set()
    for field in raw_fields:
        fields.update(expand_variations(field))

    dob_clean = data.get("dob", "").replace("/", "")
    year = dob_clean[-4:] if len(dob_clean) >= 8 else ""

    for i in range(1,1000):
        number = str(i)
        number_with_zeros = f"{i:04}"

        for field in fields:
            passwords.append(f"{field}{number}\n")
            passwords.append(f"{number}{field}\n")
            passwords.append(f"{field}{number_with_zeros}\n")
            passwords.append(f"{number_with_zeros}{field}\n")

            for char in special_char:
                passwords.append(f"{char}{number}{field}\n")
                passwords.append(f"{number}{char}{field}\n")
                passwords.append(f"{number}{field}{char}\n")
                passwords.append(f"{char}{number}{field}{char}\n")
                passwords.append(f"{char}{field}{number}\n")
                passwords.append(f"{field}{char}{number}\n")
                passwords.append(f"{field}{number}{char}\n")
                passwords.append(f"{char}{field}{number}{char}\n")

                if i < 1000:
                    passwords.append(f"{char}{field}{number_with_zeros}\n")
                    passwords.append(f"{field}{char}{number_with_zeros}\n")
                    passwords.append(f"{field}{number_with_zeros}{char}\n")
                    passwords.append(f"{char}{field}{number_with_zeros}{char}\n")
                    passwords.append(f"{char}{number_with_zeros}{field}\n")
                    passwords.append(f"{number_with_zeros}{char}{field}\n")
                    passwords.append(f"{number_with_zeros}{field}{char}\n")
                    passwords.append(f"{char}{number_with_zeros}{field}{char}\n")

            for suffix in common_suffixes:
                passwords.append(f"{field}{suffix}\n")
                passwords.append(f"{suffix}{field}\n")

            if year:
                passwords.append(f"{field}{year}\n")
                passwords.append(f"{year}{field}\n")

    return passwords

def log_result(user_id, password, found, score, entropy):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    log_data = {
        "user": user_id,

        "timestamp": datetime.now().isoformat(),
        "password_hash": hashed_password,
        "password": password,
        "found_in_wordlist": found,
        "zxcvbn_score": score,
        "entropy": entropy
    }
    with open("logs/user_results.jsonl", "a") as log_file:
        log_file.write(json.dumps(log_data) + "\n")


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate', methods=['POST'])
def generate():
    user_data = {
        "name": request.form.get("name"),
        "nickname": request.form.get("nickname"),
        "dob": request.form.get("dob"),
        "pet_name": request.form.get("pet_name"),
        "spouse_name": request.form.get("spouse_name"),
        "mother_name": request.form.get("mother_name"),
        "father_name": request.form.get("father_name"),
        "phone_number": request.form.get("phone_number"),
        "email": request.form.get("email"),
        "social_media": request.form.get("social_media"),
        "vehicle_number": request.form.get("vehicle_number"),
    }

    with open("user_data.json", "w") as f:
        json.dump(user_data, f, indent=4)

    passwords = generate_passwords(user_data)

    with open(os.path.join("static", "wordlist.txt"), "w") as f:
        f.writelines(passwords)

    return redirect("/check")


@app.route('/admin')
def admin_panel():
    logs = []

    with open("logs/user_results.jsonl", "r") as file:
        for line in file:
            logs.append(json.loads(line.strip()))

    return render_template("admin.html", logs=logs)

@app.route('/admin/export')
def export_logs():
    csv_file = "logs/password_logs.csv"
    with open("logs/user_results.jsonl", "r") as file:
        entries = [json.loads(line) for line in file]

    with open(csv_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=entries[0].keys())
        writer.writeheader()
        writer.writerows(entries)

    return send_file(csv_file, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)