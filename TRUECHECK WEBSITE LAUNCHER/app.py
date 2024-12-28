from flask import Flask, render_template, request, flash, redirect, url_for, session
import pickle
import os
import re  # Import regex for phone number validation
import sqlite3  # Import SQLite for database operations
import joblib

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Set a secret key for session management

# Load models and vectorizers
model_path = './models'
print(f"Loading models from: {os.path.abspath(model_path)}")  # Debug: Print the absolute model path

try:
    # Load URL model and vectorizer
    url_model = pickle.load(open(os.path.join(model_path, 'url_model.pkl'), 'rb'))
    url_vectorizer = pickle.load(open(os.path.join(model_path, 'url_vectorizer.pkl'), 'rb'))

    # Load Email model and vectorizer
    email_model = pickle.load(open(os.path.join(model_path, 'email_model.pkl'), 'rb'))
    email_vectorizer = pickle.load(open(os.path.join(model_path, 'email_vectorizer.pkl'), 'rb'))

    # Load SMS model and vectorizer
    sms_model = pickle.load(open(os.path.join(model_path, 'sms_model.pkl'), 'rb'))
    sms_vectorizer = pickle.load(open(os.path.join(model_path, 'sms_vectorizer.pkl'), 'rb'))

    # Load phishing model and vectorizer
    phishing_model = joblib.load(os.path.join(model_path, 'phishing_model.pkl'))
    phishing_vectorizer = joblib.load(os.path.join(model_path, 'vectorizer.pkl'))

except FileNotFoundError as e:
    print(f"Error loading model: {e}")  # Debug: Print the error if a file is not found

# Hardcoded credentials for demo purposes (change or integrate with a database)
users = {'admin': 'password@123'}

# Database setup
def init_db():
    conn = sqlite3.connect('votes.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS votes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        choice TEXT NOT NULL
    )''')
    conn.commit()
    conn.close()

@app.route('/')
def home():
    return render_template('home.html')

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check credentials
        if username in users and users[username] == password:
            session['user'] = username  # Store username in session
            flash('Login successful!', 'success')
            return redirect(url_for('profile'))  # Redirect to profile after login
        else:
            flash('Invalid username or password.', 'error')
            return redirect(url_for('login'))

    return render_template('login.html')

# Profile Route
@app.route('/profile')
def profile():
    if 'user' in session:
        return render_template('profile.html', username=session['user'])  # Pass username to profile
    else:
        flash('Please log in to access your profile.', 'error')
        return redirect(url_for('login'))

# Delete Account Route
@app.route('/delete_account', methods=['POST'])
def delete_account():
    if 'user' in session:
        # Logic to delete the user's account goes here
        # For demo, we'll just log them out and flash a message
        flash(f'Account for {session["user"]} has been deleted.', 'success')
        session.pop('user', None)  # Remove user from session
        return redirect(url_for('home'))
    else:
        flash('Please log in to delete your account.', 'error')
        return redirect(url_for('login'))

# Dashboard Route
@app.route('/dashboard')
def dashboard():
    if 'user' in session:
        return render_template('dashboard.html', username=session['user'])  # Pass username to the dashboard
    else:
        flash('Please log in to access the dashboard.', 'error')
        return redirect(url_for('login'))

# URL Detection Route
@app.route('/url_detection', methods=['GET', 'POST'])
def url_detection():
    if request.method == 'POST':
        url = request.form['url']  # Get the URL input from the form
        if not url:
            flash("URL cannot be empty.", "error")
            return redirect(url_for('url_detection'))

        try:
            url_transformed = url_vectorizer.transform([url])  # Transform URL text using vectorizer
            prediction = url_model.predict(url_transformed)  # Predict the label

            # Convert numerical prediction to label
            label_map = {0: 'Safe', 1: 'Phishing'}
            result = label_map[prediction[0]]
            return render_template('url_detection.html', result=result, url=url)
        except Exception as e:
            flash(f"Error during URL detection: {e}", "error")
            return redirect(url_for('url_detection'))

    return render_template('url_detection.html')

# Email Detection Route
@app.route('/email_detection', methods=['GET', 'POST'])
def email_detection():
    if request.method == 'POST':
        email = request.form['email']  # Get the email input from the form
        if not email:
            flash("Email cannot be empty.", "error")
            return redirect(url_for('email_detection'))

        try:
            email_transformed = email_vectorizer.transform([email])  # Transform email text using vectorizer
            prediction = email_model.predict(email_transformed)  # Predict the label

            # Convert numerical prediction to label
            label_map = {0: 'Safe', 1: 'Phishing'}
            result = label_map[prediction[0]]
            return render_template('email_detection.html', result=result)
        except Exception as e:
            flash(f"Error during email detection: {e}", "error")
            return redirect(url_for('email_detection'))

    return render_template('email_detection.html')

# SMS Detection Route
@app.route('/sms_detection', methods=['GET', 'POST'])
def sms_detection():
    if request.method == 'POST':
        sms = request.form['sms']  # Get the SMS input from the form
        if not sms:
            flash("SMS cannot be empty.", "error")
            return redirect(url_for('sms_detection'))

        try:
            sms_transformed = sms_vectorizer.transform([sms])  # Transform SMS text using vectorizer
            prediction = sms_model.predict(sms_transformed)  # Predict the label

            # Convert numerical prediction to label
            label_map = {0: 'Ham', 1: 'Spam', 2: 'Smishing'}
            result = label_map[prediction[0]]
            return render_template('sms_detection.html', result=result)
        except Exception as e:
            flash(f"Error during SMS detection: {e}", "error")
            return redirect(url_for('sms_detection'))

    return render_template('sms_detection.html')

# Phone Number Detection Route
@app.route('/phone_number_detection', methods=['GET', 'POST'])
def phone_number_detection():
    if request.method == 'POST':
        phone_number = request.form['phone_number']  # Get the phone number input from the form
        if not phone_number:
            flash("Phone number cannot be empty.", "error")
            return redirect(url_for('phone_number_detection'))

        result = validate_phone_number(phone_number)  # Validate the phone number
        return render_template('phone_number_detection.html', result=result)

    return render_template('phone_number_detection.html')

def validate_phone_number(phone_number):
    # Comprehensive regex for validating phone numbers
    # This regex allows valid phone number formats like:
    # - Country code with "+" sign (optional)
    # - Digits with or without spaces, dashes, or parentheses
    # - Ensures phone number is between 10 and 15 digits
    # - Disallows invalid patterns like starting with 123, 555, etc.
    pattern = re.compile(r'^(?:(?:\+|00)[1-9]\d{0,2})?[\s()-]*([6-9]\d{9,14})[\s()-]*$')
    
    # Check for invalid sequences
    # For example, "1234567890", "5555555555", or repetitive patterns
    invalid_patterns = [
        r'123',      # Avoids starting with "123"
        r'(\d)\1{4,}',  # Avoids repetitive numbers (e.g., 55555 or 888888)
        r'555',      # Disallows sequences starting with 555
    ]
    
    # First, check if it matches the general phone number pattern
    if pattern.match(phone_number):
        # Then, check against invalid patterns
        for invalid in invalid_patterns:
            if re.search(invalid, phone_number):
                return "Warning: This phone number seems suspicious or invalid."

        # If it passes both checks, it's considered valid
        return "Safe: This phone number seems valid."
    else:
        return "Warning: This phone number may be invalid or suspicious."

# Example usage:
phone_number = "+91 98765 43210"  # Replace with the phone number to validate
result = validate_phone_number(phone_number)
print(result)
# Credit Card Detection Route
@app.route('/credit_card_detection', methods=['GET', 'POST'])
def credit_card_detection():
    if request.method == 'POST':
        card_number = request.form['card_number']
        expiry_date = request.form['expiry_date']
        cvv = request.form['cvv']

        # Validate input fields
        if not card_number or not expiry_date or not cvv:
            flash("All fields are required.", "error")
            return redirect(url_for('credit_card_detection'))

        # Simple validation logic for fraud detection
        result = validate_credit_card(card_number)

        return render_template('credit_card_detection.html', result=result)

    return render_template('credit_card_detection.html')

def validate_credit_card(card_number):
    # Validate card number (this is basic and should be improved for real applications)
    if len(card_number) == 16 and card_number.isdigit() and card_number.startswith('4'):
        return "This card is potentially valid."
    elif len(card_number) == 16 and card_number.isdigit():
        return "This card may be fraudulent."
    else:
        return "Invalid card number format."

# # Feedback Voting Route
@app.route('/vote', methods=['GET', 'POST'])
def vote():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        choice = request.form['choice']
        
        # Insert the vote into the database
        conn = sqlite3.connect('votes.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO votes (name, email, choice) VALUES (?, ?, ?)', (name, email, choice))
        conn.commit()
        conn.close()

        flash('Your vote has been submitted!', 'success')
        return redirect(url_for('vote'))

    return render_template('vote.html')

# Check Vote Route
@app.route('/check_vote', methods=['GET', 'POST'])
def check_vote():
    if request.method == 'POST':
        email = request.form['email']

        # Fetch the vote based on the email
        conn = sqlite3.connect('votes.db')
        cursor = conn.cursor()
        cursor.execute('SELECT name, choice FROM votes WHERE email = ?', (email,))
        vote = cursor.fetchone()
        conn.close()

        if vote:
            return render_template('check_vote.html', name=vote[0], choice=vote[1])
        else:
            flash('No vote found for the provided email.')
            return redirect(url_for('check_vote'))

    return render_template('check_vote.html')



# Logout Route
@app.route('/logout')
def logout():
    session.pop('user', None)  # Remove user from session
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

# Update Profile Route (Example)
@app.route('/update_profile', methods=['GET', 'POST'])
def update_profile():
    if 'user' not in session:
        flash('Please log in to update your profile.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Handle profile update logic here
        # Example: Update username or email in the database
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))

    return render_template('update_profile.html')

# Initialize database on startup
init_db()

if __name__ == '__main__':
    app.run(debug=True)
