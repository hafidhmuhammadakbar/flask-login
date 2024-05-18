from flask import Flask, render_template, request, redirect, url_for, session
from flask_mysqldb import MySQL
import MySQLdb.cursors
import MySQLdb.cursors, re, hashlib
import pyotp
import qrcode
from io import BytesIO
import base64
import requests

app = Flask(__name__)

app.secret_key = 'loginpython'

# Enter your database connection details below
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'pythonlogin'

# Intialize MySQL
mysql = MySQL(app)

# redirect / to /flasklogin
@app.route('/')
def index():
    return redirect(url_for('login'))

# http://localhost:5000/ - the following will be our login page, which will use both GET and POST requests
@app.route('/flasklogin/', methods=['GET', 'POST'])
def login():
    msg = ''
    if 'login_attempts' not in session:
        session['login_attempts'] = 0

    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']

        # Hash the password
        hash = password + app.secret_key
        hash = hashlib.sha1(hash.encode())
        password = hash.hexdigest()

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE username = %s AND password = %s', (username, password))
        account = cursor.fetchone()

        # Verify reCAPTCHA if the user has failed more than 3 times
        if session['login_attempts'] >= 3:
            recaptcha_response = request.form.get('g-recaptcha-response')
            if not recaptcha_response:
                msg = 'Please complete the reCAPTCHA'
                return render_template('index.html', msg=msg)

            recaptcha_secret = '6LcFr5spAAAAAISIBeHQAguCWzyF14JXWvOfgP7J'
            recaptcha_verify_url = 'https://www.google.com/recaptcha/api/siteverify'
            payload = {
                'secret': recaptcha_secret,
                'response': recaptcha_response
            }
            recaptcha_res = requests.post(recaptcha_verify_url, data=payload)
            result = recaptcha_res.json()

            if not result.get('success'):
                msg = 'Invalid reCAPTCHA. Please try again.'
                return render_template('index.html', msg=msg)

        if account:
            session['login_attempts'] = 0  # Reset login attempts on successful login
            if account['2fa_enabled']:
                session['2fa_pending'] = True
                session['id'] = account['id']
                session['username'] = account['username']
                return redirect(url_for('two_factor_auth'))
            else:
                session['loggedin'] = True
                session['id'] = account['id']
                session['username'] = account['username']
                return redirect(url_for('home'))
        else:
            session['login_attempts'] += 1
            msg = 'Incorrect username/password!'

    return render_template('index.html', msg=msg)

# http://localhost:5000/logout - this will be the logout page
@app.route('/flasklogin/logout')
def logout():
    # Remove session data, this will log the user out
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    # Redirect to login page
    return redirect(url_for('login'))

# http://localhost:5000/register - this will be the registration page, we need to use both GET and POST requests
@app.route('/flasklogin/register', methods=['GET', 'POST'])
def register():
    # Output message if something goes wrong...
    msg = ''
    # Check if "username", "password" and "email" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        # Create variables for easy access
        name = request.form['name']
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        # Check if username already exists
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        account = cursor.fetchone()

        # If account exists show error and validation checks
        if account:
            msg = 'Username already exists!'
            return render_template('register.html', msg=msg)
        
        # Check if username and email already exists
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        account = cursor.fetchone()

        if account:
            msg = 'Email already exists!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only characters and numbers!'
        elif not username or not password or not email:
            msg = 'Please fill out the form!'
        else:
            # Hash the password
            hash = password + app.secret_key
            hash = hashlib.sha1(hash.encode())
            password = hash.hexdigest()
            # Account doesn't exist, and the form data is valid, so insert the new account into the users table
            cursor.execute('INSERT INTO users (name, username, password, email) VALUES (%s, %s, %s, %s)', (name, username, password, email,))
            mysql.connection.commit()
            msg = 'You have successfully registered!'
            return render_template('index.html', msg=msg)

    elif request.method == 'POST':
        # Form is empty... (no POST data)
        msg = 'Please fill out the form!'
    # Show registration form with message (if any)
    return render_template('register.html', msg=msg)

# http://localhost:5000/flasklogin/home - this will be the home page, only accessible for logged in users
@app.route('/flasklogin/home')
def home():
    # Check if the user is logged in
    if 'loggedin' in session:
        user_id = session['id']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT 2fa_enabled FROM users WHERE id = %s', (user_id,))
        account = cursor.fetchone()
        
        # Determine if 2FA is enabled
        is_2fa_enabled = account['2fa_enabled'] if account else False
        
        # Render home template with the 2FA status
        return render_template('home.html', username=session['username'], is_2fa_enabled=is_2fa_enabled)
    
    # User is not logged in redirect to login page
    return redirect(url_for('login'))

# http://localhost:5000/flasklogin/profile - this will be the profile page, only accessible for logged in users
@app.route('/flasklogin/profile')
def profile():
    # Check if the user is logged in
    if 'loggedin' in session:
        # We need all the account info for the user so we can display it on the profile page
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE id = %s', (session['id'],))
        account = cursor.fetchone()
        # Show the profile page with account info
        return render_template('profile.html', account=account)
    # User is not logged in redirect to login page
    return redirect(url_for('login'))

@app.route('/flasklogin/2fa')
def two_factor_auth():
    if '2fa_pending' in session and session['2fa_pending']:
        return render_template('2fa.html')
    return redirect(url_for('login'))

@app.route('/flasklogin/verify_2fa', methods=['POST'])
def verify_2fa():
    if '2fa_pending' in session and session['2fa_pending']:
        code = request.form.get('code')
        user_id = session['id']
        
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT 2fa_secret FROM users WHERE id = %s', (user_id,))
        account = cursor.fetchone()

        if account:
            totp = pyotp.TOTP(account['2fa_secret'])
            if totp.verify(code):
                cursor.execute('UPDATE users SET 2fa_enabled = TRUE WHERE id = %s', (user_id,))
                mysql.connection.commit()
                session.pop('2fa_pending', None)
                session['loggedin'] = True
                return redirect(url_for('home'))
            else:
                return "Invalid 2FA code", 400
    return redirect(url_for('login'))

@app.route('/flasklogin/enable_2fa', methods=['GET', 'POST'])
def enable_2fa():
    if 'loggedin' in session:
        if request.method == 'POST':
            user_id = session['id']
            secret = pyotp.random_base32()
            
            # Save the 2FA secret to the user's record
            cursor = mysql.connection.cursor()
            cursor.execute('UPDATE users SET 2fa_secret = %s WHERE id = %s', (secret, user_id))
            mysql.connection.commit()

            # Generate QR code
            totp = pyotp.TOTP(secret)
            uri = totp.provisioning_uri(session['username'], issuer_name="YourApp")
            img = qrcode.make(uri)
            buf = BytesIO()
            img.save(buf)
            img_b64 = base64.b64encode(buf.getvalue()).decode()

            return render_template('enable_2fa.html', qr_code=img_b64, secret=secret)
        
        return render_template('enable_2fa.html')
    return redirect(url_for('login'))

@app.route('/flasklogin/verify_2fa_enable', methods=['POST'])
def verify_2fa_enable():
    if 'loggedin' in session:
        user_id = session['id']
        code = request.form.get('code')
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT 2fa_secret FROM users WHERE id = %s', (user_id,))
        account = cursor.fetchone()

        if account:
            totp = pyotp.TOTP(account['2fa_secret'])
            if totp.verify(code):
                cursor.execute('UPDATE users SET 2fa_enabled = TRUE WHERE id = %s', (user_id,))
                mysql.connection.commit()
                return redirect(url_for('home'))
            else:
                return "Invalid 2FA code", 400
    return redirect(url_for('login'))

@app.route('/flasklogin/disable_2fa', methods=['POST'])
def disable_2fa():
    if 'loggedin' in session:
        user_id = session['id']
        cursor = mysql.connection.cursor()
        cursor.execute('UPDATE users SET 2fa_enabled = FALSE, 2fa_secret = NULL WHERE id = %s', (user_id,))
        mysql.connection.commit()
        return redirect(url_for('home'))
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True) 