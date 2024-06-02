from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re
import bcrypt
import pyotp
import qrcode
from io import BytesIO
import base64
import requests
from werkzeug.utils import secure_filename
import os
import uuid
from datetime import datetime, timedelta, timezone

app = Flask(__name__)

app.secret_key = 'loginpython'

# Enter your database connection details below
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'pythonlogin'

# image upload
app.config['UPLOAD_FOLDER'] = 'static/uploads/'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

# Initialize MySQL
mysql = MySQL(app)

# Redirect / to /flasklogin
@app.route('/')
def index():
    return redirect(url_for('login'))

# Login
@app.route('/flasklogin/', methods=['GET', 'POST'])
def login():
    msg = ''
    is_banned = False

    if 'login_attempts' not in session:
        session['login_attempts'] = 0
        session['last_attempt_time'] = datetime.min.replace(tzinfo=timezone.utc)

    current_time = datetime.now(timezone(timedelta(hours=7)))
    ban_time = session.get('ban_time', None)

    # Check if the user was banned but the ban period is over
    if ban_time and current_time >= ban_time:
        session['login_attempts'] = 0
        session.pop('ban_time', None)
    elif ban_time and current_time < ban_time:
        is_banned = True
        time_left = (ban_time - current_time).seconds
        msg = f'Too many failed login attempts. Please try again in {time_left} seconds.'

    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']

        # validation input
        if not username or not password:
            msg = 'Please fill out the form!'
            return render_template('index.html', error=msg, is_banned=is_banned)

        # Verify reCAPTCHA if the user has failed more than 3 times
        if session['login_attempts'] >= 3:
            recaptcha_response = request.form.get('g-recaptcha-response')
            if not recaptcha_response:
                msg = 'Please complete the reCAPTCHA'
                return render_template('index.html', error=msg, is_banned=is_banned)

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
                return render_template('index.html', error=msg, is_banned=is_banned)

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        account = cursor.fetchone()

        if account and bcrypt.checkpw(password.encode(), account['password'].encode()):
            session['login_attempts'] = 0  # Reset login attempts on successful login
            session.pop('ban_time', None)  # Remove ban time if it exists
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
            session['last_attempt_time'] = current_time
            if session['login_attempts'] > 10:
                session['ban_time'] = current_time + timedelta(minutes=2)
                msg = 'Too many failed login attempts. You are banned for 2 minutes.'
                is_banned = True
            else:
                # Check if username exists
                cursor.execute('SELECT COUNT(*) FROM users WHERE username = %s', (username,))
                count = cursor.fetchone()['COUNT(*)']
                if count == 0:
                    msg = 'This username is not registered'
                else:
                    msg = 'Incorrect username or password'

    return render_template('index.html', error=msg, is_banned=is_banned)


# Register
@app.route('/flasklogin/register', methods=['GET', 'POST'])
def register():
    msg = ''

    # Check if user is loggedin
    if 'loggedin' in session:
        return redirect(url_for('home'))
    
    # check if user get ban
    if 'login_attempts' in session:
        if session['login_attempts'] > 10:
            return redirect(url_for('login'))
    

    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        name = request.form['name']
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        account = cursor.fetchone()

        if account:
            msg = 'Username already exists!'
        else:
            cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
            account = cursor.fetchone()

            if account:
                msg = 'Email already exists!'
            elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
                msg = 'Invalid email address!'
            elif not re.match(r'[A-Za-z0-9]+', username):
                msg = 'Username must contain only characters and numbers!'
            elif len(username) < 4:
                msg = 'Username must be at least 4 characters long!'
            elif len(password) < 8:
                msg = 'Password must be at least 8 characters long!'
            elif not username or not password or not email:
                msg = 'Please fill out the form!'
            else:
                hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
                cursor.execute('INSERT INTO users (name, username, password, email) VALUES (%s, %s, %s, %s)', (name, username, hashed_password, email,))
                mysql.connection.commit()
                msg = 'You have successfully registered!'
                return render_template('index.html', success=msg)

    elif request.method == 'POST':
        msg = 'Please fill out the form!'

    return render_template('register.html', error=msg)

# Logout
@app.route('/flasklogin/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    return redirect(url_for('login'))

# Home
@app.route('/flasklogin/home')
def home():
    if 'loggedin' in session:
        user_id = session['id']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT 2fa_enabled FROM users WHERE id = %s', (user_id,))
        account = cursor.fetchone()
        
        is_2fa_enabled = account['2fa_enabled'] if account else False
        
        return render_template('home.html', username=session['username'], is_2fa_enabled=is_2fa_enabled)
    
    return redirect(url_for('login'))

# Profile
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/flasklogin/profile')
def profile():
    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE id = %s', (session['id'],))
        account = cursor.fetchone()
        return render_template('profile.html', account=account)
    return redirect(url_for('login'))

@app.route('/flasklogin/profile/edit', methods=['GET', 'POST'])
def edit_profile():
    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE id = %s', (session['id'],))
        account = cursor.fetchone()

        if request.method == 'POST':
            name = request.form['name']
            username = request.form['username']
            email = request.form['email']
            profile_image = request.files['profile_image']

            # check if username or email already exists
            cursor.execute('SELECT * FROM users WHERE (username = %s OR email = %s) AND id != %s', (username, email, session['id']))
            account = cursor.fetchone()
            if account:
                flash('Username or email already exists!', 'error')
                return redirect(url_for('edit_profile'))
            
            # validation input
            if not re.match(r'[A-Za-z0-9]+', username):
                flash('Username must contain only characters and numbers!', 'error')
                return redirect(url_for('edit_profile'))
            elif len(username) < 4:
                flash('Username must be at least 4 characters long!', 'error')
                return redirect(url_for('edit_profile'))
            elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
                flash('Invalid email address!', 'error')
                return redirect(url_for('edit_profile'))
            elif len(profile_image.filename) > 0 and not allowed_file(profile_image.filename):
                flash('Invalid file type! Only PNG, JPG, and JPEG files are allowed.', 'error')
                return redirect(url_for('edit_profile'))

            if profile_image and allowed_file(profile_image.filename):
                # Check the file size
                if len(profile_image.read()) > 5 * 1024 * 1024:  # 5 MB limit
                    flash('File size must be under 5 MB.', 'error')
                    return redirect(url_for('edit_profile'))
                profile_image.seek(0)  # Reset file pointer after size check

                # Generate a random filename
                ext = profile_image.filename.rsplit('.', 1)[1].lower()
                filename = f"{uuid.uuid4().hex}.{ext}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

                # Save the new profile image
                profile_image.save(file_path)
                
                cursor.execute('SELECT * FROM users WHERE id = %s', (session['id'],))
                account = cursor.fetchone()
                # Delete the old profile image if it exists
                old_image = account.get('profile_image')
                if old_image:
                    old_image_path = os.path.join(app.root_path, 'static', old_image.replace('/', os.sep))
                    if os.path.exists(old_image_path):
                        os.remove(old_image_path)

                # Update the database with the new image relative path
                image_url = os.path.join('uploads', filename).replace(os.sep, '/')
                cursor.execute('UPDATE users SET name = %s, username = %s, email = %s, profile_image = %s WHERE id = %s', 
                            (name, username, email, image_url, session['id']))
            else:
                cursor.execute('UPDATE users SET name = %s, username = %s, email = %s WHERE id = %s', 
                            (name, username, email, session['id']))
            mysql.connection.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('profile'))

        return render_template('edit_profile.html', account=account)
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
                return render_template('2fa.html', error='Invalid 2FA code')
    return redirect(url_for('login'))

@app.route('/flasklogin/enable_2fa', methods=['GET', 'POST'])
def enable_2fa():
    if 'loggedin' in session:
        if request.method == 'POST':
            user_id = session['id']
            secret = pyotp.random_base32()
            
            cursor = mysql.connection.cursor()
            cursor.execute('UPDATE users SET 2fa_secret = %s WHERE id = %s', (secret, user_id))
            mysql.connection.commit()

            totp = pyotp.TOTP(secret)
            uri = totp.provisioning_uri(session['username'], issuer_name="Login-Auth-JMPL")
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
                secret = pyotp.random_base32()
                uri = totp.provisioning_uri(session['username'], issuer_name="YourApp")
                img = qrcode.make(uri)
                buf = BytesIO()
                img.save(buf)
                img_b64 = base64.b64encode(buf.getvalue()).decode()
                return render_template('enable_2fa.html', qr_code=img_b64, secret=secret, error='Invalid 2FA code')
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
    app.run(host="0.0.0.0", debug=True)