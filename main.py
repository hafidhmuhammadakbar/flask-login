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
import numpy as np
from src import fuzzy_topsis as ft

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

    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']

        # validation input
        if not username or not password:
            msg = 'Please fill out the form!'
            flash(msg, 'danger')
            return render_template('index.html', error=msg, is_banned=is_banned)

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        account = cursor.fetchone()

        if account and bcrypt.checkpw(password.encode(), account['password'].encode()):
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            flash('Logged in successfully', 'success')
            msg = 'Logged in successfully'
            return render_template('home.html', success=msg)
        else:
            msg = 'Incorrect username or password'
            flash(msg, 'danger')

    return render_template('index.html', error=msg, is_banned=is_banned)

# Register
@app.route('/flasklogin/register', methods=['GET', 'POST'])
def register():
    msg = ''

    # Check if user is loggedin
    if 'loggedin' in session:
        return redirect(url_for('home'))

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
                flash(msg, 'success')
                return render_template('index.html', success=msg)

    elif request.method == 'POST':
        msg = 'Please fill out the form!'
        flash(msg, 'danger')

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

@app.route('/fuzzy', methods=['GET'])
def fuzzy():
    if 'loggedin' in session:
        return render_template('fuzzy.html')
    return redirect(url_for('login'))

@app.route('/fuzzy_post', methods=['POST'])
def fuzzy_post():
    if 'loggedin' in session:
        # Log the entire form data for debugging
        app.logger.info(request.form)

        # Determine the number of decision makers based on submitted data
        num_dm = 0
        criteria_name_length = len(ft.name_criteria())
        
        for key, value in request.form.items():
            if key.startswith('decisionMaker') and key.endswith('Criteria1'):
                num_dm += 1
        
        # print(f"Number of decision makers: {num_dm}")

        if num_dm <= 0:
            return "Error: Invalid number of decision makers submitted", 400

        dm_criteria_input = np.zeros((num_dm, criteria_name_length))

        for i in range(num_dm):
            for j in range(criteria_name_length):
                dm_criteria_input[i][j] = int(request.form.get(f'decisionMaker{i+1}Criteria{j+1}', 0))

        # Load the data
        data = ft.load_variable()

        # Get the normalized matrix
        normalized_matrix = ft.get_normalize(data)

        # build the decision maker criteria
        dm_criteria = ft.build_dm_criteria(dm_criteria_input, num_dm)

        # build the aggregate decision maker criteria
        aggregated_criteria = ft.build_aggregate_dm_criteria(dm_criteria)

        # get the weighted normalized matrix
        weighted_normalized_matriks = ft.weighted_normalized_matrix(normalized_matrix, aggregated_criteria)

        # get the fpis and fnis
        fpis, fnis = ft.get_fpis_fnis(weighted_normalized_matriks, ft.variable_info())

        # get the distance from fpis and fnis
        distance_fpis, distance_fnis = ft.get_distance_from_fpis_fnis(weighted_normalized_matriks, fpis, fnis)

        # get the closest distance
        closest_distances = ft.get_closest_distance(distance_fpis, distance_fnis)

        # load the name alternatives
        name_alternatives = ft.name_alternatives()

        # load the name of criteria
        name_criterias = ft.name_criteria()

        # sort the alternatives based on the closest distance
        sorted_alternatives = sorted(range(len(closest_distances)), key=lambda k: closest_distances[k], reverse=True)

        return render_template('result-fuzzy.html', closest_distances=closest_distances, sorted_alternatives=sorted_alternatives, 
                            name_alternatives=name_alternatives, name_criterias=name_criterias, initial_matrix=data,
                            normalized_matrix=normalized_matrix, num_dm=num_dm, dm_initial_criteria=dm_criteria,
                            aggregated_criteria=aggregated_criteria, weighted_normalized_matriks=weighted_normalized_matriks,
                            fpis=fpis, fnis=fnis, distance_fpis=distance_fpis, distance_fnis=distance_fnis)
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)