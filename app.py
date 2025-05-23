from flask import Flask, render_template, request, redirect, url_for, session, flash
import pymysql
import bcrypt
import re
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key')

# MySQL configurations
db_config = {
    'host': os.getenv('MYSQL_HOST'),
    'port': int(os.getenv('MYSQL_PORT', 3306)),
    'user': os.getenv('MYSQL_USER'),
    'password': os.getenv('MYSQL_PASSWORD'),
    'database': os.getenv('MYSQL_DB'),
    'cursorclass': pymysql.cursors.DictCursor,
    'ssl': {'ca': os.getenv('MYSQL_SSL_CA', 'aiven-ca.pem')}
}

def get_db_connection():
    try:
        conn = pymysql.connect(**db_config)
        return conn
    except Exception as e:
        print(f"Database connection failed: {e}")
        return None

@app.route('/')
def home():
    if 'loggedin' in session:
        return render_template('profile.html', username=session['username'])
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        email = request.form['email']
        
        # Input validation
        if not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only letters and numbers!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
        # Enhanced password validation: at least 6 chars, 1 uppercase, 1 lowercase, 1 digit, 1 special char
        elif not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$', password.decode('utf-8')):
            msg = 'Password must be at least 6 characters long and include at least one uppercase letter, one lowercase letter, one digit, and one special character (@$!%*?&)!'
        else:
            conn = get_db_connection()
            if conn is None:
                msg = 'Database connection failed!'
                return render_template('register.html', msg=msg)
            
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
            account = cursor.fetchone()
            
            if account:
                msg = 'Account already exists!'
            else:
                hashed = bcrypt.hashpw(password, bcrypt.gensalt()).decode('utf-8')
                cursor.execute('INSERT INTO users (username, password, email) VALUES (%s, %s, %s)', (username, hashed, email))
                conn.commit()
                flash('You have successfully registered!', 'success')
                cursor.close()
                conn.close()
                return redirect(url_for('login'))
            
            cursor.close()
            conn.close()
    
    return render_template('register.html', msg=msg)

@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        
        conn = get_db_connection()
        if conn is None:
            msg = 'Database connection failed!'
            return render_template('login.html', msg=msg)
        
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if user and bcrypt.checkpw(password, user['password'].encode('utf-8')):
            session['loggedin'] = True
            session['username'] = user['username']
            flash('Logged in successfully!', 'success')
            return redirect(url_for('home'))
        else:
            msg = 'Incorrect username or password!'
    
    return render_template('login.html', msg=msg)

@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('username', None)
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    port = int(os.getenv('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=True)