from flask import Flask, render_template, request, redirect, url_for, flash
import re
import bcrypt


app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

# create a dictionary to store registered users
users = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        if email in users:
            if bcrypt.checkpw(password.encode('utf-8'), users[email]['password']):
                flash('You have been logged in successfully')
                return redirect(url_for('dashboard'))
            else:
                flash('Incorrect email or password')
                return redirect(url_for('login'))
        else:
            flash('You are not registered. Please register first')
            return redirect(url_for('register'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        subcounty = request.form['subcounty']
        phone_number = request.form['phone_number']
        
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash('Invalid email address')
            return redirect(url_for('register'))
        elif len(password) < 8 or len(password) > 10:
            flash('Password must be between 8 and 10 characters')
            return redirect(url_for('register'))
        elif not any(char.isdigit() for char in password) or not any(char in '!@#$%^&*()' for char in password):
            flash('Password must contain at least one digit and one special character')
            return redirect(url_for('register'))
        elif password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('register'))
        elif subcounty not in ('Dagoretti', 'Embakasi central', 'Embakasi East', 'Embakasi North','Embakasi South', 'Embakasi West', 'Kamukunji', 'Kasarani','Kibra', 'Langata', 'Makadara', 'Mathare', 'Roysambu', 'Ruaraka','Starehe', 'Westlands'):
            flash('Invalid subcounty')
            return redirect(url_for('register'))
        elif not re.match(r'^07\d{8}$', phone_number):
            flash('Invalid phone number')
            return redirect(url_for('register'))
        else:
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            users[email] = {'password': hashed_password, 'subcounty': subcounty, 'phone_number': phone_number}
            flash('You have been registered successfully. Please login')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    return 'Welcome to the dashboard'

if __name__ == '__main__':
    app.run(debug=False)
    #app.run(debug=bool(os.environ.get('DEBUG', False)))

