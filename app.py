from flask import Flask, render_template, request, redirect, url_for, session
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.secret_key = 'rahasia_kita_aja'
bcrypt = Bcrypt(app)

# Simulasi penyimpanan user (saat ini hanya email dan password)
users = {
    'user@example.com': bcrypt.generate_password_hash('password123').decode('utf-8')
}

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if email in users and bcrypt.check_password_hash(users[email], password):
            session['user'] = email
            return redirect(url_for('dashboard'))
        else:
            error = 'Email atau password salah!'
    return render_template('login.html', error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm = request.form['confirm']

        if email in users:
            error = 'Email sudah terdaftar!'
        elif password != confirm:
            error = 'Password tidak cocok!'
        else:
            hashed = bcrypt.generate_password_hash(password).decode('utf-8')
            users[email] = hashed
            session['user'] = email
            return redirect(url_for('dashboard'))
    return render_template('register.html', error=error)

@app.route('/dashboard')
def dashboard():
    if 'user' in session:
        return render_template('dashboard.html', user=session['user'])
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
