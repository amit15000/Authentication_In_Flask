from flask import Flask, render_template, request, session, redirect
import mysql.connector
import os
import bcrypt

connection = mysql.connector.connect(
    host='localhost',
    database='law',
    user='root',
    password='root'
)

cursor = connection.cursor()
app = Flask(__name__)
app.secret_key = os.urandom(24)


@app.route('/')
def login():
    if 'user_id' in session:
        return redirect('/home')
    else:
        return render_template("login.html")


@app.route('/register')
def register():
    return render_template("register.html")


@app.route('/home')
def home():
    if 'user_id' in session:
        return render_template('home.html')
    else:
        return redirect('/')


@app.route('/login_validation', methods=['POST'])
def login_validation():
    msg = ''
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        cursor.execute('SELECT * FROM users WHERE email=%s', (email,))
        user = cursor.fetchone()    
        if user and bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):
            session['user_id'] = user[0]
            return redirect('/home')
        else:
            msg = 'Incorrect username or password. Try again!'
    return redirect('/')


@app.route('/signup', methods=['POST'])
def signup():
    if request.method == 'POST':
        # Extract registration form data
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Perform registration logic (insert new user into the database)
        # Add your SQL insert statement here
        cursor.execute('INSERT INTO users (username, email, password) VALUES (%s, %s, %s)',
                       (username, email, hashed_password))

        # Commit the changes to the database
        connection.commit()

        cursor.execute('SELECT * FROM users WHERE email=%s', (email,))
        myuser = cursor.fetchone()
        session['user_id'] = myuser[0]

        msg = 'Registration successful! Please log in.'
        return redirect('/home')

    return redirect('/register')  # Assuming you have a 'register.html' template for the registration form


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


if __name__ == '__main__':
    app.run(debug=True)
