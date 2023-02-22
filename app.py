from flask import Flask, render_template, redirect, request, url_for, session
from flask_mysqldb import MySQL
import re
import secrets
import MySQLdb.cursors
from passlib.hash import sha256_crypt
from cryptography.fernet import Fernet

key = Fernet.generate_key()
crypter = Fernet(key)

app = Flask(__name__)

app.secret_key = secrets.token_hex(16)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'Anupam'
app.config['MYSQL_PASSWORD'] = '8955@Mysql'
app.config['MYSQL_DB'] = 'testlogin'

mysql = MySQL(app)


@app.route('/')
@app.route('/login', methods=['GET','POST'])
def login():
    msg=''
    if request.method =='POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s ', (username,))
        account = cursor.fetchone()
        
        
        
        if account:
            pas = account['password']
            if(sha256_crypt.verify(password,pas)):
                session['loggedin'] = True
                session['id'] = account['id']
                session['username'] = account['username']
                msg = 'Logged in successfully !'
                return render_template('index.html', msg=msg)
            
            else:
                msg = 'Incorrect username / password !'
            
        else:
            msg = 'Incorrect username / password !'
            
    return render_template('login.html', msg=msg)


@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/register', methods=['GET','POST'])
def register():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        username = request.form['username']
        password = request.form['password']
        
        encpassword = sha256_crypt.encrypt(password)
        
        email = request.form['email']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        account = cursor.fetchone()
        if account:
            msg = 'Account already exists !'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address !'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only characters and numbers !'
        elif not username or not password or not email:
            msg = 'Please fill out the form !'
        else:
            cursor.execute('INSERT INTO accounts VALUES (NULL, %s, %s, %s)', (username, encpassword, email))
            mysql.connection.commit()
            msg = 'You have successfully reigstered !'
        
    elif request.method == 'POST':
        msg = 'Please fill out the form !'
    
    return render_template('register.html', msg=msg)

if __name__=="__main__":
    app.run(debug=True)