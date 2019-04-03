from flask import Flask, render_template, flash, redirect, url_for, session, logging, request
from data import Articles
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps
import IPython

app = Flask(__name__)

# config MySQL

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'qdel'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

# init MySQL

mysql = MySQL(app)

Articles = Articles() 

@app.route('/')
def index():
	return render_template('home.html')

@app.route('/about')
def about():
	return render_template('about.html')

@app.route('/faq')
def faqs():
	return render_template('articles.html', articles = Articles)

@app.route('/article/<string:id>/')
def article(id):
	return render_template('article.html', id = id)

class RegisterForm(Form):
	name = StringField('Name', [validators.Length(min = 1, max = 50)])
	username = StringField('Username', [validators.Length(min = 4, max = 25)])
	email = StringField('Email', [validators.Length(min = 6, max = 50)])
	password = PasswordField('Password', [
		validators.InputRequired(),
		validators.EqualTo('confirm', message = 'Passwords do not match.')
	
	])
	confirm = PasswordField('Confirm Password')

@app.route('/register', methods = ['GET', 'POST'])
def register(): 
	form = RegisterForm(request.form)
	if request.method == 'POST' and form.validate():
		name = form.name.data
		email = form.email.data
		username = form.username.data
		password = sha256_crypt.encrypt(str(form.password.data))
		
		#create cursor 
		cur = mysql.connection.cursor()

		#execute query
		cur.execute("INSERT INTO users(name,email,username,password) VALUES(%s, %s, %s, %s )",(name,email,username,password))

		#commit to db
		mysql.connection.commit()

		#close connection
		cur.close()

		flash('Thank You!. You are now registered with QDeL Software.', 'success') 
		return redirect(url_for('login'))

		return render_template('register.html', form = form)
	return render_template('register.html', form = form)

#User Login
@app.route('/login', methods = ['GET', 'POST'])
def login():
	if request.method == 'POST':
		#Get form field
		username = request.form['username']
		password_candidate = request.form['password']


		#create cursor
		cur = mysql.connection.cursor()


		#get user by username 
		result = cur.execute('SELECT * FROM users WHERE username = %s', [username])
		if result > 0:
			
			# Get Stored hash
			data = cur.fetchone()
			password = data['password']


			#compare passwords
			if sha256_crypt.verify(password_candidate, password):
				app.logger.info('PASSWORD MATCHED')
				#Passed
				session['logged_in'] = True
				session['username'] = username
				flash('You are now logged in.','success')
				return redirect(url_for('dashboard'))
			else:
				error = 'Invalid login.'
				return render_template('login.html', error = error)
			#close connection
			cur.close()
		else:
			error = 'Username not found.'
			return render_template('login.html', error = error)



	return render_template('login.html')

#check if user logged in
def is_logged_in(f):
	@wraps(f)
	def wrap(*args,**kwargs):
		if 'logged_in' in session:
			return f(*args,**kwargs)
		else:
			flash('Unauthorized Access! Please Login.', 'danger')
			return redirect(url_for('login'))
	return wrap

#logout
@app.route('/logout')
def logout():
	session.clear()
	flash('You are now logged out.', 'success')
	return redirect(url_for('login'))

@app.route('/dashboard')
@is_logged_in
def dashboard():
	return render_template('dashboard.html')

# IPython.embed()

if __name__ == '__main__':
	app.secret_key = 'secret123'
	app.run(debug = True)