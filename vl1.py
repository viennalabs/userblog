import os
import webapp2
import jinja2
SECRET = 'xJjNGWl69hJRp8Pv7eq5l2F0Jh5e'
import hashlib
import hmac
import re
import random
import string
from time import sleep
from google.appengine.ext import ndb

# TEMPLATE STUFF
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
JINJA_ENVIRONMENT = jinja2.Environment(
	loader=jinja2.FileSystemLoader(template_dir),
	extensions=['jinja2.ext.autoescape'],
	autoescape=True)


# USER STUFF
def hash_str(s):
	return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s): # takes the data to be stored in the cookie and returns it with it's salted hash
	return "%s|%s" % (s, hash_str(s))

def check_secure_val(h): # takes the cookie contents, checks and returns the unhashed data
	val = h.split('|')[0]
	if h == make_secure_val(val):
		return val

def make_salt(length = 5):
	return ''.join(random.choice(string.letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
	salt = h.split(',')[0]
	return h == make_pw_hash(name, password, salt)

class User(ndb.Model):
	username = ndb.StringProperty(required=True)
	pw_hash = ndb.StringProperty(required=True)
	email = ndb.StringProperty(required=True)
	created = ndb.DateTimeProperty(auto_now_add=True)
	logged_in = ndb.BooleanProperty(default=True)
	verified_email = ndb.BooleanProperty(default=False)
	admin = ndb.BooleanProperty(default=False)
	dead = ndb.BooleanProperty(default=False)

# BLOG STUFF
class Post(ndb.Model):
	author = ndb.StringProperty()
	subject = ndb.StringProperty(required = True)
	content = ndb.TextProperty(required = True)
	created = ndb.DateTimeProperty(auto_now_add = True)
	last_modified = ndb.DateTimeProperty(auto_now = True)
	last_modified_by = ndb.StringProperty()
	slug = ndb.TextProperty()

# URI HANDLERS
class MainHandler(webapp2.RequestHandler): # this is run with EVERY page request
	def template(self, template, **params): # get, write and render template
		return self.response.write(JINJA_ENVIRONMENT.get_template(template).render(**params))

	def set_secure_cookie(self, name, val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header(
			'Set-Cookie',
			'%s=%s; Path=/' % (name, cookie_val))

	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	def login(self, user): # call this to log in a user
		self.set_secure_cookie('user_id', str(user.key().id()))

	def logout(self): # call this to log out a user
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

	def initialize(self, *a, **kw): # runs automatically in GAE. 
		# self.user is True if User has valid cookie and exists in datastore
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('user_id')
		self.user = uid and User.get_by_id(int(uid)) 

class Frontpage(MainHandler):
	def get(self):
		self.template('home.html')

class Signup(MainHandler):
	def get(self):
		self.template('signup.html')

	def post(self):
		have_error = False
		self.username = self.request.get('username')
		self.password = self.request.get('password')
		self.verify = self.request.get('verify')
		self.email = self.request.get('email')

		params = dict(username = self.username,
						email = self.email)

		if not valid_username(self.username):
			params['username_error'] = "Invalid Username"
			have_error = True
		if not valid_password(self.password):
			params['password_error'] = "Invalid Password"
			have_error = True
		elif self.password != self.verify:
			params['verify_error'] = "Passwords don't match."
			have_error = True
		if not valid_email(self.email):
			params['email_error'] = "Invalid Email."
			have_error = True

		if have_error:
			self.template('signup.html', **params)
		else:
			self.template('signup.html', other_error="Not implemented yet. Userdata has not been stored.")

class UserHome(MainHandler):
	def get(self):	
		if self.read_secure_cookie('user_id'):
			# get user id out of cookie, load associated userdata, pass it into template
			# ...
			self.template('userhome.html')
		else:
			self.redirect('/login')

class Login(MainHandler):
	def get(self):
		self.template('login.html')

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')

		self.template('login.html', other_error="Not implemented yet.")

class Blog(MainHandler):
	def get(self):
		self.template('blog.html')

class Board(MainHandler):
	def get(self):
		self.template('board.html')

# Validation Regex
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
	return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):
	return not email or EMAIL_RE.match(email)

application = webapp2.WSGIApplication([
	('/', Frontpage),
	('/signup', Signup),
	('/userhome', UserHome),
	('/login', Login),
	('/blog', Blog),
	('/board', Board),
], debug=True)
