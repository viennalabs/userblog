import hashlib
import hmac
import re
import random
import string
from time import sleep
import logging

SECRET = 'xJjNGWl69hJRp8Pv7eq5l2F0Jh5e'

from webapp2 import RequestHandler

# --- REQUESTHANDLER DEPENDENCIES ---
# note that these can be called as self.func() from any Requesthandler
class MainHandler(RequestHandler): 
	def set_secure_cookie(self, name, val): # name is name of the cookie!!! val is the value to be stored!!!
		cookie_val = make_secure_val(val)
		self.response.headers.add_header(
			'Set-Cookie',
			'%s=%s; Path=/' % (name, cookie_val))

	def read_secure_cookie(self, name): # returns the cookie value or None
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

# --- COOKIE ---
def hash_str(s):
	return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s): # takes the data to be stored in the cookie and returns it with it's salted HMAC
	return "%s|%s" % (s, hash_str(s))

def check_secure_val(h): # takes the cookie contents, checks and returns the unhashed data
	val = h.split('|')[0]
	if h == make_secure_val(val):
		return val

# --- PASSWORD --- # for ndb User.pw_hash
def make_salt(length = 5): 
	return ''.join(random.choice(string.letters) for x in xrange(length))

def make_pw_hash(name, pw, salt=None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s,%s' % (salt, h)

def valid_pw(name, password, h): # checks login input (pass in ndb pw_hash as h)
	salt = h.split(',')[0] # get the salt out of the ndb
	return h == make_pw_hash(name, password, salt)

# --- FORM VALIDATION ---
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
	return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):
	return not email or EMAIL_RE.match(email)

def validation(username, password, verify, email): # needs to take **kw, but can't figure that out now
	if not valid_username(username):
		return 'Username must be between 3 and 20 characters.'
	if not valid_password(password):
		return 'Password must be between 3 and 20 characters.'
	if password != verify:
		return 'Passwords don\'t match.'
	if not valid_email(email):
		return 'That doesn\'t look like a valid Email address.'









