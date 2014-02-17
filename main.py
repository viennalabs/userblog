import os
import webapp2
import jinja2

from google.appengine.ext import ndb
from google.appengine.api import memcache

import json

import logging

import utils

# --- TEMPLATES ---
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
JINJA_ENVIRONMENT = jinja2.Environment(
	loader=jinja2.FileSystemLoader(template_dir),
	extensions=['jinja2.ext.autoescape'],
	autoescape=True)

class TemplateHandler(utils.MainHandler):
	def template(self, template, **params): 
		params['user'] = self.user # pass self.user into every template
		return self.response.write(JINJA_ENVIRONMENT.get_template(template).render(**params))

	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('user_id')
		if uid:
			logging.error("ID FROM COOKIE: " + str(uid))
		self.user = uid and User.get_by_id(int(uid), parent=user_key()) # None or User entity
		if self.user:
			logging.error("AUTHENTICATED USER, self.user has been set.")
		elif uid:
			logging.error("VALID COOKIE FOUND BUT ID NOT IN DATASTORE!")

# -- MODELS ---
class User(ndb.Model):
	username = ndb.StringProperty(required=True)
	pw_hash = ndb.StringProperty(required=True) # ',' delimited string of salt and hash
	email = ndb.StringProperty(required=True)
	created = ndb.DateTimeProperty(auto_now_add=True)
	logged_in = ndb.BooleanProperty(default=True)
	#verified_email = ndb.BooleanProperty(default=False) --> usergroups
	#admin = ndb.BooleanProperty(default=False) --> usergroups
	#dead = ndb.BooleanProperty(default=False) --> usergroups

def user_key(usergroup='default'):
	return ndb.Key('UserGroups', usergroup)

class Post(ndb.Model):
	author = ndb.StringProperty()
	subject = ndb.StringProperty(required = True)
	content = ndb.TextProperty(required = True) # TextProperty is never indexed
	created = ndb.DateTimeProperty(auto_now_add = True)
	last_modified = ndb.DateTimeProperty(auto_now = True)
	last_modified_by = ndb.StringProperty()
	slug = ndb.StringProperty()

	def render_post(self): # gets called from templates to render posts.
		return JINJA_ENVIRONMENT.get_template('post.html').render(p=self)

def blog_key(blog_name='default'):
	return ndb.Key('Blogs', blog_name)

# --- USER HANDLERS ---
class Signup(TemplateHandler):
	def get(self):
		self.template('signup.html')

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')
		verify = self.request.get('verify')
		email = self.request.get('email')

		error = utils.validation(username, password, verify, email)
		if error:	
			self.template('signup.html', other_error=error, username=username, email=email)
		else:
			if User.query(User.username==username).get():
				error = "Sorry, this username already exists"
				self.template('signup.html', other_error=error, username=username, email=email)
			else:
				h = utils.make_pw_hash(username, password)
				u = User(parent=user_key(), username=username, pw_hash=h, email=email)
				new_user_id = u.put().id() # put() returns the models Key, put().id() returns the entities id
				self.set_secure_cookie('user_id', str(new_user_id))
				logging.error("NEW USER WITH ID " + str(new_user_id) + " CREATED")
				self.redirect('/user/%s' % username)

class UserHome(TemplateHandler):
	def get(self, username):
		if self.user and username == self.user.username:
			self.template('userhome.html') # we do not need to pass in self.user because we've already passed it into every template!

		else:
			self.redirect('/login')

class Login(TemplateHandler):
	def get(self):
		if self.user:
			self.redirect("/user/%s" % self.user.username)		
		self.template('login.html')

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')

		u = User.query(User.username == username).get()

		if u and utils.valid_pw(username, password, u.pw_hash):
			user_id = u.key.id()
			self.set_secure_cookie('user_id', str(user_id))
			self.redirect('/user/%s' % username)
		else:
			error = "Invalid login."
			self.template('login.html', username=username, other_error=error)

class Logout(TemplateHandler):
	def get(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
		self.redirect('/')

# --- BLOG HANDLERS---

class Blog(TemplateHandler):
	def get(self):
		posts = blog_query() # hit cache or db
		self.template('blog.html', posts=posts)

class NewPost(TemplateHandler):
	def get(self):
		if self.user: 
			self.template('newpost.html')
		else:
			self.redirect('/login')

	def post(self):
		subject = self.request.get('subject')
		content = self.request.get('content')
		slug = subject.replace(" ", "-")

		if subject and content and slug:
			p = Post(parent=blog_key(), subject=subject, content=content, slug=slug)
			new_post_id = p.put().id()
			blog_query(update=True) # update Memcache
			self.redirect('/post/%s' % slug)
		else:
			error = "Subject and Content please"
			self.template('newpost.html', error=error, subject=subject, content=content)


class Permalink(TemplateHandler):
	def get(self, slug):
		post = post_query(slug)
		if post:
			self.template('permalink.html', post=post)
		else:
			self.redirect('/')
		

# --- MEMCACHE ---

def post_query(slug):
	post_key = "POST_%s" % slug
	post = memcache.get(post_key)

	if post is None:
		logging.error("DB HIT!")
		post = Post.query(Post.slug == slug).get()
		if not post:
			return None
		logging.error("NEW POST WITH SLUG " + slug + " ADDED TO MEMCACHE.")
		memcache.add(post_key, post)
	return post

def blog_query(update=False):
	mc_key = 'POSTS'
	posts = memcache.get(mc_key)

	if posts is None or update:
		logging.error("DB HIT!")
		posts = Post.query(ancestor=blog_key()).order(-Post.created).fetch(5)
		memcache.add(mc_key, posts)
	return posts

# --- JSON ----

class BlogJSON(TemplateHandler):
	def get(self):
		# read out of Memcached!
		pass

class PermalinkJSON(TemplateHandler):
	def get(self):
		# read out of Memcached!
		pass

# --- ROUTING ---
application = webapp2.WSGIApplication([
	('/signup', Signup),
	('/user/([\S]+)', UserHome),
	('/login', Login),
	('/logout', Logout),
	('/', Blog),
	('/newpost', NewPost),
	('/post/([\S]+)', Permalink),
	('/.json', BlogJSON),
	('/post/([\S]+)/.json', PermalinkJSON),
], debug=True)
