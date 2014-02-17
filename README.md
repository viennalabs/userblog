* User registration/authentication using cookies and ndb. Users can sign up, receive a salted cookie and are added to the datastore with their password hashed. If they supplied an email, they are sent a verification link. An registered user can post on the blog.
---
* /blog displays most recent posts from Memcache, older posts are read from ndb. /blog/subject is a permalink to that post. /newpost is accessible only with a valid cookie, posts are written in Markup. Json available at /.json and /blog/slug/.json.
---
Copyright 2014 by Viennalabs 
