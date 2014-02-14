# Work in progress. Don't use.
 
* User registration/authentication using cookies and ndb datastore. Users can sign up, receive a salted cookie and are added to the datastore. If they supplied an email, they are sent a verification link. An admins can post on the blog. /userhome shows all info we have on the user.
---
* /blog displays the 5 most recent entries, /blog(\d) displays older entries. /blog/newpost is accessible only with a valid cookie, posts are written in HTML. /blog/slug is a permalink to each post. Json available at /blog/.json and /blog/slug/.json.
---
* Board. /board/ascii lets you enter text and displays it below. /board/img uses Imgur API to allow users to post images. Uses ndb ancestry for different boards. 
---
Copyright 2014 by Viennalabs 
