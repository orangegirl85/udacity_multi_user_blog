import re
import random
import hashlib
import hmac
from string import letters

import webapp2

from google.appengine.ext import db
from models import Post, User, Comment
import helper


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)

def comment_key(name='default'):
    return db.Key.from_path('comment', name)


class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return helper.render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = helper.make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and helper.check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


class MainPage(BlogHandler):
    def get(self):
        self.write('Hello, Udacity!')


class BlogFront(BlogHandler):
    def get(self):
        posts = db.GqlQuery("select * from Post order by created desc limit 10")
        self.render('front.html', posts=posts)


def check_user_is_logged_in(func):
    def inner(*args, **kwargs):
        self = args[0]
        if not self.user:
            posts = db.GqlQuery("select * from Post order by created desc limit 10")
            self.render('front.html', posts=posts, error_message='Please login')
            return
        return func(*args, **kwargs)
    return inner


def check_post(func):
    def inner(*args, **kwargs):
        self = args[0]
        post_id = args[1]
        post = get_post(post_id)

        if not post:
            self.error(404)
            return
        return func(*args, **kwargs)
    return inner


def check_user_has_permission(func):
    def inner(*args, **kwargs):
        self = args[0]
        post_id = args[1]
        post = get_post(post_id)

        if post.user != self.user.key().id():
            self.render("newpost.html", error_message='not allowed to edit post')
            return

        return func(*args, **kwargs)
    return inner




def get_post(post_id):
    key = db.Key.from_path('Post', int(post_id), parent=blog_key())
    return db.get(key)

class PostPage(BlogHandler):
    @check_post
    @check_user_is_logged_in
    def get(self, post_id):
        post = get_post(post_id)

        self.render("permalink.html", post=post)

class EditPost(BlogHandler):


    @check_user_is_logged_in
    @check_post
    @check_user_has_permission
    def get(self, post_id):
        post = get_post(post_id)

        # if post.user != self.user.key().id():
        #     self.render("newpost.html", error_message='not allowed to edit post')
        #     return

        self.render("newpost.html", subject=post.subject, content=post.content)

    def post(self, post_id):
        post = get_post(post_id)

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            post.subject = subject
            post.content = content
            post.put()
            self.redirect('/blog/%s' % str(post.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)


class DeletePost(BlogHandler):
    @check_user_is_logged_in
    @check_post
    def get(self, post_id):
        post = get_post(post_id)

        if post.user != self.user.key().id():
            self.render("deletepost.html", error_message='not allowed to delete post')
            return

        self.render("deletepost.html", p=post)

    def post(self, post_id):
        post = get_post(post_id)

        post.delete()
        self.redirect('/blog')


class LikePost(BlogHandler):
    @check_user_is_logged_in
    @check_post
    def post(self, post_id):
        post = get_post(post_id)

        post.likes +=1
        post.put()
        self.redirect('/blog')



class NewPost(BlogHandler):
    @check_user_is_logged_in
    def get(self):
        self.render("newpost.html")

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent=blog_key(), subject=subject, content=content, user=self.user.key().id())
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)


class NewComment(BlogHandler):
    @check_user_is_logged_in
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("newcomment.html", p=post )

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return
        content = self.request.get('content')

        if content:
            c = Comment(parent=key, content=content)
            c.put()
            self.redirect('/blog' )
        else:
            error = "content, please!"
            self.render("newcomment.html", content=content, error=error)


class EditComment(BlogHandler):
    @check_user_is_logged_in
    def get(self, post_id, comment_id):
        keyBlog = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(keyBlog)

        if not post:
            self.error(404)
            return
        keyComment = db.Key.from_path('Comment', int(comment_id), parent=keyBlog)
        comment = db.get(keyComment)
        if not comment:
            self.error(404)
            return

        self.render("newcomment.html", p=post, content=comment.content)

    def post(self, post_id, comment_id):
        keyBlog = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(keyBlog)

        if not post:
            self.error(404)
            return

        keyComment = db.Key.from_path('Comment', int(comment_id), parent=keyBlog)
        comment = db.get(keyComment)
        if not comment:
            self.error(404)
            return

        content = self.request.get('content')

        if content:
            comment.content = content
            comment.put()
            self.redirect('/blog')
        else:
            error = " content, please!"
            self.render("newcomment.html", p=post, content=content, error=error)


class DeleteComment(BlogHandler):
    @check_user_is_logged_in
    def get(self, post_id, comment_id):
        keyBlog = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(keyBlog)

        if not post:
            self.error(404)
            return
        keyComment = db.Key.from_path('Comment', int(comment_id), parent=keyBlog)
        comment = db.get(keyComment)
        if not comment:
            self.error(404)
            return

        self.render("deletecomment.html", subject=post.subject, c=comment)

    def post(self, post_id, comment_id):
        keyBlog = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(keyBlog)

        if not post:
            self.error(404)
            return
        keyComment = db.Key.from_path('Comment', int(comment_id), parent=keyBlog)
        comment = db.get(keyComment)
        if not comment:
            self.error(404)
            return

        comment.delete()
        self.redirect('/blog')

###### Unit 2 HW's
class Rot13(BlogHandler):
    def get(self):
        self.render('rot13-form.html')

    def post(self):
        rot13 = ''
        text = self.request.get('text')
        if text:
            rot13 = text.encode('rot13')

        self.render('rot13-form.html', text=rot13)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)


PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)


EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Unit2Signup(Signup):
    def done(self):
        self.redirect('/unit2/welcome?username=' + self.username)


class Register(Signup):
    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')


class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')


class Unit3Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/signup')


class Welcome(BlogHandler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username=username)
        else:
            self.redirect('/unit2/signup')


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/unit2/rot13', Rot13),
                               ('/unit2/signup', Unit2Signup),
                               ('/unit2/welcome', Welcome),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/edit/([0-9]+)', EditPost),
                               ('/blog/delete/([0-9]+)', DeletePost),
                               ('/blog/like/([0-9]+)', LikePost),
                               ('/comment/newcomment/([0-9]+)', NewComment),
                               ('/comment/edit/([0-9]+)/([0-9]+)', EditComment),
                               ('/comment/delete/([0-9]+)/([0-9]+)', DeleteComment),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/unit3/welcome', Unit3Welcome),
                               ],
                              debug=True)
