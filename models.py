"""models.py - This file contains the class definitions for the Datastore
entities used by the Game. Because these classes are also regular Python
classes they can include methods (such as 'to_form' and 'new_game')."""

from google.appengine.ext import db
import helper
import random
import hashlib
from string import letters


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    """Post object"""
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    user = db.IntegerProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def render(self, logged_user_key):
        self._render_text = self.content.replace('\n', '<br>')
        if not logged_user_key:
            return helper.render_str("post.html", p=self, userId=0)
        else:
            return helper.render_str("post.html", p=self, userId=logged_user_key.id())

    @property
    def comments(self):
        key = db.Key.from_path('Post', int(self.key().id()), parent=blog_key())

        comments = db.GqlQuery("SELECT * "
                            "FROM Comment "
                            "WHERE ANCESTOR IS :1 "
                            "ORDER BY created DESC",
                            key)
        return comments

    @property
    def likes(self):
        key = db.Key.from_path('Post', int(self.key().id()), parent=blog_key())

        likes = db.GqlQuery("SELECT *"
                            "FROM Like "
                            "WHERE ANCESTOR IS :1 ",
                            key)
        count = 0
        for i in likes:
            count+=1
        return count

    def userLikes(self, user_id):
        keyPost = db.Key.from_path('Post', int(self.key().id()), parent=blog_key())

        userLikes = db.GqlQuery("SELECT *"
                            "FROM Like "
                            "WHERE ANCESTOR IS :1 "
                            "AND user = :2",
                            keyPost, user_id)

        count = 0
        for i in userLikes:
            count+=1
        return count

def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


class Comment(db.Model):
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    user = db.IntegerProperty(required=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return helper.render_str("comment.html", c=self)


class Like(db.Model):
    user = db.IntegerProperty(required=True)



