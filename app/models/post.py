from google.appengine.ext import db
from app.helpers.post import blog_key
from app.helpers.general import render_str


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
            return render_str("post/post.html", p=self, userId=0)
        else:
            return render_str("post/post.html", p=self, userId=logged_user_key.id())

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
            count += 1
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
            count += 1
        return count
