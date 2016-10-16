from google.appengine.ext import db


class Like(db.Model):
    user = db.IntegerProperty(required=True)
