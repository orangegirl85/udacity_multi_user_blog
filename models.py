"""models.py - This file contains the class definitions for the Datastore
entities used by the Game. Because these classes are also regular Python
classes they can include methods (such as 'to_form' and 'new_game')."""

from google.appengine.ext import db
#from protorpc import messages
import helper


class Post(db.Model):
    """Post object"""
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return helper.render_str("post.html", p=self)


# class User(ndb.Model):
#     """User profile"""
#     name = ndb.StringProperty(required=True)
#     email = ndb.StringProperty()
#     score = ndb.IntegerProperty(default=0)
#
#     def to_form(self):
#         return UserRankingForm(user_name=self.name, score=self.score)
#
#
# class GameHistory(ndb.Model):
#     """GameHistory object"""
#     username = ndb.StringProperty(required=True)
#     position = ndb.IntegerProperty(required=True)
#     message = ndb.StringProperty(required=True)
#
#     def to_form(self):
#         return GameHistoryForm(username=self.username, position=self.position, message=self.message)
#
#
# class Game(ndb.Model):
#     """Game object"""
#     user1 = ndb.KeyProperty(required=True, kind='User')
#     user2 = ndb.KeyProperty(required=True, kind='User')
#     game_over = ndb.BooleanProperty(required=True, default=False)
#     current_player = ndb.StringProperty(default='PLAYER_X')
#     board = ndb.StringProperty(repeated=True)
#     cancelled = ndb.BooleanProperty(required=True, default=False)
#     email_reminder_sent = ndb.BooleanProperty(default=False)
#
#     @classmethod
#     def new_game(cls, user1, user2):
#         """Creates and returns a new game"""
#         game = Game(user1=user1,
#                     user2=user2,
#                     board=['', '', '', '', '', '', '', '', ''])
#         game.put()
#         return game
#
#     def to_form(self, message):
#         """Returns a GameForm representation of the Game"""
#         form = GameForm()
#         form.urlsafe_key = self.key.urlsafe()
#         form.user_name1 = self.user1.get().name
#         form.user_name2 = self.user2.get().name
#         form.current_player = self.current_player
#         form.board = self.board
#         form.game_over = self.game_over
#         form.cancelled = self.cancelled
#         form.message = message
#         return form
#
#     def end_game(self, draw=False):
#         """Ends the game"""
#         self.game_over = True
#         self.put()
#
#         if not draw:
#             if self.current_player == 'PLAYER_X':
#                 self._update_user_score(self.user1, 1)
#                 self._update_user_score(self.user2, -1)
#             else:
#                 self._update_user_score(self.user1, -1)
#                 self._update_user_score(self.user2, 1)
#
#     def _update_user_score(self, user, score):
#         user11 = User.query(User.name == user.get().name).get()
#         user11.score += score
#         user11.put()
#
#     def cancel_game(self):
#         """Cancels the game"""
#         self.cancelled = True
#         self.put()
#
#
# class GameForm(messages.Message):
#     """GameForm for outbound game state information"""
#     urlsafe_key = messages.StringField(1, required=True)
#     game_over = messages.BooleanField(2, required=True)
#     message = messages.StringField(3, required=True)
#     user_name1 = messages.StringField(4, required=True)
#     user_name2 = messages.StringField(5, required=True)
#     current_player = messages.StringField(6, required=True)
#     board = messages.StringField(7, repeated=True)
#     cancelled = messages.BooleanField(8, required=True)
#
#
# class GameForms(messages.Message):
#     """Return multiple GameForm"""
#     items = messages.MessageField(GameForm, 1, repeated=True)
#
#
# class NewGameForm(messages.Message):
#     """Used to create a new game"""
#     user_name1 = messages.StringField(1, required=True)
#     user_name2 = messages.StringField(2, required=True)
#
#
# class MakeMoveForm(messages.Message):
#     """Used to make a move in an existing game"""
#     position = messages.IntegerField(1, required=True)
#
#
# class UserRankingForm(messages.Message):
#     """UserRankingForm for outbound User information"""
#     user_name = messages.StringField(1, required=True)
#     score = messages.IntegerField(2, required=True)
#
#
# class UserRankingsForm(messages.Message):
#     """Return multiple UserRankingsForms"""
#     items = messages.MessageField(UserRankingForm, 1, repeated=True)
#
#
# class GameHistoryForm(messages.Message):
#     """GameHistoryForm for outbound GameHistory information"""
#     username = messages.StringField(1, required=True)
#     position = messages.IntegerField(2, required=True)
#     message = messages.StringField(3, required=True)
#
#
# class GameHistoryForms(messages.Message):
#     """Return multiple GameHistoryForm"""
#     items = messages.MessageField(GameHistoryForm, 1, repeated=True)
#
#
# class StringMessage(messages.Message):
#     """StringMessage-- outbound (single) string message"""
#     message = messages.StringField(1, required=True)
