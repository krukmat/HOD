# Copyright 2011 HOD Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""App Engine data model (schema) definition for HOD."""

# Python imports
import logging
import md5
import os
import re
import time
import uuid

# AppEngine imports
from google.appengine.ext import db
from google.appengine.api import memcache

CONTEXT_CHOICES = (3, 10, 25, 50, 75, 100)
DEFAULT_CONTEXT = 10
DEFAULT_COLUMN_WIDTH = 80
MIN_COLUMN_WIDTH = 3
MAX_COLUMN_WIDTH = 2000


### GQL query cache ###


_query_cache = {}


def gql(cls, clause, *args, **kwds):
  """Return a query object, from the cache if possible.

  Args:
    cls: a db.Model subclass.
    clause: a query clause, e.g. 'WHERE draft = TRUE'.
    *args, **kwds: positional and keyword arguments to be bound to the query.

  Returns:
    A db.GqlQuery instance corresponding to the query with *args and
    **kwds bound to the query.
  """
  query_string = 'SELECT * FROM %s %s' % (cls.kind(), clause)
  query = _query_cache.get(query_string)
  if query is None:
    _query_cache[query_string] = query = db.GqlQuery(query_string)
  query.bind(*args, **kwds)
  return query

class HODModel (db.Model):
  uuid = db.TextProperty(required=False,default=str(uuid.uuid4())) #Token
  active = db.BooleanProperty(default=True)
  owner = db.UserProperty(auto_current_user_add=True, required=True)
  created = db.DateTimeProperty(auto_now_add=True)
  modified = db.DateTimeProperty(auto_now=True)
  closed = db.BooleanProperty(default=False)  
  _is_starred = None

  def user_can_edit(self, user):
    """Return true if the given user has permission to edit this issue."""
    return user == self.owner

  @property
  def edit_allowed(self):
    """Whether the current user can edit this issue."""
    account = Account.current_user_account
    if account is None:
      return False
    return self.user_can_edit(account.user)


### Passenger ###


class Passenger(HODModel): #Es la clase para Pasajero
  """Pasajero
  """ 
  first_name = db.StringProperty(required=True) #First Name
  last_name = db.StringProperty(required=True) #First Name
  type_id = db.StringProperty(required=True,default="DNI",choices=set(["DNI", "LC", "EP"])) #Identification Type
  id = db.StringProperty(required=True) #Identification number
  email = db.EmailProperty()
  url = db.LinkProperty()
  
  def __str__(self):
      return self.first_name+" "+self.last_name
  
class Room(HODModel):
    number = db.StringProperty(required=True)
    floor = db.StringProperty(required=True)
    available = db.BooleanProperty(default=True)
    
    def __str__(self):
      return "floor:"+self.floor+",number:"+self.number

class Service(HODModel):
    code = db.StringProperty(required=True)
    description = db.TextProperty(required=True)
    cost = db.FloatProperty(required=True,default=0)
    
    def __str__(self):
      return "code:"+self.code+",description:"+self.description


### Lodging ###
class Lodging(HODModel):
    date_checkin = db.DateTimeProperty(required=True)
    date_checkout = db.DateTimeProperty(required=False)
    passenger = db.ReferenceProperty(Passenger,required=True)
    room = db.ReferenceProperty(Room,required=True)
    total =  db.FloatProperty(required=True,default=0)
    
    def __str__(self):
      return "passenger:"+str(self.passenger)+",room:"+str(self.room)
  
### ServicesxLodging ###
class ServicesxLodging(HODModel):
    date = db.DateTimeProperty(required=True,auto_now_add=True)
    lodging = db.ReferenceProperty(Lodging,required=True)
    service = db.ReferenceProperty(Service,required=True)
    total =  db.FloatProperty(required=True,default=0)
  
  
### Accounts ###


class Account(db.Model):
  """Maps a user or email address to a user-selected nickname, and more.

  Nicknames do not have to be unique.

  The default nickname is generated from the email address by
  stripping the first '@' sign and everything after it.  The email
  should not be empty nor should it start with '@' (AssertionError
  error is raised if either of these happens).

  This also holds a list of ids of starred issues.  The expectation
  that you won't have more than a dozen or so starred issues (a few
  hundred in extreme cases) and the memory used up by a list of
  integers of that size is very modest, so this is an efficient
  solution.  (If someone found a use case for having thousands of
  starred issues we'd have to think of a different approach.)
  """

  user = db.UserProperty(auto_current_user_add=True, required=True)
  email = db.EmailProperty(required=True)  # key == <email>
  nickname = db.StringProperty(required=True)
  default_context = db.IntegerProperty(default=DEFAULT_CONTEXT,
                                       choices=CONTEXT_CHOICES)
  default_column_width = db.IntegerProperty(default=DEFAULT_COLUMN_WIDTH)
  created = db.DateTimeProperty(auto_now_add=True)
  modified = db.DateTimeProperty(auto_now=True)
  stars = db.ListProperty(int)  # Issue ids of all starred issues
  fresh = db.BooleanProperty()
  uploadpy_hint = db.BooleanProperty(default=True)
  notify_by_email = db.BooleanProperty(default=True)
  notify_by_chat = db.BooleanProperty(default=False)

  # Current user's Account.  Updated by middleware.AddUserToRequestMiddleware.
  current_user_account = None

  lower_email = db.StringProperty()
  lower_nickname = db.StringProperty()
  xsrf_secret = db.BlobProperty()

  # Note that this doesn't get called when doing multi-entity puts.
  def put(self):
    self.lower_email = str(self.email).lower()
    self.lower_nickname = self.nickname.lower()
    super(Account, self).put()

  @classmethod
  def get_account_for_user(cls, user):
    """Get the Account for a user, creating a default one if needed."""
    email = user.email()
    assert email
    key = '<%s>' % email
    # Since usually the account already exists, first try getting it
    # without the transaction implied by get_or_insert().
    account = cls.get_by_key_name(key)
    if account is not None:
      return account
    nickname = cls.create_nickname_for_user(user)
    return cls.get_or_insert(key, user=user, email=email, nickname=nickname,
                             fresh=True)

  @classmethod
  def create_nickname_for_user(cls, user):
    """Returns a unique nickname for a user."""
    name = nickname = user.email().split('@', 1)[0]
    next_char = chr(ord(nickname[0].lower())+1)
    existing_nicks = [account.lower_nickname
                      for account in cls.gql(('WHERE lower_nickname >= :1 AND '
                                              'lower_nickname < :2'),
                                             nickname.lower(), next_char)]
    suffix = 0
    while nickname.lower() in existing_nicks:
      suffix += 1
      nickname = '%s%d' % (name, suffix)
    return nickname

  @classmethod
  def get_nickname_for_user(cls, user):
    """Get the nickname for a user."""
    return cls.get_account_for_user(user).nickname

  @classmethod
  def get_account_for_email(cls, email):
    """Get the Account for an email address, or return None."""
    assert email
    key = '<%s>' % email
    return cls.get_by_key_name(key)

  @classmethod
  def get_accounts_for_emails(cls, emails):
    """Get the Accounts for each of a list of email addresses."""
    return cls.get_by_key_name(['<%s>' % email for email in emails])

  @classmethod
  def get_by_key_name(cls, key, **kwds):
    """Override db.Model.get_by_key_name() to use cached value if possible."""
    if not kwds and cls.current_user_account is not None:
      if key == cls.current_user_account.key().name():
        return cls.current_user_account
    return super(Account, cls).get_by_key_name(key, **kwds)

  @classmethod
  def get_multiple_accounts_by_email(cls, emails):
    """Get multiple accounts.  Returns a dict by email."""
    results = {}
    keys = []
    for email in emails:
      if cls.current_user_account and email == cls.current_user_account.email:
        results[email] = cls.current_user_account
      else:
        keys.append('<%s>' % email)
    if keys:
      accounts = cls.get_by_key_name(keys)
      for account in accounts:
        if account is not None:
          results[account.email] = account
    return results

  @classmethod
  def get_nickname_for_email(cls, email, default=None):
    """Get the nickname for an email address, possibly a default.

    If default is None a generic nickname is computed from the email
    address.

    Args:
      email: email address.
      default: If given and no account is found, returned as the default value.
    Returns:
      Nickname for given email.
    """
    account = cls.get_account_for_email(email)
    if account is not None and account.nickname:
      return account.nickname
    if default is not None:
      return default
    return email.replace('@', '_')

  @classmethod
  def get_account_for_nickname(cls, nickname):
    """Get the list of Accounts that have this nickname."""
    assert nickname
    assert '@' not in nickname
    return cls.all().filter('lower_nickname =', nickname.lower()).get()

  @classmethod
  def get_email_for_nickname(cls, nickname):
    """Turn a nickname into an email address.

    If the nickname is not unique or does not exist, this returns None.
    """
    account = cls.get_account_for_nickname(nickname)
    if account is None:
      return None
    return account.email

  def user_has_selected_nickname(self):
    """Return True if the user picked the nickname.

    Normally this returns 'not self.fresh', but if that property is
    None, we assume that if the created and modified timestamp are
    within 2 seconds, the account is fresh (i.e. the user hasn't
    selected a nickname yet).  We then also update self.fresh, so it
    is used as a cache and may even be written back if we're lucky.
    """
    if self.fresh is None:
      delta = self.created - self.modified
      # Simulate delta = abs(delta)
      if delta.days < 0:
        delta = -delta
      self.fresh = (delta.days == 0 and delta.seconds < 2)
    return not self.fresh

  _drafts = None

  @property
  def drafts(self):
    """A list of issue ids that have drafts by this user.

    This is cached in memcache.
    """
    if self._drafts is None:
      if self._initialize_drafts():
        self._save_drafts()
    return self._drafts

  def update_drafts(self, issue, have_drafts=None):
    """Update the user's draft status for this issue.

    Args:
      issue: an Issue instance.
      have_drafts: optional bool forcing the draft status.  By default,
          issue.num_drafts is inspected (which may query the datastore).

    The Account is written to the datastore if necessary.
    """
    dirty = False
    if self._drafts is None:
      dirty = self._initialize_drafts()
    id = issue.key().id()
    if have_drafts is None:
      have_drafts = bool(issue.num_drafts)  # Beware, this may do a query.
    if have_drafts:
      if id not in self._drafts:
        self._drafts.append(id)
        dirty = True
    else:
      if id in self._drafts:
        self._drafts.remove(id)
        dirty = True
    if dirty:
      self._save_drafts()

  def _initialize_drafts(self):
    """Initialize self._drafts from scratch.

    This mostly exists as a schema conversion utility.

    Returns:
      True if the user should call self._save_drafts(), False if not.
    """
    drafts = memcache.get('user_drafts:' + self.email)
    if drafts is not None:
      self._drafts = drafts
      ##logging.info('HIT: %s -> %s', self.email, self._drafts)
      return False
    # We're looking for the Issue key id.  The ancestry of comments goes:
    # Issue -> PatchSet -> Patch -> Comment.
    issue_ids = set(comment.key().parent().parent().parent().id()
                    for comment in gql(Comment,
                                       'WHERE author = :1 AND draft = TRUE',
                                       self.user))
    self._drafts = list(issue_ids)
    ##logging.info('INITIALIZED: %s -> %s', self.email, self._drafts)
    return True

  def _save_drafts(self):
    """Save self._drafts to memcache."""
    ##logging.info('SAVING: %s -> %s', self.email, self._drafts)
    memcache.set('user_drafts:' + self.email, self._drafts, 3600)

  def get_xsrf_token(self, offset=0):
    """Return an XSRF token for the current user."""
    if not self.xsrf_secret:
      self.xsrf_secret = os.urandom(8)
      self.put()
    m = md5.new(self.xsrf_secret)
    email_str = self.lower_email
    if isinstance(email_str, unicode):
      email_str = email_str.encode('utf-8')
    m.update(self.lower_email)
    when = int(time.time()) // 3600 + offset
    m.update(str(when))
    return m.hexdigest()
