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

"""Views for HOD."""


### Imports ###


# Python imports
import binascii
import datetime
import email  # see incoming_mail()
import email.utils
import logging
import md5
import os
import random
import re
import urllib
import uuid


from cStringIO import StringIO
from xml.etree import ElementTree

# AppEngine imports
from google.appengine.api import mail
from google.appengine.api import memcache
from google.appengine.api import users
from google.appengine.api import urlfetch
from google.appengine.api import xmpp
from google.appengine.ext import db
from google.appengine.ext.db import djangoforms
from google.appengine.runtime import DeadlineExceededError
from google.appengine.runtime import apiproxy_errors
from google.appengine.ext.db import Key

# Django imports
# TODO(guido): Don't import classes/functions directly.
from django import forms
from google.appengine.ext.db import djangoforms
# Import settings as django_settings to avoid name conflict with settings().
from django.conf import settings as django_settings
from django.http import HttpResponse, HttpResponseRedirect
from django.http import HttpResponseForbidden, HttpResponseNotFound
from django.http import HttpResponseBadRequest
from django.shortcuts import render_to_response
import django.template
from django.template import RequestContext
from django.utils import simplejson
from django.utils.safestring import mark_safe
from django.core.urlresolvers import reverse

# Local imports
import models
from models import Passenger,Room, Service, Lodging, ServicesxLodging
import library

# Add our own template library.
_library_name = __name__.rsplit('.', 1)[0] + '.library'
if not django.template.libraries.get(_library_name, None):
  django.template.add_to_builtins(_library_name)


### Constants ###


IS_DEV = os.environ['SERVER_SOFTWARE'].startswith('Dev')  # Development server


### Form classes ###


class AccountInput(forms.TextInput):
  # Associates the necessary css/js files for the control.  See
  # http://docs.djangoproject.com/en/dev/topics/forms/media/.
  # 
  # Don't forget to place {{formname.media}} into html header
  # when using this html control.
  class Media:
    css = {
      'all': ('autocomplete/jquery.autocomplete.css',)
    }
    js = (
      'autocomplete/lib/jquery.js',
      'autocomplete/lib/jquery.bgiframe.min.js',
      'autocomplete/lib/jquery.ajaxQueue.js',
      'autocomplete/jquery.autocomplete.js'
    )

  def render(self, name, value, attrs=None):
    output = super(AccountInput, self).render(name, value, attrs)
    # TODO(anatoli): move this into .js media for this form
    return output + mark_safe(u'''<script type="text/javascript">
                              jQuery("#id_%s").autocomplete("%s", {
                              max: 10,
                              highlight: false,
                              multiple: true,
                              multipleSeparator: ", ",
                              scroll: true,
                              scrollHeight: 300,
                              matchContains: true,
                              formatResult : function(row) {
                                return row[0].replace(/ .+/gi, '');
                              }
                              });
                              </script>''' % (name, reverse(account)))


class PassengerForm(djangoforms.ModelForm):
    class Meta:
        model = Passenger
        exclude = ['uuid']

class RoomForm(djangoforms.ModelForm):
    class Meta:
        model = Room
        exclude = ['uuid']
  
class ServiceForm(djangoforms.ModelForm):
    class Meta:
        model = Service
        exclude = ['uuid']
        
class ServicesxLodgingForm(djangoforms.ModelForm):
    class Meta:
        model = ServicesxLodging
        exclude = ['uuid']

class LodgingForm(djangoforms.ModelForm):
    class Meta:
        model = Lodging
        exclude = ['uuid']


FORM_CONTEXT_VALUES = [(x, '%d lines' % x) for x in models.CONTEXT_CHOICES]
FORM_CONTEXT_VALUES.append(('', 'Whole file'))


class SettingsForm(forms.Form):

  nickname = forms.CharField(max_length=30)
  context = forms.IntegerField(
    widget=forms.Select(choices=FORM_CONTEXT_VALUES),
    required=False,
    label='Context')
  column_width = forms.IntegerField(initial=models.DEFAULT_COLUMN_WIDTH,
                                    min_value=models.MIN_COLUMN_WIDTH,
                                    max_value=models.MAX_COLUMN_WIDTH)
  notify_by_email = forms.BooleanField(required=False,
                                       widget=forms.HiddenInput())
  notify_by_chat = forms.BooleanField(
    required=False,
    help_text='You must accept the invite for this to work.')

  def clean_nickname(self):
    nickname = self.cleaned_data.get('nickname')
    # Check for allowed characters
    match = re.match(r'[\w\.\-_\(\) ]+$', nickname, re.UNICODE|re.IGNORECASE)
    if not match:
      raise forms.ValidationError('Allowed characters are letters, digits, '
                                  '".-_()" and spaces.')
    # Check for sane whitespaces
    if re.search(r'\s{2,}', nickname):
      raise forms.ValidationError('Use single spaces between words.')
    if len(nickname) != len(nickname.strip()):
      raise forms.ValidationError('Leading and trailing whitespaces are '
                                  'not allowed.')

    if nickname.lower() == 'me':
      raise forms.ValidationError('Choose a different nickname.')

    # Look for existing nicknames
    accounts = list(models.Account.gql('WHERE lower_nickname = :1',
                                       nickname.lower()))
    for account in accounts:
      if account.key() == models.Account.current_user_account.key():
        continue
      raise forms.ValidationError('This nickname is already in use.')

    return nickname


### Exceptions ###


class InvalidIncomingEmailError(Exception):
  """Exception raised by incoming mail handler when a problem occurs."""


### Helper functions ###


# Counter displayed (by respond()) below) on every page showing how
# many requests the current incarnation has handled, not counting
# redirects.  Rendered by templates/base.html.
counter = 0


def respond(request, template, params=None):
  """Helper to render a response, passing standard stuff to the response.

  Args:
    request: The request object.
    template: The template name; '.html' is appended automatically.
    params: A dict giving the template parameters; modified in-place.

  Returns:
    Whatever render_to_response(template, params) returns.

  Raises:
    Whatever render_to_response(template, params) raises.
  """
  global counter
  counter += 1
  if params is None:
    params = {}
  must_choose_nickname = False
  uploadpy_hint = False
  if request.user is not None:
    account = models.Account.current_user_account
    must_choose_nickname = not account.user_has_selected_nickname()
    uploadpy_hint = account.uploadpy_hint
  params['request'] = request
  params['counter'] = counter
  params['user'] = request.user
  params['is_admin'] = request.user_is_admin
  params['is_dev'] = IS_DEV
  params['media_url'] = django_settings.MEDIA_URL
  full_path = request.get_full_path().encode('utf-8')
  if request.user is None:
    params['sign_in'] = users.create_login_url(full_path)
  else:
    params['sign_out'] = users.create_logout_url(full_path)
    account = models.Account.current_user_account
    if account is not None:
      params['xsrf_token'] = account.get_xsrf_token()
  params['must_choose_nickname'] = must_choose_nickname
  params['uploadpy_hint'] = uploadpy_hint
  try:
    return render_to_response(template, params,
                              context_instance=RequestContext(request))
  except DeadlineExceededError:
    logging.exception('DeadlineExceededError')
    return HttpResponse('DeadlineExceededError', status=503)
  except apiproxy_errors.CapabilityDisabledError, err:
    logging.exception('CapabilityDisabledError: %s', err)
    return HttpResponse('Rietveld: App Engine is undergoing maintenance. '
                        'Please try again in a while. ' + str(err),
                        status=503)
  except MemoryError:
    logging.exception('MemoryError')
    return HttpResponse('MemoryError', status=503)
  except AssertionError:
    logging.exception('AssertionError')
    return HttpResponse('AssertionError')
  finally:
    library.user_cache.clear() # don't want this sticking around


def _random_bytes(n):
  """Helper returning a string of random bytes of given length."""
  return ''.join(map(chr, (random.randrange(256) for i in xrange(n))))


def _notify_issue(request, issue, message):
  """Try sending an XMPP (chat) message.

  Args:
    request: The request object.
    issue: Issue whose owner, reviewers, CC are to be notified.
    message: Text of message to send, e.g. 'Created'.

  The current user and the issue's subject and URL are appended to the message.

  Returns:
    True if the message was (apparently) delivered, False if not.
  """
  iid = issue.key().id()
  emails = [issue.owner.email()]
  if issue.reviewers:
    emails.extend(issue.reviewers)
  if issue.cc:
    emails.extend(issue.cc)
  accounts = models.Account.get_multiple_accounts_by_email(emails)
  jids = []
  for account in accounts.itervalues():
    logging.debug('email=%r,chat=%r', account.email, account.notify_by_chat)
    if account.notify_by_chat:
      jids.append(account.email)
  if not jids:
    logging.debug('No XMPP jids to send to for issue %d', iid)
    return True  # Nothing to do.
  jids_str = ', '.join(jids)
  logging.debug('Sending XMPP for issue %d to %s', iid, jids_str)
  sender = '?'
  if models.Account.current_user_account:
    sender = models.Account.current_user_account.nickname
  elif request.user:
    sender = request.user.email()
  message = '%s by %s: %s\n%s' % (message,
                                  sender,
                                  issue.token,
                                  request.build_absolute_uri(
                                    reverse(show, args=[iid])))
  try:
    sts = xmpp.send_message(jids, message)
  except Exception, err:
    logging.exception('XMPP exception %s sending for issue %d to %s',
                      err, iid, jids_str)
    return False
  else:
    if sts == [xmpp.NO_ERROR] * len(jids):
      logging.info('XMPP message sent for issue %d to %s', iid, jids_str)
      return True
    else:
      logging.error('XMPP error %r sending for issue %d to %s',
                    sts, iid, jids_str)
      return False


### Decorators for request handlers ###


def post_required(func):
  """Decorator that returns an error unless request.method == 'POST'."""

  def post_wrapper(request, *args, **kwds):
    if request.method != 'POST':
      return HttpResponse('This requires a POST request.', status=405)
    return func(request, *args, **kwds)

  return post_wrapper


def login_required(func):
  """Decorator that redirects to the login page if you're not logged in."""

  def login_wrapper(request, *args, **kwds):
    if request.user is None:
      return HttpResponseRedirect(
          users.create_login_url(request.get_full_path().encode('utf-8')))
    return func(request, *args, **kwds)

  return login_wrapper


def xsrf_required(func):
  """Decorator to check XSRF token.

  This only checks if the method is POST; it lets other method go
  through unchallenged.  Apply after @login_required and (if
  applicable) @post_required.  This decorator is mutually exclusive
  with @upload_required.
  """

  def xsrf_wrapper(request, *args, **kwds):
    if request.method == 'POST':
      post_token = request.POST.get('xsrf_token')
      if not post_token:
        return HttpResponse('Missing XSRF token.', status=403)
      account = models.Account.current_user_account
      if not account:
        return HttpResponse('Must be logged in for XSRF check.', status=403)
      xsrf_token = account.get_xsrf_token()
      if post_token != xsrf_token:
        # Try the previous hour's token
        xsrf_token = account.get_xsrf_token(-1)
        if post_token != xsrf_token:
          return HttpResponse('Invalid XSRF token.', status=403)
    return func(request, *args, **kwds)

  return xsrf_wrapper


def upload_required(func):
  """Decorator for POST requests from the upload.py script.

  Right now this is for documentation only, but eventually we should
  change this to insist on a special header that JavaScript cannot
  add, to prevent XSRF attacks on these URLs.  This decorator is
  mutually exclusive with @xsrf_required.
  """
  return func


def admin_required(func):
  """Decorator that insists that you're logged in as administratior."""

  def admin_wrapper(request, *args, **kwds):
    if request.user is None:
      return HttpResponseRedirect(
          users.create_login_url(request.get_full_path().encode('utf-8')))
    if not request.user_is_admin:
      return HttpResponseForbidden('You must be admin in for this function')
    return func(request, *args, **kwds)

  return admin_wrapper



def user_key_required(func):
  """Decorator that processes the user handler argument."""

  def user_key_wrapper(request, user_key, *args, **kwds):
    user_key = urllib.unquote(user_key)
    if '@' in user_key:
      request.user_to_show = users.User(user_key)
    else:
      account = models.Account.get_account_for_nickname(user_key)
      if not account:
        logging.info("account not found for nickname %s" % user_key)
        return HttpResponseNotFound('No user found with that key (%s)' %
                                    urllib.quote(user_key))
      request.user_to_show = account.user
    return func(request, *args, **kwds)

  return user_key_wrapper



### Request handlers ###

@login_required
def index(request):
  """/ - Show a list of patches."""
  user = request.user
  news = []
  return respond(request, 'user.html',
                 {'email': user.email(),
                  'news': news,
                  })


DEFAULT_LIMIT = 10


def _url(path, **kwargs):
  """Format parameters for query string.

  Args:
    path: Path of URL.
    kwargs: Keyword parameters are treated as values to add to the query
      parameter of the URL.  If empty no query parameters will be added to
      path and '?' omitted from the URL.
  """
  if kwargs:
    encoded_parameters = urllib.urlencode(kwargs)
    if path.endswith('?'):
      # Trailing ? on path.  Append parameters to end.
      return '%s%s' % (path, encoded_parameters)
    elif '?' in path:
      # Append additional parameters to existing query parameters.
      return '%s&%s' % (path, encoded_parameters)
    else:
      # Add query parameters to path with no query parameters.
      return '%s?%s' % (path, encoded_parameters)
  else:
    return path



def lodgings(request):
      lodgings = models.Lodging.all().filter("active = ",True)
      return respond(request, 'lodging.html', {'form': LodgingForm(),'lodgings':lodgings})

def lodgings_new(request):
    if request.method != 'POST':
        form = LodgingForm()
        return respond(request, 'lodging_new.html', {'form': form })
    
    form = LodgingForm(request.POST)
    if form.is_valid():
        entity = form.save()
        entity.put()
        return HttpResponseRedirect(reverse(lodgings))
    else:
        return respond(request, 'lodging_new.html', {'form': form })

def lodgings_delete(request):
    id = int(request.GET.get('id'))
    lodging = Lodging.get(db.Key.from_path('Lodging', id))
    passenger.active = False
    passenger.put()
    return HttpResponseRedirect(reverse(lodgings))
    

def lodgings_edit(request):
    id = int(request.GET.get('id'))
    lodging = Lodging.get(db.Key.from_path('Lodging', id))
    if request.method != 'POST':
            form = LodgingForm(instance=lodging)
            return respond(request, 'lodging_edit.html', {'form': form, 'id': id })
    
    form = LodgingForm(request.POST,instance=lodging)
    if form.is_valid():
        entity = form.save()
        entity.put()
        return HttpResponseRedirect(reverse(lodging))
    else:
        return respond(request, 'lodging_edit.html', {'form': form })



def passengers(request):
      passengers = models.Passenger.all().filter("active = ",True)
      return respond(request, 'passenger.html', {'form': PassengerForm(),'passengers':passengers})

def passengers_new(request):
    if request.method != 'POST':
        form = PassengerForm()
        return respond(request, 'passenger_new.html', {'form': form })
    
    form = PassengerForm(request.POST)
    if form.is_valid():
        entity = form.save()
        entity.put()
        return HttpResponseRedirect(reverse(passengers))
    else:
        return respond(request, 'passenger_new.html', {'form': form })

def passengers_delete(request):
    id = int(request.GET.get('id'))
    passenger = Passenger.get(db.Key.from_path('Passenger', id))
    passenger.active = False
    passenger.put()
    return HttpResponseRedirect(reverse(passengers))
    

def passengers_edit(request):
    id = int(request.GET.get('id'))
    passenger = Passenger.get(db.Key.from_path('Passenger', id))
    if request.method != 'POST':
            form = PassengerForm(instance=passenger)
            return respond(request, 'passenger_edit.html', {'form': form, 'id': id })
    
    form = PassengerForm(request.POST,instance=passenger)
    if form.is_valid():
        entity = form.save()
        entity.put()
        return HttpResponseRedirect(reverse(passengers))
    else:
        return respond(request, 'passenger_edit.html', {'form': form })

def rooms(request):
    rooms = models.Room.all().filter("active = ",True)
    return respond(request, 'room.html', {'rooms':rooms})

def rooms_new(request):
    if request.method != 'POST':
        form = RoomForm()
        return respond(request, 'room_new.html', {'form': form })
    
    form = RoomForm(request.POST)
    if form.is_valid():
        entity = form.save()
        entity.put()
        return HttpResponseRedirect(reverse(rooms))
    else:
        return respond(request, 'room_new.html', {'form': form })

def rooms_delete(request):
    id = int(request.GET.get('id'))
    room = Room.get(db.Key.from_path('Room', id))
    room.active = False
    room.put()
    return HttpResponseRedirect(reverse(rooms))
    

def rooms_edit(request):
    id = int(request.GET.get('id'))
    room = Room.get(db.Key.from_path('Room', id))
    if request.method != 'POST':
            form = RoomForm(instance=room)
            return respond(request, 'room_edit.html', {'form': form, 'id': id })
    
    form = RoomForm(request.POST,instance=room)
    if form.is_valid():
        entity = form.save()
        entity.put()
        return HttpResponseRedirect(reverse(rooms))
    else:
        return respond(request, 'room_edit.html', {'form': form })

def services(request):
    services = models.Service.all().filter("active = ",True)
    return respond(request, 'service.html', {'services':services})

def services_new(request):
    if request.method != 'POST':
        form = ServiceForm()
        return respond(request, 'service_new.html', {'form': form })
    
    form = ServiceForm(request.POST)
    if form.is_valid():
        entity = form.save()
        entity.put()
        return HttpResponseRedirect(reverse(services))
    else:
        return respond(request, 'service_new.html', {'form': form })

def services_delete(request):
    id = int(request.GET.get('id'))
    service = Service.get(db.Key.from_path('Service', id))
    service.active = False
    service.put()
    return HttpResponseRedirect(reverse(services))
    

def services_edit(request):
    id = int(request.GET.get('id'))
    service = Service.get(db.Key.from_path('Service', id))
    if request.method != 'POST':
            form = ServiceForm(instance=service)
            return respond(request, 'service_edit.html', {'form': form, 'id': id })
    
    form = ServiceForm(request.POST,instance=service)
    if form.is_valid():
        entity = form.save()
        entity.put()
        return HttpResponseRedirect(reverse(services))
    else:
        return respond(request, 'service_edit.html', {'form': form })

def consumption(request):
    servicesxlodging = models.ServicesxLodging.all().filter("active = ",True)
    return respond(request, 'servicesxlodging.html', {'servicesxlodging':servicesxlodging})

def consumption_new(request):
    if request.method != 'POST':
        form = ServicesxLodgingForm()
        return respond(request, 'servicesxlodging_new.html', {'form': form })
    
    form = ServicesxLodgingForm(request.POST)
    if form.is_valid():
        entity = form.save()
        entity.put()
        return HttpResponseRedirect(reverse(consumption))
    else:
        return respond(request, 'servicesxlodging_new.html', {'form': form })

def consumption_delete(request):
    id = int(request.GET.get('id'))
    service = ServicesxLodging.get(db.Key.from_path('ServicesxLodging', id))
    service.active = False
    service.put()
    return HttpResponseRedirect(reverse(consumption))
    

def consumption_edit(request):
    id = int(request.GET.get('id'))
    service = ServicesxLodging.get(db.Key.from_path('ServicesxLodging', id))
    if request.method != 'POST':
            form = ServicesxLodgingForm(instance=service)
            return respond(request, 'servicesxlodging_edit.html', {'form': form, 'id': id })
    
    form = ServicesxLodgingForm(request.POST,instance=service)
    if form.is_valid():
        entity = form.save()
        entity.put()
        return HttpResponseRedirect(reverse(consumption))
    else:
        return respond(request, 'servicesxlodging_edit.html', {'form': form })


def _get_emails(form, label):
  """Helper to return the list of reviewers, or None for error."""
  raw_emails = form.cleaned_data.get(label)
  if raw_emails:
    return _get_emails_from_raw(raw_emails.split(','), form=form, label=label)
  return []

@login_required
def account(request):
  """/account/?q=blah&limit=10&timestamp=blah - Used for autocomplete."""
  def searchAccounts(property, domain, added, response):
    query = request.GET.get('q').lower()
    limit = _clean_int(request.GET.get('limit'), 10, 10, 100)

    accounts = models.Account.all()
    accounts.filter("lower_%s >= " % property, query)
    accounts.filter("lower_%s < " % property, query + u"\ufffd")
    accounts.order("lower_%s" % property);
    for account in accounts:
      if account.key() in added:
        continue
      if domain and not account.email.endswith(domain):
        continue
      if len(added) >= limit:
        break
      added.add(account.key())
      response += '%s (%s)\n' % (account.email, account.nickname)
    return added, response

  added = set()
  response = ''
  domain = os.environ['AUTH_DOMAIN']
  if domain != 'gmail.com':
    # 'gmail.com' is the value AUTH_DOMAIN is set to if the app is running
    # on appspot.com and shouldn't prioritize the custom domain.
    added, response = searchAccounts("email", domain, added, response)
    added, response = searchAccounts("nickname", domain, added, response)
  added, response = searchAccounts("nickname", "", added, response)
  added, response = searchAccounts("email", "", added, response)
  return HttpResponse(response)




def _delete_cached_contents(patch_set):
  """Transactional helper for edit() to delete cached contents."""
  # TODO(guido): No need to do this in a transaction.
  patches = []
  contents = []
  for patch in patch_set:
    try:
      content = patch.content
    except db.Error:
      content = None
    try:
      patched_content = patch.patched_content
    except db.Error:
      patched_content = None
    if content is not None:
      contents.append(content)
    if patched_content is not None:
      contents.append(patched_content)
    patch.content = None
    patch.patched_content = None
    patches.append(patch)
  if contents:
    logging.info("Deleting %d contents", len(contents))
    db.delete(contents)
  if patches:
    logging.info("Updating %d patches", len(patches))
    db.put(patches)




def _get_context_for_user(request):
  """Returns the context setting for a user.

  The value is validated against models.CONTEXT_CHOICES.
  If an invalid value is found, the value is overwritten with
  engine.DEFAULT_CONTEXT.
  """
  get_param = request.GET.get('context') or None
  if 'context' in request.GET and get_param is None:
    # User wants to see whole file. No further processing is needed.
    return get_param
  if request.user:
    account = models.Account.current_user_account
    default_context = account.default_context
  else:
    default_context = engine.DEFAULT_CONTEXT
  context = _clean_int(get_param, default_context)
  if context is not None and context not in models.CONTEXT_CHOICES:
    context = engine.DEFAULT_CONTEXT
  return context

def _get_column_width_for_user(request):
  """Returns the column width setting for a user."""
  if request.user:
    account = models.Account.current_user_account
    default_column_width = account.default_column_width
  else:
    default_column_width = engine.DEFAULT_COLUMN_WIDTH
  column_width = _clean_int(request.GET.get('column_width'),
                            default_column_width,
                            engine.MIN_COLUMN_WIDTH, engine.MAX_COLUMN_WIDTH)
  return column_width



def _get_mail_template(request, issue):
  """Helper to return the template and context for an email.

  If this is the first email sent by the owner, a template that lists the
  reviewers, description and files is used.
  """
  context = {}
  template = 'mails/comment.txt'
  if request.user == issue.owner:
    if db.GqlQuery('SELECT * FROM Message WHERE ANCESTOR IS :1 AND sender = :2',
                   issue, db.Email(request.user.email())).count(1) == 0:
      template = 'mails/review.txt'
  return template, context




def _encode_safely(s):
  """Helper to turn a unicode string into 8-bit bytes."""
  if isinstance(s, unicode):
    s = s.encode('utf-8')
  return s




def _make_message(request, issue, message, comments=None, send_mail=False,
                  draft=None):
  """Helper to create a Message instance and optionally send an email."""
  template, context = _get_mail_template(request, issue)
  # Decide who should receive mail
  my_email = db.Email(request.user.email())
  to = [db.Email(issue.owner.email())] + issue.reviewers
  cc = issue.cc[:]
  if django_settings.RIETVELD_INCOMING_MAIL_ADDRESS:
    cc.append(db.Email(django_settings.RIETVELD_INCOMING_MAIL_ADDRESS))
  reply_to = to + cc
  if my_email in to and len(to) > 1:  # send_mail() wants a non-empty to list
    to.remove(my_email)
  if my_email in cc:
    cc.remove(my_email)
  subject = '%s (issue%d)' % (issue.token, issue.key().id())
  if issue.message_set.count(1) > 0:
    subject = 'Re: ' + subject
  if comments:
    details = _get_draft_details(request, comments)
  else:
    details = ''
  message = message.replace('\r\n', '\n')
  text = ((message.strip() + '\n\n' + details.strip())).strip()
  if draft is None:
    msg = models.Message(issue=issue,
                         subject=subject,
                         sender=my_email,
                         recipients=reply_to,
                         text=db.Text(text),
                         parent=issue)
  else:
    msg = draft
    msg.subject = subject
    msg.recipients = reply_to
    msg.text = db.Text(text)
    msg.draft = False
    msg.date = datetime.datetime.now()

  if send_mail:
    url = request.build_absolute_uri(reverse(show, args=[issue.key().id()]))
    reviewer_nicknames = ', '.join(library.get_nickname(rev_temp, True,
                                                        request)
                                   for rev_temp in issue.reviewers)
    cc_nicknames = ', '.join(library.get_nickname(cc_temp, True, request)
                             for cc_temp in cc)
    my_nickname = library.get_nickname(request.user, True, request)
    reply_to = ', '.join(reply_to)
    description = (issue.description or '').replace('\r\n', '\n')
    home = request.build_absolute_uri(reverse(index))
    context.update({'reviewer_nicknames': reviewer_nicknames,
                    'cc_nicknames': cc_nicknames,
                    'my_nickname': my_nickname, 'url': url,
                    'message': message, 'details': details,
                    'description': description, 'home': home,
                    })
    body = django.template.loader.render_to_string(
      template, context, context_instance=RequestContext(request))
    logging.warn('Mail: to=%s; cc=%s', ', '.join(to), ', '.join(cc))
    send_args = {'sender': my_email,
                 'to': [_encode_safely(address) for address in to],
                 'subject': _encode_safely(subject),
                 'body': _encode_safely(body),
                 'reply_to': _encode_safely(reply_to)}
    if cc:
      send_args['cc'] = [_encode_safely(address) for address in cc]

    attempts = 0
    while True:
      try:
        mail.send_mail(**send_args)
        break
      except apiproxy_errors.DeadlineExceededError:
        # apiproxy_errors.DeadlineExceededError is raised when the
        # deadline of an API call is reached (e.g. for mail it's
        # something about 5 seconds). It's not the same as the lethal
        # runtime.DeadlineExeededError.
        attempts += 1
        if attempts >= 3:
          raise
    if attempts:
      logging.warning("Retried sending email %s times", attempts)

  return msg



def search(request):
  """/search - Search for issues or patchset."""
  if request.method == 'GET':
    form = SearchForm(request.GET)
    if not form.is_valid() or not request.GET:
      return respond(request, 'search.html', {'form': SearchForm()})
  else:
    form = SearchForm(request.POST)
    if not form.is_valid():
      return HttpResponseBadRequest('Invalid arguments',
          content_type='text/plain')
  logging.info('%s' % form.cleaned_data)
  keys_only = form.cleaned_data['keys_only'] or False
  format = form.cleaned_data.get('format') or 'html'
  if format == 'html':
    keys_only = False
  q = models.Issue.all(keys_only=keys_only)
  if form.cleaned_data.get('cursor'):
    q.with_cursor(form.cleaned_data['cursor'])
  if form.cleaned_data.get('closed') != None:
    q.filter('closed = ', form.cleaned_data['closed'])
  if form.cleaned_data.get('owner'):
    if '@' in form.cleaned_data['owner']:
      user = users.User(form.cleaned_data['owner'])
    else:
      account = models.Account.get_account_for_nickname(
          form.cleaned_data['owner'])
      if not account:
        return HttpResponseBadRequest('Invalid owner',
            content_type='text/plain')
      user = account.user
    q.filter('owner = ', user)
  if form.cleaned_data.get('reviewer'):
    q.filter('reviewers = ', db.Email(form.cleaned_data['reviewer']))
  if form.cleaned_data.get('private') != None:
    q.filter('private = ', form.cleaned_data['private'])
  if form.cleaned_data.get('base'):
    q.filter('base = ', form.cleaned_data['base'])
  # Update the cursor value in the result.
  if format == 'html':
    nav_params = dict(
        (k, v) for k, v in form.cleaned_data.iteritems() if v is not None)
    return _paginate_issues_with_cursor(
        reverse(search),
        request,
        q,
        form.cleaned_data['limit'] or DEFAULT_LIMIT,
        'search_results.html',
        extra_nav_parameters=nav_params)

  results = q.fetch(form.cleaned_data['limit'] or 100)
  form.cleaned_data['cursor'] = q.cursor()
  if keys_only:
    # There's not enough information to filter. The only thing that is leaked is
    # the issue's key.
    filtered_results = results
  else:
    filtered_results = [i for i in results if _can_view_issue(request.user, i)]
  data = {
    'cursor': form.cleaned_data['cursor'],
  }
  if keys_only:
    data['results'] = [i.id() for i in filtered_results]
  else:
    messages = form.cleaned_data['with_messages']
    data['results'] = [_issue_as_dict(i, messages, request)
                      for i in filtered_results],
  if format == 'json_pretty':
    out = simplejson.dumps(data, indent=2, sort_keys=True)
  else:
    out = simplejson.dumps(data, separators=(',',':'))
  return HttpResponse(out, content_type='application/json')


### User Profiles ###


@login_required
@xsrf_required
def settings(request):
  account = models.Account.current_user_account
  if request.method != 'POST':
    nickname = account.nickname
    default_context = account.default_context
    default_column_width = account.default_column_width
    form = SettingsForm(initial={'nickname': nickname,
                                 'context': default_context,
                                 'column_width': default_column_width,
                                 'notify_by_email': account.notify_by_email,
                                 'notify_by_chat': account.notify_by_chat,
                                 })
    chat_status = None
    if account.notify_by_chat:
      try:
        presence = xmpp.get_presence(account.email)
      except Exception, err:
        logging.error('Exception getting XMPP presence: %s', err)
        chat_status = 'Error (%s)' % err
      else:
        if presence:
          chat_status = 'online'
        else:
          chat_status = 'offline'
    return respond(request, 'settings.html', {'form': form,
                                              'chat_status': chat_status})
  form = SettingsForm(request.POST)
  if form.is_valid():
    account.nickname = form.cleaned_data.get('nickname')
    account.default_context = form.cleaned_data.get('context')
    account.default_column_width = form.cleaned_data.get('column_width')
    account.notify_by_email = form.cleaned_data.get('notify_by_email')
    notify_by_chat = form.cleaned_data.get('notify_by_chat')
    must_invite = notify_by_chat and not account.notify_by_chat
    account.notify_by_chat = notify_by_chat
    account.fresh = False
    account.put()
    if must_invite:
      logging.info('Sending XMPP invite to %s', account.email)
      try:
        xmpp.send_invite(account.email)
      except Exception, err:
        # XXX How to tell user it failed?
        logging.error('XMPP invite to %s failed', account.email)
  else:
    return respond(request, 'settings.html', {'form': form})
  return HttpResponseRedirect(reverse(index))


@post_required
@login_required
@xsrf_required
def account_delete(request):
  account = models.Account.current_user_account
  account.delete()
  return HttpResponseRedirect(users.create_logout_url(reverse(index)))


@post_required
def incoming_chat(request):
  """/_ah/xmpp/message/chat/

  This handles incoming XMPP (chat) messages.

  Just reply saying we ignored the chat.
  """
  sender = request.POST.get('from')
  if not sender:
    logging.warn('Incoming chat without "from" key ignored')
  else:
    sts = xmpp.send_message([sender],
                            'Sorry, HOD does not support chat input')
    logging.debug('XMPP status %r', sts)
  return HttpResponse('')


@post_required
def incoming_mail(request, recipients):
  """/_ah/mail/(.*)

  Handle incoming mail messages.

  The issue is not modified. No reviewers or CC's will be added or removed.
  """
  try:
    _process_incoming_mail(request.raw_post_data, recipients)
  except InvalidIncomingEmailError, err:
    logging.debug(str(err))
  return HttpResponse('')


def _process_incoming_mail(raw_message, recipients):
  """Process an incoming email message."""
  recipients = [x[1] for x in email.utils.getaddresses([recipients])]

  # We can't use mail.InboundEmailMessage(raw_message) here.
  # See: http://code.google.com/p/googleappengine/issues/detail?id=2326
  # msg = mail.InboundEmailMessage(raw_message)
  # The code below needs to be adjusted when issue2326 is fixed.
  incoming_msg = email.message_from_string(raw_message)

  if 'X-Google-Appengine-App-Id' in incoming_msg:
    raise InvalidIncomingEmailError('Mail sent by App Engine')

  subject = incoming_msg.get('Subject', '')
  match = re.search(r'\(issue *(?P<id>\d+)\)$', subject)
  if match is None:
    raise InvalidIncomingEmailError('No issue id found: %s', subject)
  issue_id = int(match.groupdict()['id'])
  issue = models.Issue.get_by_id(issue_id)
  if issue is None:
    raise InvalidIncomingEmailError('Unknown issue ID: %d' % issue_id)
  sender = email.utils.parseaddr(incoming_msg.get('From', None))[1]

  body = None
  charset = None
  if incoming_msg.is_multipart():
    for payload in incoming_msg.get_payload():
      if payload.get_content_type() == 'text/plain':
        body = payload.get_payload(decode=True)
        charset = payload.get_content_charset()
        break
  else:
    body = incoming_msg.get_payload(decode=True)
    charset = incoming_msg.get_content_charset()
  if body is None or not body.strip():
    raise InvalidIncomingEmailError('Ignoring empty message.')

  # If the subject is long, this might come wrapped into more than one line.
  subject = ' '.join([x.strip() for x in subject.splitlines()])
  msg = models.Message(issue=issue, parent=issue,
                       subject=subject,
                       sender=db.Email(sender),
                       recipients=[db.Email(x) for x in recipients],
                       date=datetime.datetime.now(),
                       text=db.Text(body, encoding=charset),
                       draft=False)
  msg.put()

  # Add sender to reviewers if needed.
  all_emails = [str(x).lower()
                for x in [issue.owner.email()]+issue.reviewers+issue.cc]
  if sender.lower() not in all_emails:
    query = models.Account.all().filter('lower_email =', sender.lower())
    account = query.get()
    if account is not None:
      issue.reviewers.append(account.email)  # e.g. account.email is CamelCase
    else:
      issue.reviewers.append(db.Email(sender))
    issue.put()


@login_required
def xsrf_token(request):
  """/xsrf_token - Return the user's XSRF token.

  This is used by tools like git-cl that need to be able to interact with the
  site on the user's behalf.  A custom header named X-Requesting-XSRF-Token must
  be included in the HTTP request; an error is returned otherwise.
  """
  if not request.META.has_key('HTTP_X_REQUESTING_XSRF_TOKEN'):
    return HttpResponse('Please include a header named X-Requesting-XSRF-Token '
                        '(its content doesn\'t matter).', status=400)
  return HttpResponse(models.Account.current_user_account.get_xsrf_token(),
                      mimetype='text/plain')


  # On a non-standard instance, the default review server is changed to the
  # current hostname. This might give weird results when using versioned appspot
  # URLs (eg. 1.latest.codereview.appspot.com), but this should only affect
  # testing.
  if request.META['HTTP_HOST'] != 'codereview.appspot.com':
    review_server = request.META['HTTP_HOST']
    if request.is_secure():
      review_server = 'https://' + review_server
    source = source.replace('DEFAULT_REVIEW_SERVER = "codereview.appspot.com"',
                            'DEFAULT_REVIEW_SERVER = "%s"' % review_server)

  return HttpResponse(source, content_type='text/x-python')
