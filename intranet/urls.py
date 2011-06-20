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

"""URL mappings for HOD package."""

# NOTE: Must import *, since Django looks for things here, e.g. handler500.
from django.conf.urls.defaults import *
import django.views.defaults


urlpatterns = patterns(
    'intranet.views',
    (r'^$', 'index'),
    (r'^passengers$', 'passengers'),
    (r'^passengers_edit$', 'passengers_edit'),
    (r'^passengers_new$', 'passengers_new'),
    (r'^passengers_delete$', 'passengers_delete'),
    (r'^rooms$', 'rooms'),
    (r'^rooms_edit$', 'rooms_edit'),
    (r'^rooms_new$', 'rooms_new'),
    (r'^rooms_delete$', 'rooms_delete'),
    (r'^services$', 'services'),
    (r'^services_edit$', 'services_edit'),
    (r'^services_new$', 'services_new'),
    (r'^services_delete$', 'services_delete'),
    (r'^lodgings$', 'lodgings'),
    (r'^lodgings_edit$', 'lodgings_edit'),
    (r'^lodgings_new$', 'lodgings_new'),
    (r'^lodgings_delete$', 'lodgings_delete'),
    (r'^settings$', 'settings'),
    (r'^account_delete$', 'account_delete'),
    (r'^account$', 'account'),
    (r'^_ah/xmpp/message/chat/', 'incoming_chat'),
    (r'^_ah/mail/(.*)', 'incoming_mail'),
    (r'^xsrf_token$', 'xsrf_token'),
    (r'^search$', 'search'),
    )