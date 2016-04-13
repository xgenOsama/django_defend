from defend.middleware import handling_middleware
from django.contrib.auth.models import AnonymousUser, User
from django.test import TestCase
from django.test.client import RequestFactory
from django.core.handlers.base import BaseHandler
import os.path
import time
import datetime
import urllib2
from defend.views import index


# you should modifying ban_in second value in isAttacter method to 0 to prefore test

class RequestMock(RequestFactory):
    def request(self, **request):
        "Construct a generic request object."
        request = RequestFactory.request(self, **request)
        handler = BaseHandler()
        handler.load_middleware()
        request.csrf_processing_done = True
        for middleware_method in handler._request_middleware:
            if middleware_method(request):
                raise Exception("Couldn't create request mock object - "
                                "request middleware returned a response")
        return request


factory = RequestMock()
request = factory.get('http://localhost:8000/admin/login/?next=/admin/acunetix/x.bacKup')
request_method = "FAKE"
request.user = AnonymousUser()
request.META['SERVER_PROTOCOL'] = "HTTP/8.0"
request.META['SERVER_NAME'] = "www.fake.com"
request.META['HTTP_USER_AGENT'] = "nikto"
request.session['user_agent'] = "The original user agent"

handeling = handling_middleware()

# test checkHttpMethod
handeling.checkHttpMethod(request, request_method)  # takes request and method value
# handeling.checkHttpMethod(request) # take only request as a parameter


# test checkURI method
handeling.checkURI(request)

# test checkHTTPVersion takes only request as a parameter
handeling.checkHTTPVersion(request)

# test checkUserAgent takes only request as a parameter
handeling.checkUserAgent(request)

# test checkHostname takes only request as a parameter
handeling.checkHostname(request, 'www.example.com')

#  Pre-execution control: Forced browsing: invalid URI
handeling.attackDetected("Invalid URI (potential path traversal)", 20, request)

# Pre-execution control: Forced browsing: check if a non-authenticated user is accessing a privileged resource without permission
# if not request.user:
handeling.attackDetected("Existing resource accessed by a non-authenticated user", 20, request)

# Pre-execution control: Forced browsing: check if an authenticated user is accessing a privileged resource without permission
# if not request.user and not request.user.is_authenticated():
handeling.attackDetected("Authenticated user without permission", 20, request)

# Pre-execution control: Trap: check if a user is accessing a fake robots.txt entry
handeling.attackDetected("Fake robots.txt entry", 100, request)

# Pre-execution control: Trap: check if a user is accessing a fake hidden URL within a document
handeling.attackDetected("Fake hidden URL access", 100, request)

# Execution control: check if any parameter is missing
if not request.POST.has_key("this_parameter_should_not_be_missing"):
    handeling.attackDetected("Missing parameter", 100, request)

# Execution control: check if there are any extra parameters
if len(request.POST.keys()) >= 999:
    handeling.attackDetected("Extra parameters", 100, request)

# Execution control: check if they are sending unexpected values on any parameter
if not request.POST.has_key('id') or not request.POST.get('id').isnumeric():
    handeling.attackDetected("Unexpected value", 100, request)

# Execution control: check if the canonical path differs from the path entered by the user (path traversal attack)
tmp = "/somedir/.././somefile"
if os.path.realpath(tmp) != tmp:
    handeling.attackDetected("Path traversal detected", 100, request)

# Execution control: check if the anti Cross-Site Request Forgery (CSRF) token differs from the original
handeling.attackDetected("Anti-XSRF token invalid", 100, request)

# Execution control: check if the origin is forbidden for the user's session
# if isGeoLocationForbidden(request.session):
handeling.attackDetected("Geo location is forbidden", 100, request)

# if login(user,pass):
if datetime.time.hour < 8 or datetime.time.hour > 20:
    handeling.alertAdmin("The user logged in outside business hours")
# Execution control: check if the user triggered an unexpected catch statement
def inverse(x):
    if not x:
        raise Exception('"Division by zero.')
    return 1/x
try:
    print inverse(0) + "\n"
except:
    handeling.attackDetected("Exception divided by zero should never happen", 20, request)

# Execution control: check if they are looping through passwords
# if login(user,password):
handeling.attackDetected("Password attempt", 10, request)

# Post-execution control: check if the fake secret admin acccount has been leaked
response = "0,secrethiddenadminaccount,1..."
if "secrethiddenadminaccount" in response:
    handeling.attackDetected("Passwords leaked", 100, request)

# Post-execution control: check if the fake secret directory  has been leaked
response = "/var/www/html/secrethiddendirectory"
if "secrethiddendirectory" in response:
    handeling.attackDetected("Files leaked", 100, request)

# Post-execution control: check if the request took too much time
start_time = int(time.time())
if (start_time + 0) <= int(time.time()):
    handeling.attackDetected("Too much time", 100, request)

# test nonExistingFile takes only request as a parameter
handeling.nonExistingFile(request)

# test check concurrent session
request.session['REMOTE_ADDR'] = "127.0.0.1"
request.META['REMOTE_ADDR'] = "127.0.0.2"
handeling.checkConcurrentSession(request)

# check fake input
request = factory.post('http://localhost:8000/', {"input_name": "i am value"})
handeling.checkFakeInput(request, 'input_name', 'i am valu')

# making 200 request to check speed of requess per time
request = factory.get('http://localhost:8000/')
for i in xrange(1, 200):
    handeling.checkSpeed(request)
