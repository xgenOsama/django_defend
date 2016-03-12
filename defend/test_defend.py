from defend.middleware import handling_middleware
from django.contrib.auth.models import AnonymousUser, User
from django.test import TestCase, RequestFactory
from django.core.handlers.base import BaseHandler
import urllib2
import thread
from threading import Thread
import time


class RequestMock(RequestFactory):
    def request(self, **request):
        "Construct a generic request object."
        request = RequestFactory.request(self, **request)
        handler = BaseHandler()
        handler.load_middleware()
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


# test nonExistingFile takes only request as a parameter
handeling.nonExistingFile(request)

# test check concurrent session
request.session['REMOTE_ADDR'] = "127.0.0.1"
request.META['REMOTE_ADDR'] = "127.0.0.2"
handeling.checkConcurrentSession(request)

# making 1000 request to check speed of requess per time
for i in xrange(1,200):
	urllib2.urlopen("http://localhost:8000/").read()
	
# test checkSpeed takes only request as a prameter
handeling.checkSpeed(request)
