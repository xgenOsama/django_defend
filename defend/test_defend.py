from defend.middleware import handling_middleware
from django.contrib.auth.models import AnonymousUser, User
from django.test import TestCase
from django.test.client import RequestFactory
from django.core.handlers.base import BaseHandler
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

handeling = handling_middleware()

# test checkHttpMethod
handeling.checkHttpMethod(request, request_method)  # takes request and method value
# handeling.checkHttpMethod(request) # take only request as a parameter


# test checkURI method
handeling.checkURI(request)


# test checkHTTPVersion takes only request as a parameter
handeling.checkHTTPVersion(request)


# test checkHostname takes only request as a parameter
handeling.checkHostname(request, 'www.example.com')


# test nonExistingFile takes only request as a parameter
handeling.nonExistingFile(request)

# test check concurrent session
request.session['REMOTE_ADDR'] = "127.0.0.1"
request.META['REMOTE_ADDR'] = "127.0.0.2"
handeling.checkConcurrentSession(request)

