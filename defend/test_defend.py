from defend.middleware import handling_middleware
from django.contrib.auth.models import AnonymousUser, User
from django.test import TestCase, RequestFactory

factory = RequestFactory()
request = factory.get('http://localhost:8000/admin/login/?next=/admin/acunetix/x.bacKup')
request_method = "FAKE"
request.user = AnonymousUser()
request.META['SERVER_PROTOCOL'] = "HTTP/8.0"
request.META['SERVER_NAME'] = "www.fake.com"
request.META['HTTP_USER_AGENT'] = "nikto"
request.session['user_agent'] = "The original user agent"

handeling = handling_middleware()

# test checkHttpMethod
handeling.checkHttpMethod(request, request_method) # takes request and method value
#handeling.checkHttpMethod(request) # take only request as a parameter


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
