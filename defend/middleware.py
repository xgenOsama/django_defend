import sqlite3
import os.path
import datetime
import time
from django.contrib.sessions.middleware import SessionMiddleware
from django.http import HttpResponsePermanentRedirect


class handling_middleware():
    OK = 1
    ERROR = 0
    ATTACK = -1
    BAN = 100
    DEBUG = True
    DB = 'attackers.sqlite3'
    NEWLINE = '\n'

    def process_request(self, request):
        if self.isAttacker(request):
            if request.path != '/blocked':
                return HttpResponsePermanentRedirect('/blocked')
        self.checkHttpMethod(request, '')
        self.checkURI(request)
        self.nonExistingFile(request)
        self.checkHTTPVersion(request)
        self.checkSpeed(request)
        request.session.save()

    def process_response(self, request, response):
        self.checkFakeCookie(request, response)
        return response

    def checkHttpMethod(self, request, method=""):
        attack = "Incorrect HTTP method"
        score = 25
        if request.method and method == "":
            conn = self.getDb()
            db = conn.cursor()
            results = db.execute("SELECT method FROM acceptHttpMethod")
            found = False
            if request.method in [result[0] for result in results.fetchall()]:
                found = True
            if found:
                conn.close()
                return self.OK
            else:
                conn.close()
                attack = "Blacklisted HTTP method"
                self.attackDetected(attack, score, request)
                return self.ATTACK
        elif request.method and method != "":
            if request.method != method:
                self.attackDetected(attack, score, request)
                return self.ATTACK
        else:
            return self.ERROR
        return self.OK

    # check if the url contains a string flagged as an attacker
    def checkURI(self, request):
        attack = "Vulnerabiliry scanner in URL"
        score = 10
        if request.path:
            conn = self.getDb()
            db = conn.cursor()
            results = db.execute("SELECT string FROM denyUrlString")
            all_data = results.fetchall()
            for word in request.get_full_path().split('/'):
                for result in all_data:
                    if str(word.lower()) == str(result[0].lower()):
                        self.attackDetected(attack, score, request)
                        conn.close()
                        return self.ATTACK
        else:
            return self.ERROR
        return self.OK

    def checkHTTPVersion(self, request):
        attack = "Incorrect HTTP Version"
        score = 100
        if request.META['SERVER_PROTOCOL']:
            if request.META['SERVER_PROTOCOL'] != 'HTTP/1.1':
                self.attackDetected(attack, score, request)
                return self.ATTACK
        else:
            return self.ERROR
        return self.OK

    # check if the User-Agent is flagged as an attacker
    def checkUserAgent(self, request):
        attack = "Vulnerability scanner is user-agent"
        score = 100
        if request.META['HTTP_USER_AGENT']:
            conn = self.getDb()
            db = conn.cursor()
            results = db.execute("SELECT useragent FROM denyUserAgent")
            for result in results.fetchall():
                if request.META['HTTP_USER_AGENT'] in result[0]:
                    self.attackDetected(attack, score, request)
                    conn.close()
                    return self.ATTACK
        else:
            return self.ERROR
        if request.session['user_agent'] is not None and request.META['HTTP_USER_AGENT']:
            if request.session['user_agent'] != request.META['HTTP_USER_AGENT']:
                attack = "User-agent changed during user session"
                self.attackDetected(attack, score, request)
                return self.ATTACK
        return self.OK

    def checkHostname(self, request, hostname=None):
        attack = "Incorrect hostname"
        score = 100
        if hostname is not None:
            if not request.META['SERVER_NAME'] or request.META['SERVER_NAME'] != hostname:
                self.attackDetected(attack, score, request)
                return self.ATTACK
        else:
            return self.ERROR
        return self.OK

    # check files extensions "denied and excepted"
    def nonExistingFile(self, request):
        attack = "Non existing file"
        score = 5
        path = request.get_full_path()

        if request.path:
            path_splited = path.split('/')
            filee = path_splited[len(path_splited) - 1]
            filee = filee.split('.')
            filee_extension = filee[len(filee) - 1]
            conn = self.getDb()
            db = conn.cursor()
            extensions = db.execute("SELECT extension FROM denyExtension")
            denied_extensions = extensions.fetchall()
            for denied_ex in denied_extensions:
                if str(filee_extension.lower()) == str(denied_ex[0].lower()):
                    self.attackDetected(attack, score, request)
                    conn.close()
                    return self.ATTACK
        else:
            return self.ERROR
        return self.OK

    # check if the ip address for the same cookie has changed
    def checkConcurrentSession(self, requset):
        attack = "The Ip address of the user changed for the cookie"
        score = 25
        if requset.session['REMOTE_ADDR'] is not None and requset.META['REMOTE_ADDR']:
            if requset.session['REMOTE_ADDR'] != requset.META['REMOTE_ADDR']:
                self.attackDetected(attack, score, requset)
                return self.ERROR
        else:
            return self.ERROR
        return self.OK

    def checkFakeCookie(self, request, response, cookie_name="admin", cookie_value="false"):
        attack = "False cookie modified"
        score = 100
        conn = self.getDb()
        db = conn.cursor()
        result = db.execute("SELECT id from attacker WHERE attack='" + attack + "'")
        if result:
            return
        if request.COOKIES.has_key(cookie_name) and request.COOKIES[cookie_name] != cookie_value:
            self.attackDetected(attack, score, request)
            conn.close()
            return self.ATTACK
        else:
            max_age = 365 * 24 * 60 * 60
            expires = datetime.datetime.now() + datetime.timedelta(seconds=max_age)
            response.set_cookie(cookie_name, cookie_value, expires=expires.utctimetuple(), max_age=max_age)
            conn.close()
            return self.OK

    def checkFakeInput(self, request, input_name, value):
        attack = "Fake input modified"
        score = 100
        if input_name and value and request.POST[input_name]:
            if request.POST[input_name] != value:
                self.attackDetected(attack, score, request)
                return self.ATTACK
        else:
            return self.ERROR
        return self.OK

    # check if there is many requests per seconds
    # ab -n 1000 -c 5 http://127.0.0.1:8000/
    def checkSpeed(self, request):
        attack = "Too many requests per minute"
        score = 100
        if 'amount_requests_last_minute' not in request.session or 'amount_requests_last_minute_count' not in request.session:
            request.session['amount_requests_last_minute'] = int(round(time.time()))
            request.session['amount_requests_last_minute_count'] = 0
            request.session.set_expiry(300)  # 300 seconds 5 minutes
            request.session.save()
            request.session.modified = True
            # self.add_session_to_request(request)
        if request.session.get('amount_requests_last_minute') < (int(round(time.time())) - 60):
            request.session['amount_requests_last_minute_count'] = 0
            request.session['amount_requests_last_minute'] = int(round(time.time()))
            request.session.set_expiry(300)  # 300 seconds 5 minutes
            request.session.save()
            request.session.modified = True
            # self.add_session_to_request(request)
        request.session['amount_requests_last_minute'] += 1
        request.session['amount_requests_last_minute_count'] += 1
        if request.session['amount_requests_last_minute_count'] > 100:
            self.attackDetected(attack, score, request)
            return self.ATTACK
        return self.OK

    def isAttacker(self, request):
        ban_in_seconds = 60 * 60 * 24
        conn = self.getDb()
        db = conn.cursor()
        sessions_parameter = self.getSessionParameters(request)
        extra = " ip = '" + str(sessions_parameter['ip']) + "'"
        if sessions_parameter['user']:
            extra += " or user = '" + sessions_parameter['user'] + "'"
        if sessions_parameter['cookie']:
            extra += " or cookie = '" + sessions_parameter['user'] + "'"
        timestamp = str(int(round(time.time())) - ban_in_seconds)
        statment = db.execute(
            "SELECT SUM(score) AS total FROM attacker WHERE timestamp > " + timestamp + " AND " + extra)
        if statment.fetchone()[0] > self.BAN:
            conn.close()
            return True
        else:
            conn.close()
            return False

    def add_session_to_request(self, request):
        """Annotate a request object with a session"""
        middleware = SessionMiddleware()
        middleware.process_request(request)
        request.session.save()

    def getSessionParameters(self, request):
        """
        Get the session stuff: IP, user (optional), cookie (optional)
        :param request:
        :return:
        """
        user = ''
        if request.user.is_authenticated():
            user = request.user.email
        ip = '127.0.0.1'
        if request.META['REMOTE_ADDR'] is not None:
            ip = request.META['REMOTE_ADDR']
        cookie = ''
        if request.COOKIES:
            for key in request.COOKIES.iterkeys():  # "for key in request.REQUEST" works too.
                val = request.COOKIES.get(key)
                cookie += '%s=%s&' % (key, val)
        return {'user': user, 'ip': ip, 'cookie': cookie}

    def attackDetected(self, attack, score, request):
        self.logAttack(attack, score, request)
        alert_info = "The last attack from the user was: " + attack
        if score >= self.BAN:
            alert_info += ". The user was automatically mark as an attacker"
        else:
            alert_info += ". The user was mark as an attacker because of a series of events"
        session_parameters = self.getSessionParameters(request)
        alert_info += "." + self.NEWLINE + "Attacker details:" + self.NEWLINE
        alert_info += "IP: " + session_parameters['ip'] + self.NEWLINE
        alert_info += "User: " + str(session_parameters['user']) + self.NEWLINE
        alert_info += "Cookie: " + str(session_parameters['cookie']) + self.NEWLINE
        alert_info += "File: " + str(request.META['SCRIPT_NAME']) + self.NEWLINE
        alert_info += "URI: " + request.path + self.NEWLINE
        params = ''
        # for key in request.REQUEST.iterkeys():  # "for key in request.REQUEST" works too.
        #     # Add filtering logic here.
        #     valuelist = request.REQUEST.getlist(key)
        #     params += ['%s=%s&' % (key, val) for val in valuelist]
        alert_info += "Parameter: " + params + self.NEWLINE
        self.alertAdmin(alert_info)

    # Log the attack into the database
    def logAttack(self, attack, score, request):
        conn = self.getDb()
        db = conn.cursor()
        session_parameters = self.getSessionParameters(request)
        params = ''
        # for key in request.REQUEST.iterkeys():  # "for key in request.REQUEST" works too.
        #     # Add filtering logic here.
        #     valuelist = request.REQUEST.getlist(key)
        #     params += ['%s=%s&' % (key, val) for val in valuelist]
        data = [(
            str(datetime.datetime.now()), 'defend', session_parameters['ip'], session_parameters['user'], str(session_parameters['cookie']),
            str(request.META['SCRIPT_NAME']), request.get_full_path(), params, attack, score)]
        db.executemany(
            "INSERT INTO attacker (timestamp, application, ip, user, cookie, filename, uri, parameter, attack, score) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            data)
        conn.commit()
        conn.close()

    def alertAdmin(self, alert_info):
        if self.DEBUG:
            print alert_info

    def getDb(self):
        """
        create the database , tables and inserting data if the database is not exists
        and return the connection cursor to create and inserting data
        :return: db
        """
        if not os.path.exists(self.DB):
            conn = sqlite3.connect(self.DB)
            db = conn.cursor()
            db.execute(
                "CREATE TABLE attacker (id INTEGER PRIMARY KEY, timestamp TEXT, application TEXT, ip TEXT, user TEXT, cookie TEXT, filename TEXT, uri TEXT, parameter TEXT, attack TEXT, score INTEGER)")
            db.execute("CREATE TABLE denyUserAgent (id INTEGER PRIMARY KEY, useragent TEXT)")
            db.execute(
                "INSERT INTO denyUserAgent (useragent) VALUES ('burpcollaborator'), ('dirbuster'), ('nessus'), ('nikto'), ('nmap'), ('paros'), ('python-urllib'), ('qualysguard'), ('sqlmap'), ('useragent'), ('w3af')")
            db.execute("CREATE TABLE denyUrlString (id INTEGER PRIMARY KEY, string TEXT)")
            db.execute(
                "INSERT INTO denyUrlString (string) VALUES ('acunetix'), ('burpcollab'), ('nessus'), ('nikto'), ('parosproxy'), ('qualys'), ('vega'), ('ZAP')")
            db.execute("CREATE TABLE acceptHttpMethod (id INTEGER PRIMARY KEY, method TEXT)")
            db.execute("INSERT INTO acceptHttpMethod (method) VALUES ('HEAD'), ('GET'), ('POST'), ('OPTIONS')")
            db.execute("CREATE TABLE denyExtension (id INTEGER PRIMARY KEY, extension TEXT)")
            db.execute(
                "INSERT INTO denyExtension (extension) VALUES ('bac'), ('BAC'), ('backup'), ('BACKUP'), ('bak'), ('BAK'), ('conf'), ('cs'), ('csproj'), ('inc'), ('INC'), ('ini'), ('java'), ('log'), ('lst'), ('old'), ('OLD'), ('orig'), ('ORIG'), ('sav'), ('save'), ('temp'), ('tmp'), ('TMP'), ('vb'), ('vbproj')")
            conn.commit()
            conn.close()
        else:
            conn = sqlite3.connect(self.DB)
        return conn
