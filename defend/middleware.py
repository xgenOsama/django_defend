import sqlite3
import os.path
import datetime


class handling_middleware():
    OK = 1
    ERROR = 0
    ATTACK = -1
    BAN = 100
    DEBUG = True
    DB = '/home/robot/marvel/django_defend/defend/attackers.sqlite3'
    NEWLINE = '\n'

    def process_request(self, request):
        self.checkHttpMethod(request, '')
        self.checkURI(request)
        self.checkHTTPVersion(request)

    def checkHttpMethod(self, request, method=""):
        attack = "Incorrect HTTP method"
        score = 25
        if request.method and method == "":
            db = self.getDb().cursor()
            results = db.execute("SELECT method FROM acceptHttpMethod")
            found = False
            if request.method in [result[0] for result in results.fetchall()]:
                found = True
                results.close()
            if found:
                return self.OK
            else:
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
            db = self.getDb().cursor()
            results = db.execute("SELECT string FROM denyUrlString")
            all_data = results.fetchall()
            for word in request.get_full_path().split('/'):
                for result in all_data:
                    if str(word.lower()) == str(result[0].lower()):
                        self.attackDetected(attack, score, request)
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
        if request.COOKIES.get('logged_in_status') is not None:
            cookie = request.COOKIES.get('logged_in_status')
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
            str(datetime.datetime.now()), 'defend', session_parameters['ip'], '', str(session_parameters['cookie']),
            str(request.META['SCRIPT_NAME']), request.get_full_path(), params, attack, score)]
        db.executemany(
            "INSERT INTO attacker (timestamp, application, ip, user, cookie, filename, uri, parameter, attack, score) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            data)
        conn.commit()

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
        else:
            conn = sqlite3.connect(self.DB)
        return conn
