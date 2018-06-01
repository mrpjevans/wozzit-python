from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import requests
import json
import pync
import logging
import emails
import platform
if platform.system() == 'Darwin':
    import pync
if platform.system() == 'Windows':
    from win10toast import ToastNotifier # pylint: disable=all
if platform.system() == 'Linux':
    import notify2
import haver

# Stack of event listeners
actions = []

# SMTP Settings for sending emails
smtpHost = None
smtpPort = None
smtpSSL = True
smtpUsername = None
smtpPassword = None
smtpFromName = None
smtpFromEmail = None

# Callback holder for errors
onError =  None

# Our very simple HTTP server
class WozzitRequestHandler(BaseHTTPRequestHandler):
    
    def _set_headers(self, status=200):
        self.send_response(status)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

    # Currently GET has no function, but must be implemented
    def do_GET(self):
        logging.info('GET received from %s', self.client_address[0])
        logging.info('Not found')
        h = haver.NotFound()
        self._set_headers()
        self.wfile.write(h.toJSON())

    def do_HEAD(self):
        self._set_headers()

    # You send a haver to the server using HTTP POST with a application/json content-type
    def do_POST(self):
        logging.info('POST received from %s', self.client_address[0])
        contentLength = int(self.headers['Content-Length'])
        rawData = self.rfile.read(contentLength)
        logging.debug(rawData)
        receipt = processActions(rawData, self.client_address[0])
        self._set_headers()
        self.wfile.write(receipt.toJSON())
    
    # PUT is not implemented
    def do_PUT(self):
        logging.info('PUT received from %s', self.client_address[0])
        logging.debug('Not implemented')
        h = haver.NotImplemented()
        self._set_headers()
        self.wfile.write(h.toJSON())

    # PATCH is not implemented
    def do_PATCH(self):
        logging.info('PATCH received from %s', self.client_address[0])
        logging.debug('Not implemented')
        h = haver.NotImplemented()
        self._set_headers()
        self.wfile.write(h.toJSON())

    # Delete is not implemented
    def do_DELETE(self):
        logging.debug('DELETE received from %s', self.client_address[0])
        logging.debug('Not implemented')
        h = haver.NotImplemented()
        self._set_headers()
        self.wfile.write(h.toJSON())

    def log_message(self, format, *args):
        logging.info("%s %s" % (self.client_address[0],format%args))

#
def setOptions(opts={}):
    global port, ip, smtpHost, smtpPort, smtpSSL, smtpUsername, smtpPassword, smtpFromName, smtpFromEmail, onError
    
    # Server Options
    port = opts['port'] if opts.has_key('port') else 10207
    ip = opts['ip'] if opts.has_key('ip') else ''

    # Email Options
    smtpHost = opts['smtpHost'] if opts.has_key('smtpHost') else 'localhost'
    smtpPort = opts['smtpPort'] if opts.has_key('smtpPort') else 25
    smtpSSL = opts['smtpSSL'] if opts.has_key('smtpSSL') else False
    smtpUsername = opts['smtpUsername'] if opts.has_key('smtpUsername') else None
    smtpPassword = opts['smtpPassword'] if opts.has_key('smtpPassword') else None
    smtpFromName = opts['smtpFromName'] if opts.has_key('smtpFromName') else None
    smtpFromEmail = opts['smtpFromEmail'] if opts.has_key('smtpFromEmail') else None

    # Error handler
    onError = opts['onError'] if opts.has_key('onError') else None

    # Set logging
    if opts.has_key('loglevel'):
        logDict = {'info': logging.INFO, 'warning': logging.WARNING, 'debug': logging.DEBUG, 'none': logging.NOTSET}
        level = logDict[opts['loglevel']]
    else:
        level = logging.INFO
    format = ('%(asctime)s [%(levelname)s] %(message)s')
    logging.basicConfig(level=level,format=format)

# Our main function - configures and starts the server
def listen(opts=None):
    global port, ip

    if opts is not None:
        setOptions(opts)

    # Configure and start server
    httpd = HTTPServer((ip, port), WozzitRequestHandler)
    ip = '*' if ip == '' else ip 
    logging.info('Wozzit Node listening on %s:%s', ip, str(port))

    try:
        httpd.serve_forever()

    except KeyboardInterrupt:
        logging.info('^C received, shutting down the web server')
        httpd.socket.close()

# Send a haver to another node
def send(h, to):

    # Send request
    logging.info('Sending to %s', to)
    r = requests.post(url = to, json = h.toJSON())
    if r.status_code != 200:
        logging.warn('Failed to send: %s', r.status_code)
        if(onError is not None):
            onError('send', r)

    # Attempt to parse response into haver message
    logging.debug(r)
    try:
        json = r.json()
        logging.debug(json)
    except:
        logging.error('Invalid JSON returned')
        if(onError is not None):
            onError('invalidresponse', r)
        return False

    response = haver.Message(json)

    return response

# Validate incoming data and then work out how to respond
def processActions(raw_data, ip):

    # Parse the haver
    h = haver.Message()
    result = h.loads(raw_data, ip)

    if result != True:
        logging.warning('Rejecting haver: %s', result.payload['message'])
        return result
    
    logging.debug('Haver accepted')
    logging.debug(h.toJSON())
        
    if len(actions) == 0:
        logging.debug('No actions')
        return haver.NotImplemented()
    
    # Go through each action and make sure all criteria match
    for action in actions:
        logging.debug('Testing action %s', action['action'])
        if __actionMatch(action['match'], h):
            logging.debug('Matched action %s', action['action'])
            __processAction(action, h)
    return haver.Receipt()

# Perform actions. We have some built-in but mostly it will be callbacks
def __processAction(action, h):
    if action['action'] == 'log':
        __log(h.toJSON())
    elif action['action'] == 'cb':
        logging.debug('Invoking callback')
        action['cb'](action, h)
    elif action['action'] == 'forward':
        __forward(action, h)
    elif action['action'] == 'desktop':
        __desktopNotification(action, h)
    elif action['action'] == 'email':
        __sendEmail(action, h)

# Go through each action condition and make sure all match before processing further
def __actionMatch(match, h):

    if match != '*':
        for key, value in match.iteritems():
            if hasattr(h, key) == False or getattr(h,key) != value:
                logging.debug('Failed action condition %s = %s', key, value)
                return False
            logging.debug('Matched action condition %s = %s', key, value)
    else:
        logging.debug('Matched on wildcard')

    return True


# Add event listeners
def addLog(match="*"):
    actions.append({'match': match, 'action': 'log'})

def addListener(match="*", callback=None):
    actions.append({'match': match, 'action': 'cb', 'cb': callback})

def addForwarder(match, to):
    actions.append({'match': match, 'action': 'forward', 'to': to})

def addDesktopNotification(match, message):
    actions.append({'match': match, 'action': 'desktop', 'message': message})

def addEmail(match, toName, toEmail, subject, message):
    actions.append({'match': match, 'action': 'email', 'toName': toName, 'toEmail': toEmail, 'subject': subject, 'message': message})


# Built-in actions
def __log(s):
    print '[wozzit] ' + s

def __forward(action, h):
    global onError
    logging.info('Forwarding have to %s', action['to'])
    data = h.toDict()
    r = requests.post(url = action['to'], json = data)
    if r.status_code != 200:
        logging.warn('Failed to forward: %s', r.status_code)
        logging.debug(r)
        if(onError is not None):
            onError('forward', r)

def __desktopNotification(action, h):
    logging.info('Triggering desktop notification')
    if platform.system() == 'Darwin':
        pync.notify(action['message'], title='Wozzit', sound='default')
    elif platform.system() == 'Windows':
        toaster = ToastNotifier()
        toaster.show_toast("Wozzit", action['message'])
    elif platform.system() == 'Linux':
        notify2.init('Wozzit')
        n = notify2.Notification('Wozzit', action['message'])
        n.show()

def __sendEmail(action, h):
    global smtpHost, smtpPort, smtpSSL, smtpUsername, smtpPassword, smtpFromName, smtpFromEmail, onError

    if smtpHost is None:
        logging.warn('SMTP not configured')
        return

    message = emails.Message(
                   text= action['message'],
                   subject= action['subject'],
                   mail_from=(smtpFromName, smtpFromEmail))
    
    smtpOpts = {'host':smtpHost, 'port': smtpPort, 'ssl': smtpSSL}
    if smtpUsername != None:
        smtpOpts['user'] = smtpUsername
    if smtpPassword != None:
        smtpOpts['password'] = smtpPassword

    logging.info('Sending email')
    r = message.send(to=(action['toName'], action['toEmail']), smtp=smtpOpts)
    if r.status_code != 250:
        logging.error("Failed to send email: %s", r.status_text)
        logging.debug(r)
        if(onError is not None):
            onError('sendEmail', r)
    else:
        logging.debug('Successfully sent email')