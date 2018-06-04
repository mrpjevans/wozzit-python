from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import requests, json, logging, emails, platform

if platform.system() == 'Darwin':
    import pync
if platform.system() == 'Windows':
    from win10toast import ToastNotifier # pylint: disable=all
if platform.system() == 'Linux':
    import notify2

# Stack of event listeners
actions = []

# SMTP Settings for sending emails
smtp = {
    "host": None,
    "port": None,
    "SSL": None,
    "username": None,
    "password": None,
    "fromName": None,
    "fromEmail": None
}

# Callback holder for errors
onError =  None

# Our very simple HTTP server
class __WozzitRequestHandler(BaseHTTPRequestHandler):
    
    def _set_headers(self, status=200):
        self.send_response(status)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

    # Currently GET has no function, but must be implemented
    def do_GET(self):
        logging.info('GET received from %s', self.client_address[0])
        logging.info('Not found')
        msg = NotFoundMessage()
        self._set_headers()
        self.wfile.write(msg.toJSON())

    def do_HEAD(self):
        self._set_headers()

    # You send a message to the server using HTTP POST with a application/json content-type
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
        msg = NotImplementedMessage()
        self._set_headers()
        self.wfile.write(msg.toJSON())

    # PATCH is not implemented
    def do_PATCH(self):
        logging.info('PATCH received from %s', self.client_address[0])
        logging.debug('Not implemented')
        msg = NotImplementedMessage()
        self._set_headers()
        self.wfile.write(msg.toJSON())

    # Delete is not implemented
    def do_DELETE(self):
        logging.debug('DELETE received from %s', self.client_address[0])
        logging.debug('Not implemented')
        msg = NotImplementedMessage()
        self._set_headers()
        self.wfile.write(msg.toJSON())

    def log_message(self, format, *args):
        logging.info("%s %s" % (self.client_address[0],format%args))

# Options, options, options
def setOptions(opts={}):
    global port, ip, smtp, onError
    
    # Server Options
    port = opts['port'] if opts.has_key('port') else 10207
    ip = opts['ip'] if opts.has_key('ip') else ''

    # Email Options
    smtp['host'] = opts['smtp']['host'] if opts.has_key('smtp') and opts['smtp'].has_key('host') else 'localhost'
    smtp['port'] = opts['smtp']['port'] if opts.has_key('smtp') and opts['smtp'].has_key('port') else 25
    smtp['SSL'] = opts['smtp']['SSL'] if opts.has_key('smtp') and opts['smtp'].has_key('SSL') else False
    smtp['username'] = opts['smtp']['username'] if opts.has_key('smtp') and opts['smtp'].has_key('username') else None
    smtp['password'] = opts['smtp']['password'] if opts.has_key('smtp') and opts['smtp'].has_key('password') else None
    smtp['fromName'] = opts['smtp']['fromName'] if opts.has_key('smtp') and opts['smtp'].has_key('fromName') else None
    smtp['fromEmail'] = opts['smtp']['fromEmail'] if opts.has_key('smtp') and opts['smtp'].has_key('fromEmail') else None
    
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

# Our main function - configures and starts the server (can also set options at this point)
def listen(opts={}):
    global port, ip

    setOptions(opts)
    
    # Configure and start server
    httpd = HTTPServer((ip, port), __WozzitRequestHandler)
    ip = '*' if ip == '' else ip 
    logging.info('Wozzit Node listening on %s:%s', ip, str(port))

    try:
        httpd.serve_forever()

    except KeyboardInterrupt:
        logging.info('^C received, shutting down the web server')
        httpd.socket.close()

# Send a message to another node
def send(msg, to):

    # Send request
    logging.info('Sending to %s', to)
    r = requests.post(url = to, json = msg.toJSON())
    if r.status_code != 200:
        logging.warn('Failed to send: %s', r.status_code)
        if(onError is not None):
            onError('send', r)

    # Attempt to parse response into message
    logging.debug(r)
    try:
        json = r.json()
        logging.debug(json)
    except:
        logging.error('Invalid JSON returned')
        if(onError is not None):
            onError('invalidresponse', r)
        return False

    response = Message(json)

    return response

# Validate incoming data and then work out how to respond
def processActions(raw_data, ip):

    # Parse the message
    msg = Message()
    result = msg.loads(raw_data, ip)

    if result != True:
        logging.warning('Rejecting message: %s', result.payload['message'])
        return result
    
    logging.debug('Message accepted')
    logging.debug(msg.toJSON())
        
    if len(actions) == 0:
        logging.debug('No actions')
        return NotImplementedMessage()
    
    # Go through each action and make sure all criteria match
    for action in actions:
        logging.debug('Testing action %s', action['action'])
        if __actionMatch(action['match'], msg):
            logging.debug('Matched action %s', action['action'])
            __processAction(action, msg)
    return ReceiptMessage()

# Perform actions. We have some built-in but mostly it will be callbacks
def __processAction(action, msg):
    if action['action'] == 'log':
        __log(msg.toJSON())
    elif action['action'] == 'cb':
        logging.debug('Invoking callback')
        action['cb'](action, msg)
    elif action['action'] == 'forward':
        __forward(action, msg)
    elif action['action'] == 'desktop':
        __desktopNotification(action, msg)
    elif action['action'] == 'email':
        __sendEmail(action, msg)

# Go through each action condition and make sure all match before processing further
def __actionMatch(match, msg):

    if match != '*':
        for key, value in match.iteritems():
            if hasattr(msg, key) == False or getattr(msg, key) != value:
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

def __forward(action, msg):
    global onError
    logging.info('Forwarding message to %s', action['to'])
    data = msg.toDict()
    r = requests.post(url = action['to'], json = data)
    if r.status_code != 200:
        logging.warn('Failed to forward: %s', r.status_code)
        logging.debug(r)
        if(onError is not None):
            onError('forward', r)

def __desktopNotification(action, msg):
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

def __sendEmail(action, msg):
    global smtp, onError

    if smtp['host'] is None:
        logging.warn('SMTP not configured')
        return

    message = emails.Message(
                   text= action['message'],
                   subject= action['subject'],
                   mail_from=(smtp['fromName'], smtp['fromEmail']))
    print smtp
    smtpOpts = {'host':smtp['host'], 'port': smtp['port'], 'ssl': smtp['SSL']}
    if smtp['username'] != None:
        smtpOpts['user'] = smtp['username']
    if smtp['password'] != None:
        smtpOpts['password'] = smtp['password']

    logging.info('Sending email')
    r = message.send(to=(action['toName'], action['toEmail']), smtp=smtpOpts)
    if r.status_code != 250:
        logging.error("Failed to send email: %s", r.status_text)
        logging.debug(r)
        if(onError is not None):
            onError('sendEmail', r)
    else:
        logging.debug('Successfully sent email')


# A message past from Wozzit node to Wozzit node
# This class' concerns are parsing, validating and rendering messages
class Message:

    def __init__(self, json=None):
        self._reset()
        if json is not None:
            self.loads(json)

    # Set up instance-scoped variables
    def _reset(self):

        # Protocol allows for future versions of Havers. Uses semantic versioning in tuple form.
        # Min and max represent the boundaries of what we can support.
        self.protocol = (0, 0, 1)
        self.minProtocol = (0, 0, 1)
        self.maxProtocol = (0, 0, 1)

        # Schema is a reverse-domain notation identifying what we can expect from the payload.
        # The default is wozzit.null which means 'nothing'.
        self.schema = "wozzit.null"

        # Schemas can be versioned. Whether the version is supported or not is out-of-scope.
        self.version = 1

        # For incoming havers, this records the IP address of the sender
        self.ip = None

        # Pre-shared key. Provides a layer of security. Content is unrestricted.
        self.psk = None

        # Payload: The actual data (if any) - the content is dictated by the schema.
        self.payload = None        
    
    # Serialise this instance into a dict object
    def toDict(self):
        output = {'wozzit': {'protocol': self.protocol, 'schema': self.schema, 'version': self.version}}
        if self.payload is not None:
            output['payload'] = self.payload
        return output

    # Serialize this instance into JSON
    def toJSON(self):
        output = self.toDict()
        return json.dumps(output)
    
    # Shortcut to set up an error response
    def error(self, code=500, message="Error"):
        self._reset()
        self.schema = 'wozzit.error'
        self.payload = {'code': code, 'message': message}
    
    # Parse raw JSON-formatted data into this instance, sanity checking as we go
    def loads(self, raw_data, ip=None):

        self._reset()
        if type(raw_data) is dict:
            data = raw_data
        else:
            data = json.loads(raw_data)
        
        if data.has_key('wozzit') == False:
            return Error(400, 'Bad request')
        
        msg = data['wozzit']

        if msg.has_key('protocol') == False:
            return Error(400, "No protocol")

        self.protocol = tuple(msg['protocol'])
        if self.protocol < self.minProtocol or self.protocol > self.maxProtocol:
            return Error(400, "Unsupported protocol")

        if msg.has_key('schema') == False:
            return Error(400, "No schema")

        self.schema = msg['schema']

        if msg.has_key('version') == False:
            return Error(400, "No version")

        self.version = msg['version']

        if msg.has_key('psk') != False:
            self.psk = msg['psk']

        if msg.has_key('payload') != False:
            self.payload = msg['payload']

        if ip is not None:
            self.ip = ip

        return True

class ErrorMessage(Message):
    # Override to create an 'error' Haver
    def __init__(self, code=500, message="Error"):
        self.error(code, message)

class NotFoundMessage(Message):
    # Not found
    def __init__(self):
        self._reset()
        self.error(404, 'Not found')

class NotImplementedMessage(Message):
    # HTTP method not implemented
    def __init__(self):
        self._reset()
        self.error(501, 'Not implemented')

class ReceiptMessage(Message):
    # Acknowledgement of a haver received
    # I expect this to become more useful in future
    def __init__(self):
        self._reset()
        self.schema = 'wozzit.receipt'
