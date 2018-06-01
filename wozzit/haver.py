import json

class Message:
    # A 'Haver' or message past from Wozzit node to Wozzit node
    # This class' concerns are parsing, validating and rendering messages

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
        
        haver = data['wozzit']

        if haver.has_key('protocol') == False:
            return Error(400, "No protocol")

        self.protocol = tuple(haver['protocol'])
        if self.protocol < self.minProtocol or self.protocol > self.maxProtocol:
            return Error(400, "Unsupported protocol")

        if haver.has_key('schema') == False:
            return Error(400, "No schema")

        self.schema = haver['schema']

        if haver.has_key('version') == False:
            return Error(400, "No version")

        self.version = haver['version']

        if haver.has_key('psk') != False:
            self.psk = haver['psk']

        if haver.has_key('payload') != False:
            self.payload = haver['payload']

        if ip is not None:
            self.ip = ip

        return True

class Error(Message):
    # Override to create an 'error' Haver
    def __init__(self, code=500, message="Error"):
        self.error(code, message)

class NotFound(Message):
    # Not found
    def __init__(self):
        self._reset()
        self.error(404, 'Not found')

class NotImplemented(Message):
    # HTTP method not implemented
    def __init__(self):
        self._reset()
        self.error(501, 'Not implemented')

class Receipt(Message):
    # Acknowledgement of a haver received
    # I expect this to become more useful in future
    def __init__(self):
        self._reset()
        self.schema = 'wozzit.receipt'
