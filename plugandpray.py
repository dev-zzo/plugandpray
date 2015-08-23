import argparse
import sys
import socket
import struct
import xml.etree.ElementTree as ElementTree

UPNP_DEVICE_NS = 'urn:schemas-upnp-org:device-1-0'
UPNP_SERVICE_NS = 'urn:schemas-upnp-org:service-1-0'
UPNP_CONTROL_NS = 'urn:schemas-upnp-org:control-1-0'
# Used by Element.find()
UPNP_NS_MAP = {
    'device': UPNP_DEVICE_NS,
    'service': UPNP_SERVICE_NS,
    'control': UPNP_CONTROL_NS,
}
# Used by writer
ElementTree.register_namespace('soap', 'http://schemas.xmlsoap.org/soap/envelope/')
ElementTree.register_namespace('device', UPNP_DEVICE_NS)
ElementTree.register_namespace('service', UPNP_SERVICE_NS)
ElementTree.register_namespace('control', UPNP_CONTROL_NS)

#
# Logging stubs
#

__log_level = 0
def log_error(text):
    print('[X] %s' % text)
def log_warn(text):
    print('[!] %s' % text)
def log_info(text):
    print('[.] %s' % text)
def log_debug(text):
    global __log_level
    if __log_level > 0:
        print('[#] %s' % text)
def log_text(text):
    print('    %s' % text)

#
# HTTP related code
#

class HttpTransport(object):
    "Implements a base class for HTTP transport protocols"

    def __init__(self, type, proto, timeout=5):
        self.s = socket.socket(socket.AF_INET, type, proto)
        self.s.settimeout(timeout)
    def __del__(self):
        if self.s:
            self.close()
    def is_multicast(self):
        return False
    def recv(self):
        return self.s.recvfrom(65536)
    def close(self):
        log_debug('HTTP: Closing socket.')
        self.s.close()
        self.s = None

class HttpTcpTransport(HttpTransport):
    "Implements HTTP over TCP"

    def __init__(self, remote_addr, timeout=5):
        HttpTransport.__init__(self, socket.SOCK_STREAM, socket.IPPROTO_TCP, timeout)
        self.remote_addr = remote_addr
        log_debug('HTTP/TCP: Connecting to %s:%d.' % remote_addr)
        self.s.connect(remote_addr)
    def send(self, data):
        self.s.send(data)
    def recv(self):
        return (self.s.recv(65536), self.remote_addr)

class HttpUdpTransport(HttpTransport):
    "Implements HTTP over (unicast) UDP"

    def __init__(self, remote_addr, timeout=5):
        HttpTransport.__init__(self, socket.SOCK_DGRAM, socket.IPPROTO_UDP, timeout)
        self.remote_addr = remote_addr
    def send(self, data):
        self.s.sendto(data, self.remote_addr)

class HttpUdpUnicastTransport(HttpUdpTransport):
    "Implements HTTP over unicast UDP"
    pass

class HttpUdpMulticastTransport(HttpUdpTransport):
    "Implements HTTP over multicast UDP"

    def __init__(self, remote_addr, bind_addr, timeout=5):
        """Initialise the transport.
        
        remote_addr: remote endpoint address (as in socket address)
        bind_addr: local address to bind to (as in socket address)
        """
        HttpUdpTransport.__init__(self, remote_addr, timeout)
        self.s.bind(bind_addr)
        self.s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)
        mreq = socket.inet_aton(remote_addr[0]) + socket.inet_aton(bind_addr[0])
        self.s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    def is_multicast(self):
        return True

def xlines(text):
    "Iterate over lines in text."

    index = 0
    while True:
        next_index = text.find("\n", index)
        if next_index == -1:
            raise StopIteration
        if text[next_index - 1] == "\r":
            line = text[index:next_index - 1]
        else:
            line = text[index:next_index]
        index = next_index + 1
        yield line

class HttpClient(object):
    """Implements a simple HTTP client via various transports.
    
    Currently not implemented:
    * Keep-alive connections
    
    Quirks:
    * Some HTTP servers don't respond at all when protocol is set to 1.0.
    """

    def __init__(self, transport, version='1.1'):
        self.http_version = version
        self._tr = transport

    def request(self, method, url, headers=None, body=None):
        """Perform a HTTP request.
        
        method: HTTP method to be sent in request line
        url: URL to be sent in request line
        headers: additional headers to be sent
        body: request body to be sent
        
        Returns:
        * Unicast transport: a tuple (status, headers, body)
        * Multicast transport: a list of tuples (addr, status, headers, body)
        """
        request_lines = [ '%s %s HTTP/%s' % (method, url, self.http_version) ]
        has_host = False
        if headers:
            for header, value in headers.iteritems():
                header = header.upper()
                has_host = has_host or header == 'HOST'
                request_lines.append('%s: %s' % (header, str(value)))
        if not has_host:
            request_lines.append('HOST: %s:%d' % self._tr.remote_addr)
        if body:
            request_lines.append('CONTENT-LENGTH: %d' % len(body))
        request_lines.append('\r\n')
        headers_text = '\r\n'.join(request_lines)
        log_debug("HTTP: Sending headers:\n%s" % headers_text)
        self._tr.send(headers_text)
        if body:
            log_debug("HTTP: Sending body (%d bytes):\n%s" % (len(body), body))
            self._tr.send(body)

        if self._tr.is_multicast():
            responses = []
            try:
                while True:
                    responses.append(self._do_recv())
            except socket.timeout:
                pass
            return responses
        else:
            response = self._do_recv()
            return (response[1], response[2], response[3])

    def _do_recv(self):
        "Internal routine. Performs response reception."

        response = ''
        end_of_headers = -1
        while end_of_headers < 0:
            frag, addr = self._tr.recv()
            response += frag
            end_of_headers = response.find("\r\n\r\n")
            if end_of_headers < 0:
                end_of_headers = response.find("\n\n")
        body = response[end_of_headers + 4:]
        headers = response[:end_of_headers + 4]
        log_debug("HTTP: Received headers:\n%s" % headers)
        status, headers = self._parse_headers(headers)
        
        if 'CONTENT-LENGTH' in headers:
            log_debug("HTTP: Content-Length given")
            content_length = int(headers['CONTENT-LENGTH']) - len(body)
            while content_length > 0:
                frag, addr = self._tr.recv()
                body += frag
                content_length -= len(frag)
        elif 'TRANSFER-ENCODING' in headers and headers['TRANSFER-ENCODING'].lower() == 'chunked':
            log_debug("HTTP: Transfer-Encoding(chunked) given")
            buffer = body
            body = ''
            while True:
                buffer_offset = 0
                while buffer.find("\n") == -1:
                    frag, addr = self._tr.recv()
                    buffer += frag
                buffer_offset = buffer.find("\n")
                if buffer_offset == 0:
                    buffer = buffer[1:]
                    continue
                elif buffer_offset == 1 and buffer[0] == "\r":
                    buffer = buffer[2:]
                    continue
                if buffer[buffer_offset - 1] == "\r":
                    chunk_len = buffer[:buffer_offset - 1]
                else:
                    chunk_len = buffer[:buffer_offset]
                buffer_offset += 1
                if chunk_len == "0":
                    break
                chunk_len = int(chunk_len, 16)
                while len(buffer) - buffer_offset < chunk_len:
                    frag, addr = self._tr.recv()
                    buffer += frag
                body += buffer[buffer_offset:buffer_offset + chunk_len]
                buffer = buffer[buffer_offset + chunk_len:]
        else:
            # Unknown transfer method
            pass
        if body:
            log_debug("HTTP: Received body:\n%s" % body)
        return (addr, status, headers, body)

    def _parse_headers(self, text):
        "Internal routine. Performs header parsing."

        lines = xlines(text)
        status = lines.next()
        headers = {}
        for line in lines:
            if len(line) == 0:
                break
            sep_index = line.find(':')
            if sep_index < 0:
                continue
            header = line[:sep_index].upper()
            sep_index += 1
            try:
                while line[sep_index] == ' ' or line[sep_index] == '\t':
                    sep_index += 1
                value = line[sep_index:]
            except:
                value = ''
            headers[header] = value
        return (status, headers)
# End of HttpClient

class URIParseError(Exception):
    pass

class URL(object):
    "Simple URL parser/combiner"

    def __init__(self, text):
        self.scheme = ''
        self.domain = ''
        self.port = 0
        self.path = ''
        self.query = ''
        self.frag = ''
        self.__parse(text)
    def __parse(self, text):
        offset = 0
        scheme_delim = text.find('://', offset)
        if scheme_delim >= 0:
            self.scheme = text[:scheme_delim]
            offset = scheme_delim + 3
        path_delim = text.find('/', offset)
        if path_delim < 0:
            raise URIParseError('URL format is incorrect (no path)')
        port_delim = text.find(':', offset, path_delim)
        if port_delim >= 0:
            self.domain = text[offset:port_delim]
            self.port = int(text[port_delim + 1:path_delim])
        else:
            self.domain = text[offset:path_delim]
        query_delim = text.find('?', path_delim)
        if query_delim >= 0:
            frag_delim = text.find('#', query_delim)
            if frag_delim >= 0:
                self.frag = text[frag_delim + 1:]
                self.query = text[query_delim + 1:frag_delim]
            else:
                self.query = text[query_delim + 1:]
            self.path = text[path_delim:query_delim]
        else:
            self.path = text[path_delim:]
    def __str__(self):
        text = ''
        if self.scheme:
            text += self.scheme + '://'
        text += self.domain
        if self.port:
            text += ':%d' % self.port
        text += self.path
        if self.query:
            text += '?' + self.query
        if self.frag:
            text += '#' + self.frag
        return text
# End of URL

class URN(object):
    "Simple URN parser/combiner"

    def __init__(self, text):
        self.nid = ''
        self.frags = []
        self.__parse(text)
    def __parse(self, text):
        if not text.startswith('urn:'):
            raise URIParseError('Text does not start with "urn:"')
        offset = 4
        sep_index = text.find(':', offset)
        self.nid = text[offset:sep_index]
        offset = sep_index + 1
        while True:
            sep_index = text.find(':', offset)
            if sep_index >= 0:
                self.frags.append(text[offset:sep_index])
                offset = sep_index + 1
            else:
                self.frags.append(text[offset:])
                break
    def __str__(self):
        text = 'urn:%s:' % self.nid
        text += ':'.join(self.frags)
        return text
# End of URN

def http_get(url, headers=None):
    "Shortcut for GETting a URL via HTTP/TCP"
    url = URL(url)
    domain = url.domain
    port = url.port
    if not port:
        port = 80
    path = url.path
    if not path:
        path = '/'
    if url.query:
        path += '?' + url.query
    return HttpClient(HttpTcpTransport((url.domain, port))).request('GET', path, headers)

def http_post(url, headers=None, body=None):
    "Shortcut for POSTting to a URL via HTTP/TCP"
    url = URL(url)
    port = url.port
    if not port:
        port = 80
    return HttpClient(HttpTcpTransport((url.domain, port))).request('POST', url.path, headers, body)

#
# SSDP client code
#

class SsdpSearchResult(object):
    def __init__(self, ipaddr, headers):
        self.ipaddr = ipaddr
        self.server = headers.get('SERVER')
        self.location = headers.get('LOCATION')
        self.search_type = headers.get('ST')
        self.usn = headers.get('USN')
    def __str__(self):
        return 'SSDP search result:\r\n  IP: %s\r\n  Server: %s\r\n  Location: %s\r\n  USN: %s' % (self.ipaddr, self.server, self.location, self.usn)
    def __eq__(self, other):
        return self.ipaddr == other.ipaddr and self.usn == other.usn
    def __ne__(self, other):
        return not (self == other)

SSDP_MULTICAST_IPv4 = '239.255.255.250'
SSDP_PORT = 1900

def ssdp_search(transport, search_type):
    return HttpClient(transport).request('M-SEARCH', '*', {
            'HOST': '%s:%d' % (SSDP_MULTICAST_IPv4, SSDP_PORT),
            'ST': search_type,
            'MAN': '"ssdp:discover"',
            'MX': 1,
        })

def ssdp_search_uni(target_ip, search_type, timeout=5):
    "Perform a unicast SSDP M-SEARCH request"

    target_addr = (target_ip, SSDP_PORT)
    tr = HttpUdpUnicastTransport(target_addr, timeout)
    try:
        rsp = ssdp_search(tr, search_type)
        return SsdpSearchResult(target_ip, rsp[1])
    except socket.timeout:
        return None

def ssdp_search_multi(bind_addr, search_type, timeout=5):
    "Perform a multicast SSDP M-SEARCH request"

    tr = HttpUdpMulticastTransport(
        (SSDP_MULTICAST_IPv4, SSDP_PORT),
        bind_addr,
        timeout)
    results = []
    for rsp in ssdp_search(tr, search_type):
        result = SsdpSearchResult(rsp[0][0], rsp[2])
        if result not in results:
            results.append(result)
    return results

#
# UPnP client code
#

UPNP_DEBUG = True

class UpnpError(Exception):
    pass

def clean_tag(tag):
    i = tag.find('}')
    if i < 0:
        return tag
    return tag[i+1:]

class UpnpServiceAction(object):
    "Describes a UPnP service action"

    def __init__(self):
        self.name = None
        self.args_in = []
        self.args_out = []
    
    def __str__(self):
        return '%s(%s)' % (self.name, ', '.join(self.args_in))
    __repr__ = __str__

    @staticmethod
    def from_xml(xml):
        o = UpnpServiceAction()
        for child in xml:
            tag = clean_tag(child.tag)
            if tag == 'name':
                o.name = child.text
            elif tag == 'argumentList':
                for arg_child in child:
                    arg_name, arg_dir = UpnpServiceAction._parse_arg(arg_child)
                    if arg_dir == 'in':
                        o.args_in.append(arg_name)
                    # Can't be bothered with args_out...
        return o

    @staticmethod
    def _parse_arg(xml):
        arg_name = None
        arg_dir = None
        for child in xml:
            tag = clean_tag(child.tag)
            if tag == 'name':
                arg_name = child.text
            elif tag == 'direction':
                arg_dir = child.text.lower()
        return (arg_name, arg_dir)
# End of UpnpServiceAction

class UpnpServiceDescriptor(object):
    "Dscribes service actions and state vars"

    def __init__(self):
        self.actions = {}
    
    def __str__(self):
        return "\r\n".join([str(a) for a in self.actions])
    __repr__ = __str__

    @staticmethod
    def from_xml(xml):
        #print('UpnpServiceDescriptor.from_xml()')
        o = UpnpServiceDescriptor()
        n = xml.find('service:actionList', UPNP_NS_MAP)
        if n is not None:
            for child in n:
                action = UpnpServiceAction.from_xml(child)
                o.actions[action.name] = action
        return o
# End of UpnpServiceDescriptor

class UpnpService(object):
    "Describes a UPnP service instance"

    def __init__(self, root):
        self._root = root
        # These describe the service type
        self.type = None
        self.type_urn = None
        self.scpd_url = None
        # These describe the service instance
        self.id = None
        self.control_url = None
        self.event_sub_url = None

    def __str__(self):
        return 'Service %s (%s)' % (self.id, str(self.type_urn))
    __repr__ = __str__

    @staticmethod
    def from_xml(xml, root):
        #print('UpnpService.from_xml()')
        o = UpnpService(root)
        for child in xml:
            tag = clean_tag(child.tag)
            if tag == 'serviceType':
                o.type_urn = URN(child.text)
                o.type = ':'.join(o.type_urn.frags[1:])
            elif tag == 'SCPDURL':
                o.scpd_url = child.text
            elif tag == 'serviceId':
                o.id = ':'.join(URN(child.text).frags[1:])
            elif tag == 'controlURL':
                o.control_url = child.text
            elif tag == 'eventSubURL':
                o.events_url = child.text
        return o

    def get_control_url(self):
        control_url = self.control_url
        if self._root.url_base is not None:
            control_url = self._root.url_base + control_url
        return control_url

    def get_descriptor(self):
        try:
            return self._descriptor
        except:
            scpd_url = self.scpd_url
            if self._root.url_base is not None:
                scpd_url = self._root.url_base + scpd_url
            sd = self._descriptor = self._root.get_scpd(self.type, scpd_url)
            return sd
        
    def invoke(self, action, **kwargs):
        return upnp_service_action(self.get_control_url(), self.type_urn, action, **kwargs)
# End of UpnpService

class UpnpDevice(object):
    "Describes a UPnP device"

    def __init__(self, root):
        self._root = root
        self.type = None
        self.type_urn = None
        self.name = None
        self.services = []
        self.subdevices = []

    def __str__(self):
        return 'Device %s (type %s)' % (self.name, self.type)
    __repr__ = __str__

    @staticmethod
    def from_xml(xml, root):
        #print('UpnpDevice.from_xml()')
        o = UpnpDevice(root)
        for child in xml:
            tag = clean_tag(child.tag)
            #print tag
            UpnpDevice._parse_node(o, tag, child)
        return o

    @staticmethod
    def _parse_node(o, tag, node):
        if tag == 'deviceType':
            o.type_urn = URN(node.text)
            o.type = ':'.join(o.type_urn.frags[1:])
        elif tag == 'friendlyName':
            o.name = node.text
        elif tag == 'serviceList':
            for child in node:
                o.services.append(UpnpService.from_xml(child, o._root))
        elif tag == 'deviceList':
            for child in node:
                o.subdevices.append(UpnpDevice.from_xml(child, o._root))
    
    def find_services(self, service_type, results=None):
        if results is None:
            results = []
        for s in self.services:
            if s.type == service_type:
                results.append(s)
        for d in self.subdevices:
            d.find_services(service_type, results)
        return results
# End of UpnpDevice

class UpnpRootDevice(UpnpDevice):
    "Describes a UPnP root device"

    def __init__(self, url_base=None):
        UpnpDevice.__init__(self, self)
        self.url_base = url_base
        self.service_types = {}

    def __str__(self):
        return 'Device %s (type %s)' % (self.name, self.type)
    __repr__ = __str__

    @staticmethod
    def from_xml(xml, url_base=None):
        #print('UpnpRootDevice.from_xml()')
        n = xml.find('device:URLBase', UPNP_NS_MAP)
        if n is not None:
            url_base = n.text
        n = xml.find('device:device', UPNP_NS_MAP)
        if n is None:
            raise Exception("no device node in device description")
        o = UpnpRootDevice(url_base)
        for child in n:
            tag = clean_tag(child.tag)
            UpnpRootDevice._parse_node(o, tag, child)
        return o
        
    @staticmethod
    def _parse_node(o, tag, node):
        if tag == 'manufacturer':
            o.manufacturer = node.text
        elif tag == 'modelName':
            o.model_name = node.text
        elif tag == 'modelDescription':
            o.model_description = node.text
        elif tag == 'modelNumber':
            o.model_number = node.text
        elif tag == 'UDN':
            o.udn = node.text
        elif tag == 'UPC':
            o.upc = node.text
        elif tag == 'presentationURL':
            o.presentation_url = node.text
        else:
            UpnpDevice._parse_node(o, tag, node)
    
    def get_scpd(self, service_type, scpd_url):
        try:
            return self.service_types[service_type]
        except KeyError:
            pass
        log_debug('Getting SCPD')
        desc_text = http_get(scpd_url)[2]
        desc_xml = ElementTree.XML(desc_text)
        sd = UpnpServiceDescriptor.from_xml(desc_xml)
        self.service_types[service_type] = sd
        return sd
# End of UpnpRootDevice

def upnp_print_service(root, indent=''):
    log_text('%s%s' % (indent, root))
    indent += '  '
    log_text('%s%s' % (indent, root.get_control_url()))
    sd = root.get_descriptor()
    for an, a in sd.actions.iteritems():
        log_text('%s-> %s' % (indent, a))

def upnp_print_schema(root, indent=''):
    log_text('%s%s' % (indent, root))
    indent += '  '
    for s in root.services:
        upnp_print_service(s, indent)
    for d in root.subdevices:
        upnp_print_schema(d, indent)

def upnp_service_action(control_url, service_type, action, **kwargs):
    args = ['<%s>%s</%s>' % (name, value, name) for name, value in kwargs.iteritems()]
    body_text = '<u:%s xmlns:u="%s">%s</u:%s>' % (action, service_type, ''.join(args), action)
    xml = '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>'+body_text+'</s:Body></s:Envelope>'
    
    headers = {
            'SOAPACTION': '"%s#%s"' % (service_type, action),
            'CONTENT-TYPE': 'text/xml; charset="utf-8"',
        }
    response_status, response_headers, response_body = http_post(control_url, headers, xml)
    # TODO: check HTTP status code
    xml = ElementTree.XML(response_body)
    xml = xml[0][0]
    root_tag = clean_tag(xml.tag)
    if root_tag == action + 'Response':
        args_out = {}
        for node in xml:
            tag = clean_tag(node.tag)
            args_out[tag] = node.text
        return args_out
    elif root_tag == 'Fault':
        raise UpnpError('Fault')
    else:
        raise UpnpError('Unknown tag')

def upnp_process_descriptor(location):
    desc = http_get(location)
    desc_xml = ElementTree.XML(desc[2])
    # NOTE: Some device descriptors don't contain URL base.
    # Use location as base, then.
    base_url = URL(location)
    base_url.path = ''
    base_url.query = None
    base_url.frag = None
    return UpnpRootDevice.from_xml(desc_xml, str(base_url))

#
# Commands implementation
#

def ssdp_response_printout(r):
    log_info('SSDP response from %s:' % r.ipaddr)
    log_text('Server ver: %s' % r.server)
    log_text('Location: %s' % r.location)
    log_text('Search type: %s' % r.search_type)
    log_text('USN: %s' % r.usn)

def do_ssdp_multi(args):
    "Perform a SSDP multicast M-SEARCH"

    bind_ip = args.bind_ip4
    if bind_ip is None:
        log_warn('No bind address is given, will try to guess.')
        bind_ip = socket.gethostbyname(socket.gethostname())
        log_info('Will bind to %s.' % bind_ip)
    
    log_info('Starting SSDP Discovery (multicast).')
    bind_addr = (bind_ip, args.bind_port)
    ssdp_results = ssdp_search_multi(bind_addr, args.search_type, timeout=args.timeout)
    log_info('SSDP responses: %d' % len(ssdp_results))
    for r in ssdp_results:
        ssdp_response_printout(r)
    log_info('SSDP Discovery (multicast) completed.')

def do_ssdp_uni(args):
    "Perform a SSDP unicast M-SEARCH"

    log_info('Starting SSDP Discovery (unicast).')
    ssdp_result = ssdp_search_uni(args.target_ip, args.search_type, timeout=args.timeout)
    if ssdp_result:
        ssdp_response_printout(ssdp_result)
    else:
        log_error('No response from the target.')
    log_info('SSDP Discovery (unicast) completed.')

def do_upnp_dump(args):
    log_info('Starting UPnP descriptor dumping.')
    root = upnp_process_descriptor(args.location)
    upnp_print_schema(root)
    log_info('UPnP descriptor dumping completed.')

def do_upnp_action(args):
    log_info('Starting UPnP action invocation.')
    inputs = {}
    for i in args.inputs:
        name, sep, value = i.partition('=')
        inputs[name] = value
    try:
        log_info('Performing SOAP call...')
        outputs = upnp_service_action(args.control_url, args.service_type, args.action, **inputs)
        if outputs:
            log_info('Returned values:')
            for p in outputs.iteritems():
                log_text('%s = %s' % p)
        else:
            log_info('No values returned.')
    except UpnpError as e:
        log_error('Call failed.')
        log_text(str(e))
    log_info('UPnP action invocation completed.')

#
# Main code
#

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Your UPnP pwnage tool")
    parser.add_argument('--debug',
        help='enable debugging of this script',
        action='store_true')

    subparsers = parser.add_subparsers()
    
    p = subparsers.add_parser('ssdp-multi', help='perform a SSDP multicast M-SEARCH')
    p.add_argument('--bind-ip4',
        help='IPv4 local address to bind to',
        default=None)
    p.add_argument('--bind-port',
        help='UDP port number to bind to',
        type=int,
        default=2600)
    p.add_argument('--search-type',
        help='search type to perform',
        default='upnp:rootdevice')
    p.add_argument('--timeout',
        help='how long to wait for replies, seconds',
        type=int,
        default=2)
    p.set_defaults(handler=do_ssdp_multi)
    
    p = subparsers.add_parser('ssdp-uni', help='perform a SSDP unicast M-SEARCH')
    p.add_argument('target_ip',
        help='IPv4 remote address',
        metavar='target-ip')
    p.add_argument('--search-type',
        help='search type to perform (eg: upnp:rootdevice)',
        default='upnp:rootdevice')
    p.add_argument('--timeout',
        help='how long to wait for a reply, seconds',
        type=int,
        default=2)
    p.set_defaults(handler=do_ssdp_uni)
    
    p = subparsers.add_parser('upnp', help='perform a UPnP action')
    ps = p.add_subparsers()
    
    pp = ps.add_parser('dump', help='dump device specification from location')
    pp.add_argument('location',
        help='XML descriptor location')
    pp.set_defaults(handler=do_upnp_dump)
    
    pp = ps.add_parser('action', help='invoke a service action')
    pp.add_argument('control_url',
        help='control point URL',
        metavar='control-url')
    pp.add_argument('service_type',
        help='UPnP service type',
        metavar='control-url')
    pp.add_argument('action',
        help='action name')
    pp.add_argument('inputs',
        help='action arguments',
        nargs='*')
    pp.set_defaults(handler=do_upnp_action)

    args = parser.parse_args()
    if args.debug:
        __log_level = 1

    log_text('')
    log_text('Plug and Pray -- UPnP script starting up.')
    log_text('')
    args.handler(args)
    
    log_error('Have a nice day.')
# EOF
