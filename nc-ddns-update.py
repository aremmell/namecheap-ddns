#
#
# ref: https://www.namecheap.com/support/knowledgebase/article.aspx/29/11/how-to-dynamically-update-the-hosts-ip-with-an-http-request/

import urllib.request
import urllib.parse
import argparse
import logging
import xml.parsers.expat

def build_query_string(domain, password, ip):
    return urllib.parse.urlencode({'host': '@', 'domain': domain, 'password': password, 'ip': ip})

def build_argparser():
    argparser = argparse.ArgumentParser(
        prog="nc-ddns-update.py",
        description="Updates Namecheap's Dynamic DNS service with your current IP address.")
    
    argparser.add_argument('-d', '--domain', help='The TLD (top-level domain) to update the DNS record for', required=True, type=str)
    argparser.add_argument('-p', '--password', help='Your Namecheap DDNS password', required=True, type=str)
    argparser.add_argument('-i', '--ip', help='The IPv4 address to set the A record to', required=True, type=str)
    
    return argparser

def parse_xml_response(xml_data):

    def start_element(name, attrs):
        logging.debug("start_element: %s %s" % (name, attrs))

    def end_element(name):
        logging.debug("end_element: %s" % name)

    def char_data(data):
        data = data.strip()
        if data != '':
            logging.debug("char_data: %s" % repr(data))

    try:
        xml_parser = xml.parsers.expat.ParserCreate("utf-16")
        xml_parser.StartElementHandler = start_element
        xml_parser.EndElementHandler = end_element
        xml_parser.CharacterDataHandler = char_data
        xml_parser.Parse(xml_data, True)
    except xml.parsers.expat.ExpatError as e:
        logging.error("Error creating XML parser: %s" % e)
        return
    
#<?xml version="1.0" encoding="utf-16"?>
#<interface-response>
#  <Command>SETDNSHOST</Command>
#  <Language>eng</Language>
#  <ErrCount>1</ErrCount>
#  <errors>
#    <Err1>Invalid IP</Err1>
#  </errors>
#  <ResponseCount>1</ResponseCount>
#  <responses>
#    <response>
#      <Description>Invalid IP</Description>
#      <ResponseNumber>304156</ResponseNumber>
#      <ResponseString>Validation error; invalid ; IP Address</ResponseString>
#    </response>
#  </responses>
#  <Done>true</Done>
#  <debug><![CDATA[]]></debug>
#</interface-response>

def do_get_request(arg_ns):
    data = build_query_string(arg_ns.domain, arg_ns.password, arg_ns.ip)
    data = data.encode()
    https_handler = urllib.request.HTTPSHandler(debuglevel=3)
    opener = urllib.request.build_opener(https_handler)
    with opener.open("https://dynamicdns.park-your-domain.com/update?%s" % data) as f:
        if f.status != 200:
            logging.error("HTTP response code: %d" % f.status)
        else:
            logging.info("Got 200 OK; parsing response body...");
            parse_xml_response(f.read().decode('utf-8'))

def main():
    logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s', level=logging.DEBUG)
    argparser = build_argparser()
    arg_ns = argparser.parse_args()
    do_get_request(arg_ns)
    
if __name__ == "__main__":
    main()
