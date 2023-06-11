#!
# @file nc-ddns-update.py
# @brief Namecheap Dyanmic DNS utilities
#
# Namecheap offers a great DDNS service, but the software (and router integration)
# available to let Namecheap's DNS servers know when your public IP address has
# changed are not plentiful or portable.
#
# This script aims to become the defacto standard for manual and automated
# (e.g. via cron) updating of Namecheap DDNS records.
#
# @author Ryan M. Lederman <lederman@gmail.com>
# @date 11 May 2023
# @version 0.1.0a
# @copyright The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
import sys
import urllib.request
import urllib.parse
import urllib.error
from requests import get
from requests import exceptions
import argparse
import logging
import re
#import pdb; pdb.set_trace();

# The default service for resolution of public IP addresses.
ip_service = "https://api.ipify.org/"

# The default timeouts for an HTTP GET request, in seconds (connect, read).
http_timeouts = (3.05, 27)

# builds the query string for the HTTP GET request.
def build_query_string(domain, password, ip):
    dict = {'host': '@', 'domain': domain, 'password': password};
    if ip is not None:
        dict['ip'] = ip
    return urllib.parse.urlencode(dict)

# builds the command-line argument configuration and parser.
def build_cli_parser():
    argparser = argparse.ArgumentParser(
        prog="nc-ddns-update.py",
        description="Namecheap Dynamic DNS utilities.",
        epilog="For updates, filing bug reports, making feature requests, etc.," +
               " visit https://github.com/aremmell/namecheap-ddns."        
    )

    argparser.add_argument(
        '--debug',
        help='Enables debug mode. Detailed diagnostic information will be' +
             ' printed during the execution of this script.',
        action='store_true'
    )

    subparsers = argparser.add_subparsers(
        title='Commands',
        description="Available commands",
        dest='command',
        required=True
    )

    sp_update = subparsers.add_parser(
        name='update',
        help='Updates the A record for the specified Namecheap DDNS domain.'
    )

    sp_update.add_argument(
        '-d',
        '--domain',
        help='The TLD (top-level domain) to update the A record for.' +
             'Note: this field is case-sensitive. It must be entered exactly' +
             'as it appears in your Namecheap account.',
        required=True,
        type=str
    )

    sp_update.add_argument(
        '-p',
        '--password',
        help='Your Namecheap DDNS password. This is NOT the same as your' +
             ' Namecheap account password!' +
             '' +
             ' Locating your DDNS password: "Domain List" -> (your domain) ->' +
             ' "Manage", -> "Domain" drop-down -> "Advanced DNS"' +
             ' Scroll down to the section labeled "Dynamic DNS."',
        required=True,
        type=str
    )

    sp_update.add_argument(
        '-i',
        '--ip',
        help='The IPv4 address to update the A record with.' +
             ' If omitted, Namecheap will use your client address.' +
             ' You may also use the `resolve` command in this script' +
             ' and a third-party service will be used to determine the' +
             ' address.',
        required=False,
        type=str,
        default=None
    )    

    # ======================================================================#

    sp_resolve = subparsers.add_parser(
        name='resolve',
        help='Resolves your public IP address using a third-party service' +
             ' and prints it to stdout.',
    )

    sp_resolve.add_argument(
        '-s',
        '--service',
        help='If specified, override the third-party service used to resolve' +
             ' your public IP address. (default: %s)' % ip_service +
             ' Note: the service must return a plaintext/JSON or other human-' +
             'readable format; this script does not modify the response body.',
        required=False,             
        type=str,
        default=None
    )

    return argparser

def parse_xml_response(xml_data):
    logging.debug("XML response body:\n%s\n" % xml_data)
    logging.debug("Using regex to parse XML...")

    # searches the XML for a pattern, and returns the match if found.
    # returns None otherwise.
    def search_xml(pattern, flags):
        logging.debug("Searching regex pattern: '%s'..." % pattern)

        m = re.search(pattern, xml_data, flags)
                
        if m is None:
            logging.debug("No match: '%s'" % pattern)            
        else:
            logging.debug("Match: %r, groups: %r" % (m.group(), m.groups()))

        return m
    
    # same as the above, but returns more than one match (global search)
    def findall_xml(pattern, flags):
        logging.debug("Searching all instances of pattern: '%s'..." % pattern)

        m = re.findall(pattern, xml_data, flags);

        if type(m) is list and len(m) > 0:
            logging.debug("Match(es): %s" % m);
        else:
            logging.debug("No match: %s" % m)
        
        return m

    try:
        re_flags = re.ASCII | re.MULTILINE
        err_patterns = [
            r'<ErrCount>(\d+)</ErrCount>',                                  # 1
            r'<Err[\d]>(.+)</Err[\d]>',                                     # 2
            r'<ResponseCount>(\d)</ResponseCount>',                         # 3
            r'<response>(?:[\s\n]+)<Description>(.+)</(?:\w+)>(?:[\s\n]+)'  # 4
            r'<ResponseNumber>(.+)</(?:\w+)>(?:[\s\n]+)<ResponseString>(.+)'# 4
            r'</(?:\w+)>(?:[\s\n]+)</(?:\w+)>'                              # 4
        ]

        success_patterns = [
            r'<ErrCount>0</ErrCount>',
            r'<ResponseCount>0</ResponseCount>',
            r'<IP>(.+)</IP>',            
        ]

        final_err_set = list(())

        # look for error count, which hints at whether or not we should
        # look for the second pattern.
        m1 = search_xml(err_patterns[0], re_flags)
        if m1: # got a match; error count = group 1
            n_err = int(m1.group(1))
            if n_err > 0: # extract the error message(s) from the second pattern.
                logging.debug("errors: %d; looking for error messages..." % n_err)                
                m2 = findall_xml(err_patterns[1], re_flags)
                if m2:
                    for i in range(len(m2)):
                        logging.debug("Found error description: %s" % m2[i])
                        final_err_set.append(m2[i])
            # look for response count, which also contains additional error
            # information, if any <response> tags are present.
            m3 = search_xml(err_patterns[2], re_flags)
            if m3: # got a match; response count = group 1
                n_resp = int(m3.group(1))
                if n_resp > 0: # find and extract <response> tag contents
                    logging.debug("responses: %d; looking for response"
                                  " content..." % n_resp)
                    m4 = findall_xml(err_patterns[3], re_flags)
                    if m4: # this should be a list of tuples, since there were
                           # 3 capture groups.
                        for i in range(len(m4)):
                            this_response = ""
                            for n in range(len(m4[i])):
                                this_response += m4[i][n]
                                if n <= 1: this_response += ": "
                            final_err_set.append(this_response);
        
        # if final_err_set is empty, no errors were found, and it's time
        # to move on to searching for known success patterns.
        if len(final_err_set) == 0:
            all_succeeded = True
            final_result  = ""
            for p in range(len(success_patterns)):
                m = search_xml(success_patterns[p], re_flags)
                if m:
                    logging.debug("verified %d/%d expected success patterns"
                                    %(p + 1, len(success_patterns)))
                    if p == len(success_patterns) - 1:
                        final_result = m.group(1)
                else:
                    all_succeeded = False
            if all_succeeded:
                logging.info("Successfully updated A record with IP: '%s'",
                             final_result);
            return all_succeeded
        else: # all done; print final list of errors and return.
            logging.error("Failed to update A record! Found these error(s) in"
                            " the response body:\n");
            for e in range(len(final_err_set)):
                logging.error("\t%d: '%s'" % (e + 1, final_err_set[e]))

            return False
    except re.error as e:
        logging.error("regex exception: %s" % e)
        return False

# entry point for the 'update' command
def do_update_request(arg_ns):
    data = build_query_string(arg_ns.domain, arg_ns.password, arg_ns.ip)

    if logging.getLogger().level == logging.DEBUG:
        https_level = 3
    else:
        https_level = 0

    try:
        https_handler = urllib.request.HTTPSHandler(debuglevel=https_level, check_hostname=True)
        opener = urllib.request.build_opener(https_handler)
        with opener.open("https://dynamicdns.park-your-domain.com/update?%s" % data) as f:
            if f.status != 200:
                logging.error("Couldn't update A record for %s: HTTP GET request" +
                            " to %s failed! code: %d, response body: '%s'"
                            % arg_ns.domain % f.geturl() % f.status % f.read().decode('utf-8'))
                return False
            else:
                logging.debug("Got 200 OK; parsing response body...");
                return parse_xml_response(f.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        logging.error("HTTP exception: %s", e)
        return False

# entry point for the 'resolve' command
def do_resolve_request(arg_ns):
    if arg_ns.service is not None:
        svc = arg_ns.service
    else:
        svc = ip_service
    
    try:
        logging.debug("Starting GET request to %s...", svc);
        my_ip = get(svc, timeout=http_timeouts)

        if my_ip.status_code != 200 or my_ip.text is None:
            logging.error("Couldn't determine your IP address: HTTP GET " + 
                            "request to %s failed! code: %d, response body:\n'%s'"
                            % (svc, my_ip.status_code, my_ip.text))
            return False
        else:
            ip_v4_pattern = r'^[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}$'
            m = re.fullmatch(ip_v4_pattern, my_ip.text, re.A)
            if m:
                logging.info("Success! Your public IP address is: %s" % my_ip.text)
                return True
            else:
                logging.error(my_ip.text);
                logging.error("The response body from %s isn't an IPv4 address!" % svc)
                return False
    except re.error as rex:
        logging.error("regex exception: %s" % rex)
        return False
    except exceptions.RequestException as e:
        logging.error("HTTP exception: %s", e);
        return False

# script entry point
if __name__ == "__main__":
    argparser = build_cli_parser()
    arg_ns = argparser.parse_args()

    print(arg_ns)

    if arg_ns.debug:
        level = logging.DEBUG
    else:
        level = logging.INFO

    logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s', level=level)
    logging.info("Logging initialized with level: %s" % logging.getLevelName(level))
    logging.info("Executing command: '%s'..." % arg_ns.command)

    if arg_ns.command == 'resolve':
        exit_code = not do_resolve_request(arg_ns)
    elif arg_ns.command == 'update':
        exit_code = not do_update_request(arg_ns)
    else:
        logging.error("Unknown command: %s" % arg_ns.command)
        exit_code = 1

    logging.debug("Exiting with code: %d" % exit_code)
    sys.exit(exit_code)
