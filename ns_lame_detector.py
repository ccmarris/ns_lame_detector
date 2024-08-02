#!/usr/bin/env python3
#vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
"""
-----------------------------------------------------------------------

 Python Script to Check DNS domain(s) for Lame Delegations and
 therefore potential exposure to Sitting Duck:

 https://blogs.infoblox.com/threat-intelligence/who-knew-domain-hijacking-is-so-easy/

 Requirements:
   Python 3

 Usage: <scriptname> [options]
        -d        dump mode (dump message as-is)
        -t        test mode (no actions taken)
        -h        help
        -v        verbose

 Author: Chris Marrison
 Email: chris@infoblox.com

 ChangeLog:
   <date>	<version>	<comment>

 Todo:

 Copyright 2024 Chris Marrison / Infoblox Inc

 Redistribution and use in source and binary forms,
 with or without modification, are permitted provided
 that the following conditions are met:

 1. Redistributions of source code must retain the above copyright
 notice, this list of conditions and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright
 notice, this list of conditions and the following disclaimer in the
 documentation and/or other materials provided with the distribution.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 POSSIBILITY OF SUCH DAMAGE.
----------------------------------------------------------------------
"""

__version__ = '0.1.0'
__author__ = 'Chris Marrison'

import logging
import argparse
import dns.resolver
import dns.rcode
from rich import print

_logger = logging.getLogger(__name__)
### Global Variables ###

# --- Classes ---

### Functions ###

def parseargs():
    '''
    Parse Arguments Using argparse

    Parameters:
        None

    Returns:
        Returns parsed arguments
    '''
    description = 'DNS Lame Server Check'
    parse = argparse.ArgumentParser(description=description)
    parse.add_argument('-z', '--zone', type=str, default='all',
                       help='Zone to perform checks against')
    parse.add_argument('-f', '--file', action='store_true',
                        help='Output CSVs to file')
    parse.add_argument('-d', '--debug', action='store_true', 
                        help="Enable debug messages")

    return parse.parse_args()


def setup_logging(debug):
    '''
     Set up logging

     Parameters:
        debug (bool): True or False.

     Returns:
        None.

    '''
    # Set debug level
    if debug:
        logging.basicConfig(level=logging.DEBUG,
                            format='%(asctime)s %(levelname)s: %(message)s')
    else:
        logging.basicConfig(level=logging.INFO,
                            format='%(asctime)s %(levelname)s: %(message)s')

    return


class LAME():

    def __init__(self, timeout:float = 10.0):
        '''
        '''
        self.ns_from_parent:set = set()
        self.auth_ns:set = set()
        self.nameservers:set = set()
        self.results:list
        self.timeout:float = timeout

        return
    

    def report(self):
        '''
        Generate and report on full lame delegation check
        '''
        lame:bool = False
        unknown:bool = False

        if self.results:
            for result in self.results:
                if result.get('status') == 'LAME':
                    lame = True
                elif 'UNKNOWN' in result.get('status'):
                    unknown = True

        print()
        if lame:
            print('LAME DELEGATIONS DETECTED')
            print()
        if unknown:
            print('Could not determine status of all servers')
            print('You may wish to test again')
            print()
        
        if not lame and not unknown:
            print('Fantastic: No lame servers detected!')
            print()
        
        print('Nameserver:  Status')
        for r in self.results:
            print(f"{r.get('nameserver')}: {r.get('status')}")
        
        print()

        return


    def full_lame_check(self, zone:str = ''):
        '''
        Check zone for lame delegations

        Parameters:
            zone:str = fqdn of domain to check
        
        Returns:
            list of results (dict per nameserver )
            Also sets this a property self.results
        '''
        results:list = []

        # Check delegation at parent
        if not self.ns_from_parent:
            self.get_delegation_from_parent(fqdn=zone)
        
        for ns in self.ns_from_parent:
            results.append(self.lame_server_check(zone=zone, server=ns))
        
        if self.ns_from_parent != self.auth_ns:
            # Check auth list
            to_check = self.ns_from_parent.symmetric_difference(self.auth_ns)
            if to_check:
                for ns in to_check:
                    results.append(self.lame_server_check(zone=zone, server=ns))
                    
        self.results = results

        return results


    def lame_server_check(self, zone:str = '', server:str = ''):
        '''
        Check server for lameness

        Parameters:
            zone:str = zone to check
            server:str = hostname or IP of server

        Returns:
            dict: {'nameserver: '', 'status': 'AUTHORITATIVE|LAME|UNKNOEN, NO RESPONSE' }
            Updates self.auth_ns set
        '''

        status:str
        result:dict = {}

        qr = self.dns_query(query=zone, qtype='NS', nameserver=server)
        _logger.debug(f'Server check query: {qr}')

        if qr.get('status') == 'NOERROR':
            # Check flags
            if 'AA' in qr.get('flags'):
                status = 'AUTHORITATIVE'

                # Add nameserver to set
                if qr.get('rrset'):
                        self.auth_ns.update(sorted(qr.get('rrset')))
                        

            else:
                status = 'LAME DELEGATION'
        elif qr.get('status') == 'TIMEOUT':
            status = 'UNKNOWN, NO RESPONSE'
        else:
            status = 'LAME DELEGATION'
        
        result = { 'nameserver': server,
                   'status': status }

        return result
            

    def dns_query(self, query:str ='', qtype:str ='A', nameserver:str=None):
        '''
        Perform a DNS query

        Parameters:
            query:str = fqdn
            qtype:str = record type, defaults to A records
            nameserver:str = Send query to specific nameserver
        
        Returns:
            dict: { 'status': dns.rcode.to_text(answers.response.rcode()),
                    'rdtype': qtype,
                    'rrset': rrset,
                    'flags': answers.response.flags.name,
                    'authority': authority }
            
        '''
        rrset = []
        authority = []
        response:dict = {}
        try: 
            if nameserver:
                answers = dns.resolver.resolve_at(where=nameserver,
                                                  qname=query, 
                                                  rdtype=qtype,
                                                  raise_on_no_answer=False,
                                                  lifetime=self.timeout)
            else:
                answers = dns.resolver.resolve(query, 
                                               qtype,
                                               lifetime=self.timeout)

            for rdata in answers:
                rrset.append(str(rdata))
                _logger.debug(f'{rdata}')
            
            # Isolate authority NS in response
            if answers.response.authority:
                auth = str(answers.response.authority).split('[')[2].split(']')[0]
                auth =auth.replace('<','').replace('>','').replace(' ','')
                authority = auth.split(',')
            
            response = { 'status': dns.rcode.to_text(answers.response.rcode()),
                         'rdtype': qtype,
                         'rrset': rrset,
                         'flags': answers.response.flags.name,
                         'authority': authority }

        except dns.resolver.NXDOMAIN:
            response = { 'status': 'NXDOMAIN' }
        except dns.resolver.YXDOMAIN:
            response = { 'status': 'YXDOMAIN' }
        except dns.resolver.NoAnswer:
            response = { 'status': 'NOANSWER' }
        except dns.resolver.LifetimeTimeout:
            response = { 'status': 'TIMEOUT' }
        except Exception as err: 
            raise err

        return response


    def label_count(self, fqdn=''):
        '''
        Count number of labels in an FQDN

        Parameters:
            fqdn:str = FQDN
        
        Returns:
            int = Number of labels
        '''
        labels:list = []
        labels = fqdn.split('.')

        return len(labels)


    def get_domain(self, fqdn=''):
        '''
        Get the parent domain from an FQDN

        Parameters:
            fqdn:str = FQDN
        
        Returns:
            parent domain:str = Parent domain of FQDN
        '''
        parent:str = ''
        count:int = self.label_count(fqdn)
        no_of_labels:int = count - 1
        labels:list = fqdn.split('.')

        if count == 1:
            parent = '.'
        else:
            for label in range((count - no_of_labels), (count)):
                parent += labels[label]
                parent += "." 
            # Strip last "."
            parent = parent.replace("..", ".")

        return parent


    def get_delegation_from_parent(self, fqdn:str = ''):
        '''
        Determing the parent and retrieve NS records
        '''
        status = False
        delegation_ns:list = []
        parent_ns:list = []

        # Get the parent domain
        parent_domain = self.get_domain(fqdn=fqdn)

        # Get NS for parent
        _logger.debug(f'Performing query for parent domain: {parent_domain}')
        qr = self.dns_query(query=parent_domain, qtype='NS')
        if qr.get('status') == 'NOERROR':
            _logger.debug('Successful query for parent domain')
            if qr.get('rrset'):
                parent_ns  = qr.get('rrset')
                _logger.debug(f'Parents NS Records: {parent_ns}')
        
        # Get NS for target domain
        if parent_ns:
            # Select first nameserver on list
            ns = parent_ns.pop()
            _logger.debug(f'Querying {ns} for delegation authority')
            qr = self.dns_query(query=fqdn, qtype='NS', nameserver=ns)
        else:
            _logger.warning('No parent NS records found attempting recursion')
            qr = self.dns_query(query=fqdn, qtype='NS')
        
        _logger.debug(f'Response: {qr}')
        if qr.get('status') == 'NOERROR':
            if qr.get('rrset'):
                _logger.debug('Using RR set')
                delegation_ns = qr.get('rrset')
            else:
                # Expected
                _logger.debug('Using authority section')
                delegation_ns = qr.get('authority')
        
        self.ns_from_parent.update(sorted(delegation_ns))

        return delegation_ns


# --- Functions --- 

def main():
    '''
    Code logic
    '''

    # Parse Arguments
    args = parseargs()
    setup_logging(args.debug)

    lame = LAME()
    lame.full_lame_check(zone=args.zone)
    lame.report()

    return


### Main ###
if __name__ == '__main__':
    exitcode = main()
    exit(exitcode)
## End Main ###

    