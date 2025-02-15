from __future__ import print_function
from lib.util.cache import CacheHandler
cache_handler = CacheHandler(".cache")
cache_handler.setup_import_hook()
from lib.core.DNSDumpsterAPI import DNSDumpsterAPI
from lib.core import socks
from lib.util.report import generate_report
import argparse
import re
import sys
import socket
import binascii
import datetime
import requests
import colorama
import zipfile
import os
import win_inet_pton
import platform
from colorama import Fore, Style
import dns.resolver
from typing import Dict, Set
import collections

collections.Callable = collections.abc.Callable


colorama.init(Style.BRIGHT)
found_ips: Dict[str, str] = {}
cloudflare_domains: Set[str] = set()

def print_out(data, end='\n'):
    datetimestr = str(datetime.datetime.strftime(datetime.datetime.now(), '%H:%M:%S'))
    print(Style.NORMAL + "[" + datetimestr + "] " + re.sub(' +', ' ', data) + Style.RESET_ALL,' ', end=end)


def ip_in_subnetwork(ip_address, subnetwork):
    (ip_integer, version1) = ip_to_integer(ip_address)
    (ip_lower, ip_upper, version2) = subnetwork_to_ip_range(subnetwork)

    if version1 != version2:
        raise ValueError("incompatible IP versions")

    return (ip_lower <= ip_integer <= ip_upper)


def ip_to_integer(ip_address):
    # try parsing the IP address first as IPv4, then as IPv6
    for version in (socket.AF_INET, socket.AF_INET6):
        try:
            ip_hex = win_inet_pton.inet_pton(version, ip_address) if platform == 'Windows' else socket.inet_pton(version, ip_address)
            ip_integer = int(binascii.hexlify(ip_hex), 16)

            return ip_integer, 4 if version == socket.AF_INET else 6
        except:
            pass

    raise ValueError("invalid IP address")


def subnetwork_to_ip_range(subnetwork):
    try:
        fragments = subnetwork.split('/')
        network_prefix = fragments[0]
        netmask_len = int(fragments[1])

        # try parsing the subnetwork first as IPv4, then as IPv6
        for version in (socket.AF_INET, socket.AF_INET6):

            ip_len = 32 if version == socket.AF_INET else 128

            try:
                suffix_mask = (1 << (ip_len - netmask_len)) - 1
                netmask = ((1 << ip_len) - 1) - suffix_mask
                ip_hex = socket.inet_pton(version, network_prefix)
                ip_lower = int(binascii.hexlify(ip_hex), 16) & netmask
                ip_upper = ip_lower + suffix_mask

                return (ip_lower,
                        ip_upper,
                        4 if version == socket.AF_INET else 6)
            except:
                pass
    except:
        pass

    raise ValueError("invalid subnetwork")


def dnsdumpster(target):
    print_out(Fore.CYAN + "Testing for misconfigured DNS using dnsdumpster...")
    
    res = DNSDumpsterAPI(False).search(target)

    if not res:
        return

    if res['dns_records']['host']:
        for entry in res['dns_records']['host']:
            provider = str(entry['provider'])
            if "Cloudflare" not in provider and not entry['domain'].endswith('cloudflare.com'):
                print_out(
                    Style.BRIGHT + Fore.WHITE + "[FOUND:HOST] " + Fore.GREEN + "{domain} {ip} {as} {provider} {country}".format(
                        **entry))
                found_ips[entry['domain']] = entry['ip']

    if res['dns_records']['dns']:
        for entry in res['dns_records']['dns']:
            provider = str(entry['provider'])
            if "Cloudflare" not in provider and not entry['domain'].endswith('cloudflare.com'):
                print_out(
                    Style.BRIGHT + Fore.WHITE + "[FOUND:DNS] " + Fore.GREEN + "{domain} {ip} {as} {provider} {country}".format(
                        **entry))
                found_ips[entry['domain']] = entry['ip']

    if res['dns_records']['mx']:
        for entry in res['dns_records']['mx']:
            provider = str(entry['provider'])
            if "Cloudflare" not in provider and not entry['domain'].endswith('cloudflare.com'):
                print_out(
                    Style.BRIGHT + Fore.WHITE + "[FOUND:MX] " + Fore.GREEN + "{ip} {as} {provider} {domain}".format(
                        **entry))
                found_ips[entry['domain']] = entry['ip']


def crimeflare(target):
    print_out(Fore.CYAN + "Scanning crimeflare database...")

    with open("data/ipout", "r") as ins:
        for line in ins:
            lineExploded = line.split(" ")
            if lineExploded[1] == args.target:
                ip = lineExploded[2].strip()
                print_out(Style.BRIGHT + Fore.WHITE + "[FOUND:IP] " + Fore.GREEN + "" + ip)
                found_ips[args.target] = ip


def init(target):
    if args.target:
        print_out(Fore.CYAN + "Fetching initial information from: " + args.target + "...")
    else:
        print_out(Fore.RED + "No target set, exiting")
        sys.exit(1)

    if not os.path.isfile("data/ipout"):
            print_out(Fore.CYAN + "No ipout file found, fetching data")
            update()
            print_out(Fore.CYAN + "ipout file created")

    try:
        ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print_out(Fore.RED + "Domain is not valid, exiting")
        sys.exit(0)

    print_out(Fore.CYAN + "Server IP: " + ip)
    print_out(Fore.CYAN + "Testing if " + args.target + " is on the Cloudflare network...")

    try:
        ifIpIsWithin = inCloudFlare(ip)

        if ifIpIsWithin:
            print_out(Style.BRIGHT + Fore.GREEN + args.target + " is part of the Cloudflare network!")
        else:
            print_out(Fore.RED + args.target + " is not part of the Cloudflare network, quitting...")
            sys.exit(0)
    except ValueError:
        print_out(Fore.RED + "IP address does not appear to be within Cloudflare range, shutting down..")
        sys.exit(0)


def inCloudFlare(ip):
    with open('{}/data/cf-subnet.txt'.format(os.getcwd())) as f:
        for line in f:
            isInNetwork = ip_in_subnetwork(ip, line)
            if isInNetwork:
                return True
        return False

def check_for_wildcard(target):
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ['1.1.1.1', '1.0.0.1']
    #Unsure how exactly I should test, for now simple appending to target. Don't know how to extract only domain to append *. for wildcard test
    try:
        #Throws exception if none found
        answer = resolver.resolve('*.' + target)
        #If found, ask user if continue as long until valid answer
        choice = ''
        while choice != 'y' and choice != 'n':
            choice = input("A wildcard DNS entry was found. This will result in all subdomains returning an IP. Do you want to scan subdomains anyway? (y/n): ")
        if choice == 'y':
            return False
        else:
            return True
    except:
        #Return False to not return if no wildcard was found
        return False


def subdomain_scan(target, _):
    i = 0
    c = 0
    if check_for_wildcard(target):
        print_out(Fore.CYAN + "Scanning finished...")
        print_summary()
        return

    try:
        file_path = args.input if args.input else "data/subdomains.txt"
            
        with open(file_path, "r") as wordlist:
            numOfLines = len(list(wordlist))
            if numOfLines == 0:
                print_out(Fore.RED + "Input file is empty")
                return
                
            print_out(Fore.CYAN + f"Scanning {numOfLines} subdomains ({file_path}), please wait...")
            wordlist.seek(0)
            
            for word in wordlist:
                c += 1
                if numOfLines > 100 and (c % int((float(numOfLines) / 100.0))) == 0:
                    print_out(Fore.CYAN + str(round((c / float(numOfLines)) * 100.0, 2)) + "% complete", '\r')

                subdomain = "{}.{}".format(word.strip(), target)
                try:
                    target_http = requests.get("http://" + subdomain)
                    target_http = str(target_http.status_code)
                    ip = socket.gethostbyname(subdomain)
                    ifIpIsWithin = inCloudFlare(ip)

                    if not ifIpIsWithin:
                        i += 1
                        print_out(
                            Style.BRIGHT + Fore.WHITE + "[FOUND:SUBDOMAIN] " + Fore.GREEN + subdomain + " IP: " + ip + " HTTP: " + target_http)
                        found_ips[subdomain] = ip
                    else:
                        print_out(
                            Style.BRIGHT + Fore.WHITE + "[FOUND:SUBDOMAIN] " + Fore.RED + subdomain + " ON CLOUDFLARE NETWORK!")
                        cloudflare_domains.add(subdomain)
                        continue

                except requests.exceptions.RequestException:
                    continue
            print_out(Fore.CYAN + "Scanning finished...")
            print_summary()

    except IOError:
        print_out(Fore.RED + f"File {file_path} does not exist, aborting scan...")
        sys.exit(1)


def print_summary():
    """Print summary of found IPs"""
    if found_ips:
        print_out("Found IPs:")
        for domain, ip in found_ips.items():
            print_out(f"- {domain} > {ip}")
    else:
        print_out("Found no IPs.")


def update():
    print_out(Fore.CYAN + "Just checking for updates, please wait...")
    print_out(Fore.CYAN + "Updating CloudFlare subnet...")
    if(args.tor == False):
        headers = {'User-Agent': 'Mozilla/5.0 (Windows; U; Windows NT 5.1; it; rv:1.8.1.11) Gecko/20071127 Firefox/2.0.0.11'}
        r = requests.get("https://www.cloudflare.com/ips-v4", headers=headers, cookies={'__cfduid': "d7c6a0ce9257406ea38be0156aa1ea7a21490639772"}, stream=True)
        with open('data/cf-subnet.txt', 'wb') as fd:
            for chunk in r.iter_content(4000):
                fd.write(chunk)
    else:
        print_out(Fore.RED + Style.BRIGHT+"Unable to fetch CloudFlare subnet while TOR is active")
    print_out(Fore.CYAN + "Updating Crimeflare database...")
    r = requests.get("https://cf.ozeliurs.com/ipout", stream=True)
    with open('data/ipout', 'wb') as fd:
        for chunk in r.iter_content(4000):
            fd.write(chunk)

# END FUNCTIONS

logo = """\
   ____ _                 _ _____     _ _
  / ___| | ___  _   _  __| |  ___|_ _(_) |
 | |   | |/ _ \\| | | |/ _` | |_ / _` | | |
 | |___| | (_) | |_| | (_| |  _| (_| | | |
  \\____|_|\\___/ \\__,_|\\__,_|_|  \\__,_|_|_|
    v1.0.6                      by m0rtem / updated by cnoid

"""

print(Fore.RED + Style.BRIGHT + logo + Fore.RESET)
datestr = str(datetime.datetime.strftime(datetime.datetime.now(), '%d/%m/%Y'))
print_out("Initializing CloudFail - the date is: " + datestr)

parser = argparse.ArgumentParser()
parser.add_argument("-t", "--target", help="target url of website", type=str)
parser.add_argument("-T", "--tor", dest="tor", action="store_true", help="enable TOR routing")
parser.add_argument("-u", "--update", dest="update", action="store_true", help="update databases")
parser.add_argument("-i", "--input", help="path to input file containing subdomains", type=str)
parser.add_argument("-r", "--report", nargs='*', help="generate reports (html, md, ip, sub, all)")
parser.add_argument("-o", "--output", help="output file for reports")
parser.set_defaults(tor=False)
parser.set_defaults(update=False)

args = parser.parse_args()

if args.tor is True:
    ipcheck_url = 'https://api.ipify.org/'
    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, '127.0.0.1', 9050)
    socket.socket = socks.socksocket
    try:
        tor_ip = requests.get(ipcheck_url)
        tor_ip = str(tor_ip.text)

        print_out(Fore.WHITE + Style.BRIGHT + "TOR connection established!")
        print_out(Fore.WHITE + Style.BRIGHT + "New IP: " + tor_ip)

    except requests.exceptions.RequestException as e:
        print(e, net_exc)
        sys.exit(0)

if args.update is True:
    update()

def handle_reports(args):
    if args.report is not None or args.output:
        report_types = args.report if args.report else []
        generate_report(args.target, found_ips, report_types, args.output, cloudflare_domains)

try:

    # Initialize CloudFail
    init(args.target)

    # Scan DNSdumpster.com
    dnsdumpster(args.target)

    # Scan Crimeflare database
    crimeflare(args.target)

    # Scan subdomains with or without TOR
    subdomain_scan(args.target, None)

    # Generate report
    handle_reports(args)

except KeyboardInterrupt:
    sys.exit(0)