#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
from . import stringstat

# check for presence of IP/URL in PE

def valid_ip(address):
    try:
        host_bytes = address.split('.')
        valid = [int(b) for b in host_bytes]
        valid = [b for b in valid if b >= 0 and b <= 255]
        return len(host_bytes) == 4 and len(valid) == 4
    except:
        return False


def get(malware, mydoc):
    h_main = mydoc.add_heading("URL's",2)
    h_main.alignment = 0

    paragraph_string = ""

    ip_list = []
    file_list = []
    url_list = []
    strings_list = list(stringstat.get_result(malware))

    # Strings analysis
    for string in strings_list:

        if len(string) < 2000:
            # URL list
            urllist = re.findall(
                r'((smb|srm|ssh|ftps?|file|https?):((//)|(\\\\))+([\w\d:#@%/;$()~_?\+-=\\\.&](#!)?)*)', string, re.MULTILINE)
            if urllist:
                for url in urllist:
                    url_list.append(re.sub(r'\(|\)|;|,|\$', '', url[0]))

            # IP list
            iplist = re.findall(r'[0-9]+(?:\.[0-9]+){3}', string, re.MULTILINE)
            if iplist:
                for ip in iplist:
                    if valid_ip(str(ip)) and not re.findall(r'[0-9]{1,}\.[0-9]{1,}\.[0-9]{1,}\.0', str(ip)):
                        ip_list.append(str(ip))

            # FILE list
            fname = re.findall("(.+(\.([a-z]{2,3}$)|\/.+\/|\\\.+\\\))+", string, re.IGNORECASE | re.MULTILINE)
            if fname:
                for word in fname:
                    file_list.append(word[0])

    ip_list = list(set([item for item in ip_list]))
    url_list = list(set([item for item in url_list]))

    if url_list:
        paragraph_string = "\nTotal Url found: " + len(url_list)
        paragraph_string = "\n".join(url_list)
    else:
        paragraph_string = paragraph_string + "\n[X]: No URL"


    h_main2 = mydoc.add_heading("IP",2)
    h_main2.alignment = 0

    if ip_list:
        paragraph_string = "\nTotal Url found: " + len(ip_list)
        paragraph_string = "\n".join(ip_list)
    else:
        paragraph_string = paragraph_string + "\n[X]: None"

    mydoc.add_paragraph(paragraph_string + "\n\n")
