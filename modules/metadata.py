import magic
import os
from . import hashes
import datetime
import re


# print metadata of PE
def get(malware , mydoc):

    # header for METADATA
    h_main = mydoc.add_heading("METADATA",2)
    h_main.alignment = 0 # 0=left , 1=center , 2=right

    name = re.sub(r'.*/', '/', malware)[1:]

    paragraph_string = ("FileName: " + str(name)
                        + "\nFile size: " + str(os.path.getsize(malware)) 
                        + "\nFile type: " + str(os.path.getsize(malware)) 
                        + "\nMD5: " + str(hashes.get(malware)['md5']) 
                        + "\nSHA1: " + str(hashes.get(malware)['sha1']) 
                        + "\nSHA256: " + str(hashes.get(malware)['sha256']) 
                        + "\n\n")

    mydoc.add_paragraph(paragraph_string)
