# imports
import docx
import time
from modules import header
from modules import metadata
from modules import fileheader
from modules import optheader
from modules import sections
from modules import imphash
from modules import imports
from modules import exports
from modules import antidbg
from modules import antivm
from modules import apialert
from modules import codeint
from modules import cfg
from modules import dep
from modules import aslr
from modules import seh
from modules import tls
from modules import gs
from modules import codeint
from modules import dbgts
from modules import url
from modules import manifest
from modules import version
from modules import packed
from modules import virustotal
from modules import yarar

def get(malware, mydoc, progress_bar):
    progress_bar.UpdateBar(0,27)
    
    header.get(mydoc)
    progress_bar.UpdateBar(1,27)
    
    metadata.get(malware, mydoc)
    progress_bar.UpdateBar(2,27)
    progress_bar.UpdateBar(3,27)
    
    optheader.get(malware, mydoc)
    progress_bar.UpdateBar(4,27)
    
    sections.get(malware, mydoc)
    progress_bar.UpdateBar(5,27)
    
    imphash.get(malware, mydoc)
    progress_bar.UpdateBar(6,27)
    
    imports.get(malware, mydoc)
    progress_bar.UpdateBar(7,27)
    
    exports.get(malware, mydoc)
    progress_bar.UpdateBar(8,27)
    
    antidbg.get(malware, mydoc)
    progress_bar.UpdateBar(9,27)
    
    antivm.get(malware, mydoc)
    progress_bar.UpdateBar(10,27)
    
    apialert.get(malware, mydoc)
    progress_bar.UpdateBar(11,27)
    
    codeint.get(malware, mydoc)
    progress_bar.UpdateBar(12,27)
    
    cfg.get(malware, mydoc)
    progress_bar.UpdateBar(13,27)
    
    dep.get(malware, mydoc)
    progress_bar.UpdateBar(14,27)
    
    aslr.get(malware, mydoc)
    progress_bar.UpdateBar(15,27)
    
    seh.get(malware, mydoc)
    progress_bar.UpdateBar(16,27)
    
    gs.get(malware, mydoc)
    progress_bar.UpdateBar(17,27)
    
    tls.get(malware, mydoc)
    progress_bar.UpdateBar(18,27)
    progress_bar.UpdateBar(19,27)

    dbgts.get(malware, mydoc)
    progress_bar.UpdateBar(20,27)

    # url.get(malware, mydoc)
    manifest.get(malware, mydoc)
    progress_bar.UpdateBar(21,27)

    version.get(malware, mydoc)
    progress_bar.UpdateBar(22,27)
    ## badstr.get(malware)

    packed.get(malware, mydoc)
    progress_bar.UpdateBar(23,27)

    ## certificate.get(malware)
    virustotal.get(malware, mydoc)
    progress_bar.UpdateBar(25,27)

    # yarar.get(malware, mydoc)
    progress_bar.UpdateBar(26,27)

    progress_bar.UpdateBar(27,27)