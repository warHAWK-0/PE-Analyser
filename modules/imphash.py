import pefile
import sys
import os

def get_rule(path):
    root_dir = os.path.dirname(sys.modules['__main__'].__file__)
    return os.path.join(root_dir, 'signatures', path)


# print the imphash
def get(malware, mydoc):
    # header for IMPHASH
    h_main = mydoc.add_heading("IMPHASH",2)
    h_main.alignment = 0

    paragraph_string = ""

    try:
        pe = pefile.PE(malware)
        global susp_imp
        susp_imp = False
        paragraph_string = paragraph_string + "ImpHash: " + pe.get_imphash()

    except Exception:
        paragraph_string = paragraph_string + "ImpHash: Error detecting imphash"

    paragraph_string = paragraph_string + "\n\n"

    mydoc.add_paragraph(paragraph_string)
