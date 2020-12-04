import pefile
import sys
import peutils
import os


# check if the PE is packed


def get_rule(path):
    root_dir = os.path.dirname(sys.modules['__main__'].__file__)
    return os.path.join(root_dir, 'signatures', path)


def get(malware, mydoc):
    # We use a list of the most common signature (signatureDB.txt), credits goes to creators of PEid "BobSoft"
    # get all possible matches found as the signature tree is walked.
    # The last signature will always be the most precise (as more bytes will have been matched)
    # and is the one returned by the match() method.

    h_main = mydoc.add_heading("PE PACKERS",2)
    h_main.alignment = 0

    paragraph_string = ""

    try:
        pe = pefile.PE(malware)
        signatures = peutils.SignatureDatabase(get_rule('packers.txt'))
        matches = signatures.match_all(pe, ep_only=True)
        array = []
        if matches:
            for item in matches:
                if item[0] not in array:
                    array.append(item[0])
                    paragraph_string = "".join(array)
        else:
            paragraph_string = "[X]: No packers signatures detected"
        
        mydoc.add_paragraph(paragraph_string + "\n\n")

    except Exception as e:
        print(e)
