import os
import sys
import lief

# checks for suspicious calls


def get_rule(path):
    root_dir = os.path.dirname(sys.modules['__main__'].__file__)
    return os.path.join(root_dir, 'signatures', path)


def get(malware, mydoc):
    # header for API CALLS
    h_main = mydoc.add_heading("SUSPICIOUS CALLS",2)
    h_main.alignment = 0

    paragraph_string = ""


    suspicious_api = []
    count = 0
    with open(get_rule('alerts.txt')) as f:
        content = [x for x in (line.strip() for line in f) if x]
    try:
        binary = lief.parse(malware)
        for imported_library in binary.imports:
            for func in imported_library.entries:
                for susp in content:
                    if func.name == susp:
                        count += 1
                        suspicious_api.append(susp)
        if count > 0:
            for x in suspicious_api:
                paragraph_string = paragraph_string + x +"\n"
        else:
            paragraph_string = paragraph_string + "No of api calls: " + str(count) + "\n\n"
        f.close()

        mydoc.add_paragraph(paragraph_string)

    except Exception as e:
        print(e)
