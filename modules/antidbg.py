import os
import lief
import sys


# check for anti-debugging calls

def get_rule(path):
    root_dir = os.path.dirname(sys.modules['__main__'].__file__)
    return os.path.join(root_dir, 'signatures', path)


def get(malware, mydoc):
    # header for ANTI-DEBUGGGING CALLS
    h_main = mydoc.add_heading("ANTI DEBUGGING CALLS",2)
    h_main.alignment = 0

    paragraph_string = ""

    antidbg = []
    count = 0
    with open(get_rule('antidbg.txt')) as f:
        content = [x for x in (line.strip() for line in f) if x]
    try:
        binary = lief.parse(malware)
        for imported_library in binary.imports:
            for func in imported_library.entries:
                for susp in content:
                    if func.name == susp:
                        count += 1
                        antidbg.append(susp)
        if count > 0:
            for x in antidbg:
                paragraph_string = paragraph_string + x + "\n"
        else:
            paragraph_string = paragraph_string + "[X]: None \n"
        f.close()

        paragraph_string = paragraph_string + "\nTotal Anti-debug calls: " + str(count)
        mydoc.add_paragraph(paragraph_string)

    except Exception as e:
        print(e)
