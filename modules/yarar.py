import yara
import os
import sys
import string


# checks if the PE matches some YARA rules (database: ~/rules)


def get_yara(path):
    root_dir = os.path.dirname(sys.modules['__main__'].__file__)
    return os.path.join(root_dir, 'rules', path)


def get(malware, mydoc):

    h_main = mydoc.add_heading("YARA RULES VERIFICATION",2)
    h_main.alignment = 0

    paragraph_string = ""

    rules = yara.compile(filepaths={'AntiVM/DB': get_yara('Antidebug_AntiVM_index.yar'),
                                    'Crypto': get_yara('Crypto_index.yar'),
                                    'CVE': get_yara('CVE_Rules_index.yar'),
                                    'Exploit': get_yara('Exploit-Kits_index.yar'),
                                    'Document': get_yara('Malicious_Documents_index.yar'),
                                    'Malware': get_yara('malware_index.yar'),
                                    'Packers': get_yara('Packers_index.yar'),
                                    'Webshell': get_yara('Webshells_index.yar')})

    strings_list = []

    with open(malware, 'rb') as f:
        matches = rules.match(data=f.read())
    if matches:
        for x in matches:
            paragraph_string = (
                str(x.rule)
                + "\n\tType: " + str(x.namespace)
                + "\n\tTags: " + "".join(x.tags)
                + "\n\tMeta:"
                + "\n\t\tDate: " + str(x.meta.get('date'))
                + "\n\t\tVersion: " + str(x.meta.get('version'))
                + "\n\t\tDescription: " + str(x.meta.get('description'))
                + "\n\t\tAuthor: " + str(x.meta.get('author'))
            )
            if not x.strings:
                paragraph_string = paragraph_string + "\n\tStrings: " + "None"
            else:
                for i in x.strings:
                    strings_list.append(i[2])
                    paragraph_string = paragraph_string + "\n\tStrings: "
                for i in list(set(strings_list)):
                    if all(str(c) in string.printable for c in i):
                        paragraph_string = paragraph_string + "\n\t\t" + str(i) + "| Occurrences:" + str(strings_list.count(i))
                    else:
                        paragraph_string = paragraph_string + "\n\t\t[X] Not printable"
                del(strings_list[:])
        paragraph_string = paragraph_string + "\nYARA rules matched: " + str(len(matches)) 
    else:
        paragraph_string = paragraph_string + "\n[X]: None"

    paragraph_string = paragraph_string + "\n\n"

    mydoc.add_paragraph(paragraph_string)
