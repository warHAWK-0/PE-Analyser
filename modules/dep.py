import lief

# check if PE supports Data Execution Prevention


def get(malware, mydoc):
    h_main = mydoc.add_heading("DATA EXECUTION PREVENTION",2)
    h_main.alignment = 0

    paragraph_string = ""

    binary = lief.parse(malware)
    if binary.optional_header.has(lief.PE.DLL_CHARACTERISTICS.NX_COMPAT):
        paragraph_string = "[" + '\u2713' + "]: The file supports Data Execution Prevention (DEP)"
    else:
        paragraph_string = "[X]: The file doesn't supports Data Execution Prevention (DEP)"

    mydoc.add_paragraph(paragraph_string + "\n\n")
