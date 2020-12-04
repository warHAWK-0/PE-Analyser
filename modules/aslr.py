import lief

# check if PE support for Address Space Layout Randomization


def get(malware, mydoc):
    h_main = mydoc.add_heading("ASLR",2)
    h_main.alignment = 0

    paragraph_string = ""

    binary = lief.parse(malware)
    if binary.optional_header.has(lief.PE.DLL_CHARACTERISTICS.DYNAMIC_BASE):
        paragraph_string = "[" + '\u2713' + "]: The file supports Address Space Layout Randomization (ASLR)"
    else:
        paragraph_string = "[X]: The file doesn't supports Address Space Layout Randomization (ASLR)"

    mydoc.add_paragraph(paragraph_string + "\n\n")
