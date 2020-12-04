import lief

# check if PE file supports control flow guard
def get(malware, mydoc):
    # header for CFG
    h_main = mydoc.add_heading("CONTROL FLOW GUARD",2)
    h_main.alignment = 0

    paragraph_string = ""

    binary = lief.parse(malware)
    if binary.optional_header.has(lief.PE.DLL_CHARACTERISTICS.GUARD_CF):
        paragraph_string = "[" + '\u2713' + "]: The file supports Control Flow Guard (CFG)"
    else:
        paragraph_string = "[X]: The file doesn't support Control Flow Guard (CFG)"

    mydoc.add_paragraph(paragraph_string + "\n\n")
