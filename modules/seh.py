import lief

# check if PE file use Structured Error Handling (SEH)


def get(malware, mydoc):
    h_main = mydoc.add_heading("STRUCTURED ERROR HANDLING",2)
    h_main.alignment = 0

    paragraph_string = ""

    binary = lief.parse(malware)
    if binary.optional_header.has(lief.PE.DLL_CHARACTERISTICS.NO_SEH):
        paragraph_string = "[X]: The file doesn't support Structured Exception Handling (SEH)"
    else:
        paragraph_string = "[" + '\u2713' + "]: The file supports Structured Exception Handling (SEH)"

    mydoc.add_paragraph(paragraph_string + "\n\n")