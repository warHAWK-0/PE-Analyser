import lief


# print exports of PE
def get(malware, mydoc):
    # header for EXPORTS
    h_main = mydoc.add_heading("EXPORTS",2)
    h_main.alignment = 0

    paragraph_string = ""
    binary = lief.parse(malware)
    count = 0
    try:
        for exported_library in binary.exports:
            count = count + 1
            paragraph_string = paragraph_string + exported_library.name
            for func in exported_library.entries:
                paragraph_string = (
                    paragraph_string
                    + func.address + " - "
                    + func.name
                )
            paragraph_string = paragraph_string + "\n"
        mydoc.add_paragraph(paragraph_string + "\n\n")

    except Exception as e:
        paragraph_string = "[x]: Cannot identify exports for this file"
        mydoc.add_paragraph(paragraph_string + "\n\n")
