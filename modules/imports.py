import lief

# print imports of PE

def get(malware,mydoc):
    # header for IMPORTS
    h_main = mydoc.add_heading("IMPORTS",2)
    h_main.alignment = 0

    paragraph_string = ""
    
    binary = lief.parse(malware)
    for imported_library in binary.imports:
        for func in imported_library.entries:
            paragraph_string = (
                paragraph_string
                + "\t 0x" + str(func.iat_address) + ": " + func.name + "\n"
            )

    paragraph_string = paragraph_string + "\n"

    mydoc.add_paragraph(paragraph_string)