import lief

# check if PE supports cookies on the stack (GS)


def get(malware, mydoc):
    h_main = mydoc.add_heading("STACK COOKIES",2)
    h_main.alignment = 0

    paragraph_string = ""

    binary = lief.parse(malware)
    if binary.has_configuration:
        if binary.load_configuration.security_cookie == 0:
            paragraph_string = "[X]: The file doesn't support cookies on the stack (GS)"
        else:
            paragraph_string = "[" + '\u2713' + "]: The file supports cookies on the stack (GS)"
    else:
        paragraph_string = " Binary has no configuration"

    mydoc.add_paragraph(paragraph_string + "\n\n")
