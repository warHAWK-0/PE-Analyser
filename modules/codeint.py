import lief

def get(malware, mydoc):
    h_main = mydoc.add_heading("CODE INTEGRITY",2)
    h_main.alignment = 0

    paragraph_string = ""

    binary = lief.parse(malware)
    if binary.has_configuration:
        if isinstance(binary.load_configuration, lief.PE.LoadConfigurationV2) and binary.load_configuration.code_integrity.catalog == 0xFFFF:
            paragraph_string = "[X]: The file doesn't support Code Integrity"
        else:
            "[" + '\u2713' + "]: The file supports Code Integrity"
    else:
        paragraph_string = "[X]: Binary has no configuration"

    mydoc.add_paragraph(paragraph_string + "\n\n")
