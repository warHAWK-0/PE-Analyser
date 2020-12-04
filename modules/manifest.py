import lief

# check whether the PE has a manifest


def get(malware, mydoc):
    h_main = mydoc.add_heading("ASSEMBLY MANIFEST",2)
    h_main.alignment = 0

    paragraph_string = ""

    binary = lief.parse(malware)
    if binary.has_resources and not binary.resources_manager.has_manifest:
        paragraph_string = "[X]: None"
    else:
        paragraph_string = "[" + '\u2713' + "]: PE has a manifest\n" + str(binary.resources_manager.manifest)

    mydoc.add_paragraph(paragraph_string + "\n\n")
