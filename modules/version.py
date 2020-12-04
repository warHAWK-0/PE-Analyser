import lief
# check if PE has a version
def get(malware, mydoc):
    h_main = mydoc.add_heading("VERSION",2)
    h_main.alignment = 0

    paragraph_string = ""

    binary = lief.parse(malware)
    if binary.has_resources and not binary.resources_manager.has_version:
        paragraph_string = "[X]: PE has no version"
    else:
        paragraph_string = "[" + '\u2713' + "]: PE has a version\n" + str(binary.resources_manager.version.string_file_info)

    mydoc.add_paragraph(paragraph_string + "\n\n")
