import lief

# print PE sections
def get(malware, mydoc):
    # header for SECTIONS
    h_main = mydoc.add_heading("SECTIONS",2)
    h_main.alignment = 0

    paragraph_string = ""

    sec = 0
    susp_sec = 0
    binary = lief.parse(malware)

    for section in binary.sections:
        sec += 1

        paragraph_string = (
            paragraph_string
            + str(section)
            + "\n\tVirtual Address: " + str(section.virtual_address)
            + "\n\tVirtual Size: " + str(section.virtual_size) + " bytes"
            + "\n\tRaw Size: " + str(section.sizeof_raw_data) + " bytes"
            + "\n\tEntropy: " + str(section.entropy)
            + "\n"
        )

        if section.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_READ):
            paragraph_string = paragraph_string + "\n \tReadable: " + "[" + str('\u2713') + "]"
        else:
            paragraph_string = paragraph_string + "\n \tReadable: " + "[X]"


        if section.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE):
            paragraph_string = paragraph_string + "\n \tWritable: " + "[" + str('\u2713') + "]"
        else:
            paragraph_string = paragraph_string + "\n \tWritable: " + "[X]"

        if section.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE):
            paragraph_string = paragraph_string + "\n \tExecutable: " + "[" + str('\u2713') + "]"
        else:
            paragraph_string = paragraph_string + "\n \tExecutable: " + "[X]"

        if section.size == 0 or (0 < section.entropy < 1) or section.entropy > 7:
            paragraph_string = paragraph_string + "\n \tSuspicious: " + "[" + str('\u2713') + "]" +"\n"
            susp_sec += 1
        else:
            paragraph_string = paragraph_string + "\n \tSuspicious: " + "[X]\n"

    # suspicious section based on entropy
    paragraph_string = (
        paragraph_string 
        + "\n Suspicious section (entropy) ratio:" + " %i/%i" % (susp_sec, sec)
    )

    # suspicious section names
    standardSectionNames = [".text", ".bss", ".rdata",
                            ".data", ".idata", ".reloc", ".rsrc"]
    suspiciousSections = 0
    for section in binary.sections:
        if not section.name in standardSectionNames:
            suspiciousSections += 1

    paragraph_string = (
        paragraph_string 
        + "\n Suspicious section (name) ratio:" + " %i/%i" % (suspiciousSections, sec)
    )
    paragraph_string = paragraph_string + "\n\n"

    mydoc.add_paragraph(paragraph_string)