import lief

# print the PE header


def get(malware , mydoc):
    # header for FILE HEADER
    h_main = mydoc.add_heading("FILE HEADER",2)
    h_main.alignment = 0 # 0=left , 1=center , 2=right

    binary = lief.parse(malware)
    header = binary.header

    paragraph_string = ""

    try:
        char_str = " - ".join([str(chara).split(".")[-1] for chara in header.characteristics_list])

        paragraph_string = ("Signature: " + "".join(map(chr, header.signature))
                            + "\n Machine: " + str(header.machine)
                            + "\n Number of sections: " + str( header.numberof_sections)
                            + "\n DateTime Stamp: " + str(header.time_date_stamps)
                            + "\n Size of optional header:" + str(header.sizeof_optional_header)
                            + "\n Characteristics:" + char_str
                            )
    except Exception as e:
        paragraph_string = "[X] Can't Determine"

    mydoc.add_paragraph(paragraph_string  + "\n\n")

