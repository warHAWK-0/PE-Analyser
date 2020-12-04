from lief import PE
import lief

# print PE optionals header

def get(malware , mydoc):
    # header for OPPTIONAL HEADER
    h_main = mydoc.add_heading("OPTIONAL HEADER",2)
    h_main.alignment = 0 # 0=left , 1=center , 2=right

    binary = lief.parse(malware)
    optional_header = binary.optional_header

    dll_char_str = " - ".join([str(chara).split(".")[-1]
                               for chara in optional_header.dll_characteristics_lists])

    subsystem_str = str(optional_header.subsystem).split(".")[-1]
    magic = "PE32" if optional_header.magic == PE.PE_TYPE.PE32 else "PE64"

    paragraph_string = (
        "Magic:" + magic
        + "\nMajor linker version:" + str(optional_header.major_linker_version)
        + "\nMinor linker version:" + str(optional_header.minor_linker_version)
        + "\nSize of code:" + str(optional_header.sizeof_code) + " bytes"
        + "\nSize of initialized data:" + str(optional_header.sizeof_initialized_data) + " bytes"
        + "\nize of uninitialized data:" + str(optional_header.sizeof_uninitialized_data) + " bytes"
        + "\nEntry point:" + str(optional_header.addressof_entrypoint)
        + "\nBase of code:" + str(optional_header.baseof_code)
    )

    if magic == "PE32":
        paragraph_string = (
            paragraph_string
            + "\nBase of data" + str(optional_header.baseof_data)
            + "\nImage base:" + str(optional_header.imagebase)
            + "\nSection alignment:" + str(optional_header.section_alignment)
            + "\nFile alignment:" + str(optional_header.file_alignment)
            + "\nMajor operating system version:" + str(optional_header.major_operating_system_version)
            + "\nMinor operating system version:" + str(optional_header.minor_operating_system_version)
            + "\nSize of headers:" + str(optional_header.sizeof_headers) + " bytes"
            + "\nChecksum:" +  str(optional_header.checksum) + " bytes"
            + "\nSubsystem:" + str(subsystem_str)
            + "\nDLL Characteristics:" + str(dll_char_str)
            + "\nLoader flags:" + str(optional_header.loader_flags)
            + "\nNumber of RVA and size:" + str(optional_header.numberof_rva_and_size)
        )
    paragraph_string = paragraph_string + "\n\n"

    mydoc.add_paragraph(paragraph_string)

