import re

# check for virtual-machine detection
def get(malware, mydoc):
    # header for EXPORTS
    h_main = mydoc.add_heading("VIRTUAL ENVIRONMENT",2)
    h_main.alignment = 0

    paragraph_string = ""

    trk = []
    count = 0
    VM_Str = {
        "Virtual Box": "VBox",
        "VMware": "WMvare"
    }

    VM_Sign = {
        "Red Pill": "\x0f\x01\x0d\x00\x00\x00\x00\xc3",
        "VirtualPc trick": "\x0f\x3f\x07\x0b",
        "VMware trick": "VMXh",
        "VMCheck.dll": "\x45\xC7\x00\x01",
        "VMCheck.dll for VirtualPC": "\x0f\x3f\x07\x0b\xc7\x45\xfc\xff\xff\xff\xff",
        "Xen": "XenVMM",
        "Bochs & QEmu CPUID Trick": "\x44\x4d\x41\x63",
        "Torpig VMM Trick": "\xE8\xED\xFF\xFF\xFF\x25\x00\x00\x00\xFF\x33\xC9\x3D\x00\x00\x00\x80\x0F\x95\xC1\x8B\xC1"
                            "\xC3",
        "Torpig (UPX) VMM Trick": "\x51\x51\x0F\x01\x27\x00\xC1\xFB\xB5\xD5\x35\x02\xE2\xC3\xD1\x66\x25\x32\xBD\x83"
                                  "\x7F\xB7\x4E\x3D\x06\x80\x0F\x95\xC1\x8B\xC1\xC3 "
    }

    with open(malware, "r", errors='replace') as f:
        buf = f.read()
        for string in VM_Str:
            match = re.findall(VM_Str[string], buf,
                               re.IGNORECASE | re.MULTILINE)
            if match:
                trk.append(string)

        for trick in VM_Sign:
            if buf.find(VM_Sign[trick][::-1]) > -1:
                count += 1
                trk.append(trick)
        
        paragraph_string = paragraph_string + "Total VM Tricks: " + str(count)
