import lief

# malwares employ Thread Local Storage callbacks to evade debugger messages
def get(malware, mydoc):
    h_main = mydoc.add_heading("THREAD LOCAL STORAGE",2)
    h_main.alignment = 0

    paragraph_string = ""

    binary = lief.parse(malware)
    if not binary.has_tls:
        paragraph_string = "[X]: None"

    else:
        table_entry_address = binary.tls.addressof_callbacks
        callback = binary.get_content_from_virtual_address(
            table_entry_address, 4)
        callback = '0x' + "".join(["{0:02x}".format(x)
                                   for x in callback[::-1]])
        while int(callback, 16) != 0:
            paragraph_string = (
                paragraph_string + '\t' + callback
            )
            table_entry_address += 4
            callback = binary.get_content_from_virtual_address(table_entry_address, 4)
            callback = '0x' + "".join(["{0:02x}".format(x) for x in callback])
    
    mydoc.add_paragraph(paragraph_string + "\n\n")
