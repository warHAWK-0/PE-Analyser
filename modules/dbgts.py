import lief
import datetime

# check for suspicious debug timestamps
def get(malware, mydoc):
    h_main = mydoc.add_heading("DEBUG TIMESTAMPS",2)
    h_main.alignment = 0

    paragraph_string = ""

    binary = lief.parse(malware)
    try:
        if binary.has_debug:
            dbg_time = datetime.datetime.fromtimestamp(binary.debug.timestamp)
            if dbg_time > datetime.datetime.now():
                paragraph_string = '[' + '\u2713' + "]" + " The age (%s) of the debug file is suspicious" % (str(dbg_time))

            else:
                paragraph_string = "[X]: Not Suspicious"
        else:
            paragraph_string = "[X] PE has not debug object"
    except Exception as e:
        paragraph_string = "[X] Can't Determine"


    mydoc.add_paragraph(paragraph_string + "\n\n")
