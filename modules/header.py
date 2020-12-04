import docx

def get(mydoc):
    
    h_main = mydoc.add_heading("Malware Analysis",0)
    h_main.alignment = 1 # 0=left , 1=center , 2=right
    h_sub = mydoc.add_paragraph("This report is auto-generated")
    h_sub.alignment = 1

