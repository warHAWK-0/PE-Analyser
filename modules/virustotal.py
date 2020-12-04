from . import hashes
import requests
from . import const

# check the md5 hash of pe file with the VirusTotal Database

def get(malware, mydoc):
    h_main = mydoc.add_heading("VIRUSTOTAL SCAN",2)
    h_main.alignment = 0

    para = mydoc.add_paragraph()

    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': const.getVirustotalApiKey(),  
              'resource': hashes.get(malware)['md5']}

    if params['apikey']:
        response = requests.get(url, params=params)
        result = response.json()
        if result['response_code'] == 0:
            para.add_run("Malware Possibility: 0%").bold = True
        else:
            paragraph_string = "[" + '\u2713' + "]: Found Match"
            para.add_run(
                "\n Resource: " + result['resource']
                + "\n First detected on: " + str(result['scan_date'])
            )

            para.add_run("\n Malware Possibility: " + str(result['positives']/result['total']) + "%").bold = True


    else:
        paragraph_string = "[X]:  API token not found"

    paragraph_string = paragraph_string + "\n\n"

    mydoc.add_paragraph(paragraph_string)
