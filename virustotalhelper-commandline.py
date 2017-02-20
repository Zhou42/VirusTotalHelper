import urllib
import json
import requests
import pprint
import time

apikey = "1e485224849dd525aa4362d26b1bab3437974c18597157e0d8a316c62b0aebee"

def count_detection_mapping(engine):
    if (engine['detected']):
        return 1
    else:
        return 0

def add(x, y): return x + y 


serviceurl = "https://www.virustotal.com/vtapi/v2/file/report"
headers = { "Accept-Encoding": "gzip, deflate" }

filename = raw_input('Enter input file name: ')

if len(filename) < 1:
    filename = "sample_hash_input.txt"

fread = open(filename, "r")
fwrite = open("res.data", "w")

count = 0

for line in fread:
    # Avoid reaching the query limit
    time.sleep(16)
    
    try:
        # query each md5 hash
        params = {'apikey': apikey, 'resource': line.strip()}
        response = requests.post('https://www.virustotal.com/vtapi/v2/file/report', params = params)
        json_response = response.json()
        if (json_response['response_code'] == 1):
            if json_response['scans']['Fortinet']['result'] == None:
                Fortinet_detection = 'None'
            else:
                Fortinet_detection = json_response['scans']['Fortinet']['result']
            detected_engine_number = reduce(add, map(count_detection_mapping, json_response['scans'].values()), 0)
            result = json_response['md5'] + '|' + Fortinet_detection + '|' + str(detected_engine_number) + '|' + json_response['scan_date'] + '|'
            fwrite.write(result)
        else:
            fwrite.write("File with hash " + params['resource'] + " not present in the file store!")
        fwrite.write('\n')
    except:
        pass
    
fread.close()
fwrite.close()