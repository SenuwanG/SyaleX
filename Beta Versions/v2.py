#this works

import requests
import time

startTime = time.time()

# Replace 'your_api_key' with your actual API key
api_key = '4619bf69-ee30-49e4-b5c2-7de43908683f'

# Define the software you want to check for vulnerabilities
software_name = 'sudo'
software_version = '1.9.5p2'

# Define the URL for the NVD API
url = f'https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={software_name}&resultsPerPage=100'

# Send a GET request to the NVD API using the requests library
response = requests.get(url, headers={'X-Api-Key': api_key})

# Check if the request was successful
if response.status_code == 200:
    # Parse the JSON response
    data = response.json()

    # Check if the software version is in the list of vulnerable versions
    for item in data['result']['CVE_Items']:
        cve_description = item['cve']['description']['description_data'][0]['value']
        if software_version in cve_description:
            print(f'Vulnerability found for {software_name} version {software_version}: {cve_description}')
            break
    else:
        print(f'No vulnerabilities found for {software_name} version {software_version}')
else:
    print(f'Error: Unable to connect to NVD API. Status code: {response.status_code}')
print('Time taken:', time.time() - startTime)

