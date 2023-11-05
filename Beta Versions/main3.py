import requests
import time
import pdfkit
def get_installed_software():
    """Get a list of installed software and their versions."""
    installed_software = []
    output = subprocess.check_output("dpkg -l", shell=True)
    for line in output.split('\n'):
        if line.startswith('ii'):
            software_name = line.split()[1]
            software_version = line.split()[2]
            installed_software.append((software_name, software_version))
    return installed_software
# Print the list of installed software with their versions & vulnerabilities
installed_software = get_installed_software()
startTime = time.time()
vulnerable_software = []
non_vulnerable_software = []
for software_name, software_version in installed_software:
    print(f"{software_name}: {software_version}")
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
                vulnerable_software.append((software_name, software_version, cve_description))
                break
        else:
            print(f'No vulnerabilities found for {software_name} version {software_version}')
            non_vulnerable_software.append((software_name, software_version))
    else:
        print(f'Error: Unable to connect to NVD API. Status code: {response.status_code}')
# Generate a PDF report
pdfkit.from_string(f'Vulnerable software:\n{vulnerable_software}\n\nNon-vulnerable software:\n{non_vulnerable_software}', 'software_vulnerabilities.pdf')
print(f'PDF report generated in {time.time() - startTime} seconds.')