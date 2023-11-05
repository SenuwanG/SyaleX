import requests
import json
import subprocess
import time

def get_installed_packages():
    """Get a list of installed packages and their versions."""
    output = subprocess.check_output("dpkg -l", shell=True)
    lines = output.decode('utf-8').split('\n')
    packages = []
    for line in lines:
        if line.startswith('ii'):
            package_name = line.split()[1]
            package_version = line.split()[2]
            packages.append((package_name, package_version))
    return packages

def get_size_installed_software():
    """Get a list of installed software and their versions."""
    output = subprocess.check_output("dpkg -l", shell=True)
    lines = output.decode('utf-8').split('\n')
    packages = []
    for line in lines:
        if line.startswith('ii'):
            package_name = line.split()[1]
            package_version = line.split()[2]
            packages.append((package_name, package_version))
    size = len(packages)
    return size

def get_cve_data(package_name, package_version):
    """Get the CVE data for a package."""
    # Define the URL for the NVD API
    url = f'https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={package_name}+{package_version}&resultsPerPage=100'
    # Send a GET request to the NVD API using the requests library
    header = {"X-Api-Key": "619bf69-ee30-49e4-b5c2-7de43908683f"}
    response = requests.get(url, headers=header)
    # Check if the request was successful
    if response.status_code == 200:
        # Parse the JSON response
        data = response.json()
        cve_id=[]
        # Check if the software version is in the list of vulnerable versions
        for cpe in data['result']['CVE_Items']:
            cpe = cve['configurations']['nodes'][0]['cpe_match'][0]['cpe23Uri']
            if package_name in cpe and package_version in cpe:
                cve_id.append(cve['cve']['CVE_data_meta']['ID'])
            else:
                cve_id.append('No vulnerabilities found in {package_name} version {package_version}')
        return cve_id
    else:
        print(f'Error: Unable to connect to NVD API. Status code: {response.status_code}')
        return None
    
def progress_bar():
    """Display a progress bar."""
    for i in range(100):
        print(f"\rScanning: {i + 1}%", end="")
        time.sleep(0.1)
    print("\rScanning : 100%")

def main():
    i=0
    sizes = get_size_installed_software()
    print(f"Total packages: {sizes}")
    packages = get_installed_packages()
    for package_name, package_version in packages:
        i+=1
        print(f"\rProgress: {i/sizes*100}%", end="\n")
        #print(f"{package_name}: {package_version}")
        cve_data = get_cve_data(package_name, package_version)
        if cve_data:
            progress_bar()
            print(f'Vulnerability found for {package_name} version {package_version}: CVE-ID: {", ".join(cve_data)}')
        else:
            progress_bar()
            #print(f'No vulnerabilities found for {package_name} version {package_version}')
    print (f"\rProgress: 100%")    

if __name__ == "__main__":
    main()
