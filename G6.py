import subprocess
import requests
import socket
import time
import os
import json
import tkinter as tk
from flask import Flask, render_template_string

# List of dependencies to install
dependencies = [
    'subprocess',
    'requests',
    'socket',
    'time',
    'os',
    'json',
    'tkinter',
    'Flask',
]

# Install each dependency using pip
for package in dependencies:
    try:
        subprocess.check_call(['pip', 'install', package])
        print(f'Successfully installed {package}')
    except subprocess.CalledProcessError:
        print(f'Failed to install {package}')

print('Dependency installation complete.')

print("running......")
print("")

startTime = time.time()

# Replace 'your_api_key' with your actual API key
api_key = '4619bf69-ee30-49e4-b5c2-7de43908683f'

import subprocess

def get_installed_software():
    try:
        # Run the 'dpkg --list' command for Debian-based distributions
        output = subprocess.check_output(['dpkg', '--list']).decode('utf-8')
    except subprocess.CalledProcessError:
        try:
            # Run the 'rpm -qa' command for Red Hat-based distributions
            output = subprocess.check_output(['rpm', '-qa']).decode('utf-8')
        except subprocess.CalledProcessError:
            return []

    # Parse the output to extract the names and versions of the installed software packages
    installed_software = []
    for line in output.split('\n'):
        if line.startswith('ii'):
            software_name = line.split()[1]
            software_version = line.split()[2]
            installed_software.append((software_name, software_version))

    return installed_software

# Print the list of installed software with their versions
installed_software = get_installed_software()
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
            else:
                print(f'No vulnerabilities found for {software_name} version {software_version}')
    else:
        print(f'Error: Unable to connect to NVD API. Status code: {response.status_code}')
        time.sleep(20)
    time.sleep(6)
print('Time taken:', time.time() - startTime)




subprocess.run(["sudo", "./lynis", "audit", "system", "--quick"], shell=True)


def check_port(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)  # Adjust the timeout as needed
    result = sock.connect_ex((host, port))
    sock.close()
    return result == 0

def find_open_ports(host, start_port, end_port):
    open_ports = []
    for port in range(start_port, end_port + 1):
        if check_port(host, port):
            open_ports.append(port)
    return open_ports

if __name__ == "__main__":
    target_host = "localhost"  # Replace with the target host or IP address
    start_port = 1
    end_port = 65535  # Adjust the range as needed

    open_ports = find_open_ports(target_host, start_port, end_port)

    if open_ports:
        print(f"Open ports on {target_host}: {open_ports}")
    else:
        print(f"No open ports found on {target_host}")

warnings_output = subprocess.check_output("sudo cat /var/log/lynis-report.dat | grep warning | sed -e 's/warning\\[\\]=//g' -e 's/|-|-|//g'", shell=True, universal_newlines=True)
warnings = warnings_output.splitlines()

suggestions_output = subprocess.check_output("sudo cat /var/log/lynis-report.dat | grep suggestion | sed -e 's/suggestion\\[\\]=//g' -e 's/|-|-|//g'", shell=True, universal_newlines=True)
suggestions = suggestions_output.splitlines()

packages_output = subprocess.check_output("sudo cat /var/log/lynis-report.dat | grep installed_package | sed -e 's/installed_package\\[\\]=//g' -e 's/|-|-|//g'", shell=True, universal_newlines=True)
packages = packages_output.splitlines()


shells_output = subprocess.check_output("sudo cat /var/log/lynis-report.dat | grep available_shell | sed -e 's/available_shell\\[\\]=//g' -e 's/|-|-|//g'", shell=True, universal_newlines=True)
shells = shells_output.splitlines()

app = Flask(__name__)

@app.route('/')
def display_data():
    results = f"<h1>System Information</h1><br><br><h2>Open ports:</h2><ul>"
    for port in open_ports:
        results += f"<li>{port}</li>"
    results += "</ul><br><h2>Warnings:</h2><ul>"
    for warning in warnings:
        results += f"<li>{warning}</li>"
    results += "</ul><br><h2>Suggestions:</h2><ul>"
    for suggestion in suggestions[1:]:
        results += f"<li>{suggestion}</li>"
    results += "</ul><br><h2>Packages:</h2><ul>"
    for package in packages:
        results += f"<li>{package}</li>"
    for shell in shells:
        results += f"<li>{shell}</li>"
    results += "</ul>"
    
    
    return render_template_string(f"""
        <html>
            <head>
                <title>System Information</title>
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        margin: 0;
                        padding: 0;
                    }}
                    h1 {{
                        background-color: #4CAF50;
                        color: white;
                        margin: 0;
                        padding: 20px;
                        text-align: center;
                    }}
                    h2 {{
                        font-size: 24px;
                        margin: 0;
                        padding: 10px;
                    }}
                    ul {{
                        list-style-type: none;
                        margin: 0;
                        padding: 0;
                    }}
                    li {{
                        margin: 0;
                        padding: 10px;
                        border-bottom: 1px solid #ddd;
                    }}
                    p {{
                        margin: 0;
                        padding: 10px;
                    }}
                </style>
            </head>
            <body>
                {results}
            </body>
        </html>
    """)
    

if __name__ == '__main__':
    app.run()
