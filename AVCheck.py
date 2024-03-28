import os
import subprocess
import sys
from urllib.parse import urlparse
import requests
import json
from bs4 import BeautifulSoup
import re
import platform
import io
from colorama import init, AnsiToWin32

def display_header():
    print("""Dear User,

Welcome to our "Automatic Vulnerability Check" tool designed for seamless automation. To ensure smooth functionality, please make sure you have the following tools installed:

- Dirsearch
- Nuclei Scans
- CMS Detection
- TestSSL
- Nmap Scan


""")
    print("                                                         ")
    print("   A      V   V   CCCCC    H   H  EEEEE  CCCC   K    K   ")
    print("  A A     V   V   C        H   H  E      C      K  K     ")
    print(" A   A    V   V   C        HHHHH  EEEE   C      K K      ")
    print(" AAAAA     V V    C        H   H  E      C      K  K     ")
    print(" A   A      V     CCCCC    H   H  EEEEE  CCCC   K    K   ")
    
    print("=========================================================")
    print("                                                 ")
    print(" ************ AUTOMATIC VULNERABILITY Check ************ ")
    print("Developed by  : Abhishek Yadav   ")
    print("*********************************************************")
    print('''
    
    ''')

# Display the graphical header
display_header()

# Ask the user to create a subfolder for the project
subfolder = input("Enter the name of the subfolder for the project: ")
'''# Prompt the user for the target website or IP address
website = input("Enter the website or IP address to scan (Example: https://test.example.com): ")
subdomain = input("Enter the subdomain: ")
domain= input("Enter the domain: ")'''


def check_and_update_redirect(url):
    try:
        response = requests.head(url, allow_redirects=True)
        final_url = response.url
        if final_url != url:
            print(f"URL redirected to: {final_url}")
            return final_url
        else:
            return url
    except requests.RequestException as e:
        print(f"Error checking redirection: {e}")
        return url

# Prompt the user for the target website or IP address
website = input("Enter the website or IP address to scan (Example: https://test.example.com): ")
website = check_and_update_redirect(website)

# Extract subdomain and domain from the final URL
parsed_url = urlparse(website)
subdomain = parsed_url.hostname.split('.')[0] if '.' in parsed_url.hostname else ''
domain = '.'.join(parsed_url.hostname.split('.')[1:])

dirb_file_path= input("Please enter the path for directory discovery file(Example: /home/kali/Desktop/Dirbuster_Word_lists/ApacheTomca.txt): ")

output_directory = os.path.join("scan_results", subfolder)

# Create the output directory if it doesn't exist
os.makedirs(output_directory, exist_ok=True)

# Function to run a command with real-time output
def run_command(command, output_file):
    print(f"Running {command}...")
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, text=True)
    with open(os.path.join(output_directory, output_file), 'w') as f:
        f.write(result.stdout)
    print(f"{command} complete.")

init(wrap=False)

def strip_ansi_codes(text):
    # Use a regular expression to remove ANSI escape codes
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)
    
    
 

# Case 1: Directories discovery using Dirsearch
def discover_directories(url):
    
    tool_name = "Dirsearch"
    output_file = os.path.join(output_directory, f'{tool_name.lower()}_results.txt')
    command = f"dirsearch -q -u {url} -o {output_directory}/dirsearch.txt"

    try:
        # Write the command to the output file
        with open(output_file, 'w') as f:
            f.write(f"Running command: {command}\n\n")

        # Print the command to the console
        print(f"Running command: {command}")

        # Run Dirsearch using subprocess.Popen to capture real-time output
        with subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) as process:
            # Print real-time output to console
            for line in iter(process.stdout.readline, ''):
                print(line.strip())
                # Write the line to the output file
                with open(output_file, 'a') as f:
                    f.write(line)

        # Display completion message
        print(f"{tool_name} complete. Output saved in {output_file}\n")
    except Exception as e:
        print(f"Error during running {tool_name}: {e}")

    
    

# Function to run Nuclei scan
def run_nuclei_scan(scan_type, url):
    output_file = os.path.join(output_directory, f'nuclei_{scan_type}_results.txt')
    command = f'nuclei -t {scan_type} -u {url} -o {output_file}'
    print(command)

    # Write the command to the output file
    with open(output_file, 'w') as f:
        f.write(f"Running command: {command}\n\n")

    # Print the command to the console
    print(f"Running command: {command}")

    # Run the Nuclei command
    subprocess.run(command, shell=True)
# Call the Nuclei function for various scan types
nuclei_scan_types = ['technologies', 'ssl', 'http', 'cves']

#for scan_type in nuclei_scan_types:
#    run_nuclei_scan(scan_type, website)

def analyze_cors(url):
    tool_name = "CORS Analysis"
    output_file = os.path.join(output_directory, f'{tool_name.lower()}_results.txt')

    print(f"Running {tool_name}...")
    try:
        response = requests.get(url)
        response.raise_for_status()

        cors_headers = response.headers.get('Access-Control-Allow-Origin', '')

        with open(output_file, 'w') as f:
            f.write(f"{tool_name}:\n")

            if cors_headers:
                f.write("CORS headers detected:\n")
                f.write(f"Access-Control-Allow-Origin: {cors_headers}\n")
                # Add additional details or response content as needed
                f.write(response.text + "\n")
            else:
                f.write("No CORS headers detected.\n")

        print(f"{tool_name} results saved in {output_file}")
    except requests.RequestException as e:
        print(f"Error during {tool_name}: {e}")

        
      

   
   
def detect_cms(url):
    tool_name = "CMSeeK"
    output_file_path = os.path.join(output_directory, "cms_detection_results.txt")

    try:
        # Capture current console output
        original_stdout = sys.stdout
        console_output = io.StringIO()
        sys.stdout = console_output

        # Use 'cmseek' directly if it's in the PATH
        command = f"cmseek -u {url}"

        # Print the command before executing
        print(f"Running command: {command}")

        # Run the command with subprocess.Popen to capture real-time output
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Write the command to the output file
        with open(output_file_path, 'w') as output_file:
            output_file.write(f"Running command: {command}\n\n")

            # Use AnsiToWin32 to strip ANSI escape codes while printing to console
            process_stdout = AnsiToWin32(process.stdout).stream
            process_stderr = AnsiToWin32(process.stderr).stream

            # Read and print real-time output to the console
            while True:
                output_line = process_stdout.readline()
                if output_line == '' and process.poll() is not None:
                    break
                if output_line:
                    print(output_line.strip())
                    output_file.write(strip_ansi_codes(output_line))

            # Capture any remaining output
            remaining_output = process.communicate()[0]
            if remaining_output:
                print(strip_ansi_codes(remaining_output.strip()))
                output_file.write(strip_ansi_codes(remaining_output))

        # Print the original console output back
        sys.stdout = original_stdout
        print(console_output.getvalue(), end='')

        # Apply sed command to remove ANSI escape codes from the output file
        sed_command = f"sed -r 's/\\x1B\\[[0-9;]*[a-zA-Z]//g' {output_file_path}"
        subprocess.run(sed_command, shell=True)

        if process.returncode != 0:
            raise subprocess.CalledProcessError(process.returncode, command)

        print(f"{tool_name} CMS detection complete. Results saved in {output_file_path}\n")

    except subprocess.CalledProcessError as e:
        print(f"Error during {tool_name} CMS detection. Command returned non-zero exit code {e.returncode}")
    except Exception as e:
        print(f"Error during {tool_name} CMS detection: {e}")
    finally:
        # Ensure that the original sys.stdout is restored
        sys.stdout = original_stdout






# Function to collect all JS pages
def collect_js_pages(url):
    print("Collecting JS pages...")
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        js_pages = [f"https://{subdomain}{domain}{link['src']}" for link in soup.find_all('script', {'src': True})]

        with open(os.path.join(output_directory, 'javascript_pages.txt'), 'w') as f:
            f.write('\n'.join(js_pages))
        print("JavaScript pages found and saved in javascript_pages.txt")
    except requests.RequestException as e:
        print(f"Error collecting JavaScript pages: {e}")

# Function to print technology stack
def print_technology_stack(url):
    print("Printing technology stack...")
    try:
        response = requests.get(url)
        response.raise_for_status()

        with open(os.path.join(output_directory, 'technology_stack.txt'), 'w') as f:
            server_header = response.headers.get('Server', 'N/A')
            f.write(f"Server: {server_header}\n")
            
            x_powered_by = response.headers.get('X-Powered-By', 'N/A')
            f.write(f"X-Powered-By: {x_powered_by}\n")

        print("Technology stack information saved in technology_stack.txt")
    except requests.RequestException as e:
        print(f"Error printing technology stack: {e}")


        
# Running testsslscan
def run_testsslscan(url):
    full_url = f"https://{subdomain}.{domain}"
    output_file_path = os.path.join(output_directory, "testsslscan_output.txt")
    command = f"testssl {full_url}"

    try:
        # Open a subprocess with pipes for stdout and stderr
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Write the command to the output file
        with open(output_file_path, 'w') as output_file:
            output_file.write(f"Running command: {command}\n\n")

            # Use AnsiToWin32 to strip ANSI escape codes while printing to console
            process_stdout = AnsiToWin32(process.stdout).stream
            process_stderr = AnsiToWin32(process.stderr).stream

            # Read and print real-time output to the console
            while True:
                output_line = process_stdout.readline()
                if output_line == '' and process.poll() is not None:
                    break
                if output_line:
                    print(output_line.strip())
                    output_file.write(strip_ansi_codes(output_line))

            # Capture any remaining output
            remaining_output = process.communicate()[0]
            if remaining_output:
                print(strip_ansi_codes(remaining_output.strip()))
                output_file.write(strip_ansi_codes(remaining_output))

        print(f"testsslscan complete. Output saved in {output_file_path}")
    except Exception as e:
        print(f"Error during testsslscan: {e}")        
   
# nmap scan
def run_nmap_scan(target):
    # Define the Nmap commands for different scans and corresponding output file names
    nmap_commands = [
        ("nmap --script http-methods {domain}", "nmap_Methods.txt"),
        ("nmap -p {target}", "nmap_Ports.txt"),
        ("nmap --script http-methods {target}", "nmap_Methods.txt"),
        ("nmap -sV --script http-wordpress-enum {target}", "nmap_WordPress_Enumeration.txt"),
        ("nmap --script http-slowloris-check {target}", "nmap_SlowLoris_Check.txt"),
        ("nmap --script ssl-dh-params {target}", "nmap_DeffieHllman.txt"),
        ("nmap -sV -p 443 --script ssl-enum-ciphers {target}", "nmap_Ciphers.txt"),
        ("nmap -sV --script=http-enum {target}", "nmap_HTTP_Srvices.txt"),
        ("nmap --script ssl* {target}", "nmap_SSL.txt"),
        ("nmap --script vuln {target}", "nmap_Vulnerabilities.txt"),
        ("nmap --script http* {target}", "nmap_output10.txt")
    ]

    try:
        for command, output_file_name in nmap_commands:
            output_file_path = os.path.join(output_directory, output_file_name)

            print(f"Running {command}...")
            with open(output_file_path, 'w') as output_file:
                output_file.write(f"Running command: {command}\n\n")

                # Open a subprocess with pipes for stdout and stderr
                process = subprocess.Popen(command.format(target=target, domain=domain), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

                # Read and print real-time output to the console
                while True:
                    output_line = process.stdout.readline()
                    if output_line == '' and process.poll() is not None:
                        break
                    if output_line:
                        print(output_line.strip())
                        output_file.write(output_line)

                # Capture any remaining output
                remaining_output = process.communicate()[0]
                if remaining_output:
                    print(remaining_output.strip())
                    output_file.write(remaining_output)

                print(f"{command} complete. Output saved in {output_file_path}\n")

        print("Nmap scan complete.")
    except Exception as e:
        print(f"Error during Nmap scan: {e}")



# Display a summary
def display_summary():
    print(f"Security scans completed for {website}. Results are stored in the {output_directory} directory.")


# ... (previous code remains unchanged)

while True:
    print("\nChoose the tools to run:")
    print("1. CMS Detection")
    print("2. TestSSLScan")
    print("3. Nuclei Scans")
    print("4. Nmap Scan")
    print("5. Print Technology Stack")
    print("6. CORS Analysis")
    print("7. Collect JS Pages")
    print("8. Dirsearch")
    print("A. Run All")
    print("Q. Quit")

    user_choice = input("Enter the tool number(s) to run (comma-separated), 'A' to run all, or 'Q' to quit: ").strip()

    if user_choice.upper() == 'Q':
        print("Exiting the program.")
        break

    if user_choice.upper() == 'A':
        detect_cms(website)
        run_testsslscan(website)
        for scan_type in ['technologies', 'ssl', 'http', 'cves']:
            run_nuclei_scan(scan_type, website)
        run_nmap_scan(subdomain + "." + domain if subdomain else domain)
        print_technology_stack(website)
        analyze_cors(website)
        collect_js_pages(website)
        discover_directories(website)
        display_summary()
        break
    else:
        selected_tools = user_choice.split(',')
        for tool in selected_tools:
            if tool == '1':
                detect_cms(website)
            elif tool == '2':
                run_testsslscan(website)
            elif tool == '3':
                for scan_type in ['technologies', 'ssl', 'http', 'cves']:
                    run_nuclei_scan(scan_type, website)
            elif tool == '4':
                run_nmap_scan(subdomain + "." + domain if subdomain else domain)
            elif tool == '5':
                print_technology_stack(website)
            elif tool == '6':
                analyze_cors(website)
            elif tool == '7':
                collect_js_pages(website)
            elif tool == '8':
                discover_directories(website)
            else:
                print(f"Invalid tool number: {tool}")
