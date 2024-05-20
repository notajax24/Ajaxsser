import subprocess
import json
import re
import logging
import os
import argparse
import time

# ASCII art for the bordered line
border_ascii = """
╔═════════════════════════════════════════════════════════════════════╗
"""

# ASCII art
ascii_art = """
░█████╗░░░░░░██╗░█████╗░██╗░░██╗░██████╗░██████╗███████╗██████╗░
██╔══██╗░░░░░██║██╔══██╗╚██╗██╔╝██╔════╝██╔════╝██╔════╝██╔══██╗
███████║░░░░░██║███████║░╚███╔╝░╚█████╗░╚█████╗░█████╗░░██████╔╝
██╔══██║██╗░░██║██╔══██║░██╔██╗░░╚═══██╗░╚═══██╗██╔══╝░░██╔══██╗
██║░░██║╚█████╔╝██║░░██║██╔╝╚██╗██████╔╝██████╔╝███████╗██║░░██║
╚═╝░░╚═╝░╚════╝░╚═╝░░╚═╝╚═╝░░╚═╝╚═════╝░╚═════╝░╚══════╝╚═╝░░╚═╝
"""

# Loading animation
loading_animation = [
    "| Loading   ",
    "/ Loading   ",
    "- Loading   ",
    "\\ Loading  ",
]

# Setup logging
logging.basicConfig(filename='xss_automation_tool.log', level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s %(message)s')

def run_command(command):
    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if stderr:
            logging.error(f"Error executing {command}: {stderr.decode()}")
        return stdout.decode(), stderr.decode()
    except Exception as e:
        logging.error(f"Exception: {str(e)}")
        return None, str(e)

def run_nikto_scan(target):
    command = f"nikto -h {target}"
    stdout, stderr = run_command(command)
    return stdout, stderr

def run_xsser_scan(target):
    command = f"xsser -u {target} --auto"
    stdout, stderr = run_command(command)
    return stdout, stderr

def parse_nikto_output(output):
    xss_vulns = []
    for line in output.splitlines():
        if "XSS" in line or "Cross Site Scripting" in line:
            xss_vulns.append(line)
    return xss_vulns

def generate_report(scan_results, report_file, vulnerable_urls):
    with open(report_file, 'w') as file:
        file.write(border_ascii)
        file.write("💻 AJAXSSER - Automated XSS Vulnerability Scanner 💻\n")
        file.write("Author: Ajay Jachak\n") 
        file.write("Created on: May 20, 2024 📅\n")
        file.write("❤️ from India \n")
        file.write("="*50 + "\n\n")
        
        if vulnerable_urls:
            file.write("🚨 Vulnerable URLs:\n")
            for url, is_vulnerable in vulnerable_urls.items():
                status = "Vulnerable 😟" if is_vulnerable else "Not Vulnerable 🙂"
                file.write(f"🔗 {url} - {status}\n")
            file.write("\n" + "="*50 + "\n\n")
        
        for url, results in scan_results.items():
            file.write(f"🌐 URL: {url}\n")
            file.write("-" * 50 + "\n")
            if results["nikto_xss_vulns"]:
                file.write("🔍 Nikto XSS Vulnerabilities:\n")
                for vuln in results["nikto_xss_vulns"]:
                    file.write(f"  - {vuln}\n")
            else:
                file.write("✅ No XSS vulnerabilities found by Nikto.\n")
            
            if "XSS" in results["xsser_output"]:
                file.write("\n🔍 XSSer Output:\n")
                file.write(results["xsser_output"] + "\n")
            else:
                file.write("✅ No XSS vulnerabilities found by XSSer.\n")
            
            file.write("\n" + "="*50 + "\n\n")

def scan_url(url):
    # Display loading animation
    for frame in loading_animation:
        print(f"\r{frame}", end="")
        time.sleep(0.2)
    print("\r", end="")  # Clear loading animation line
    
    # Run Nikto Scan
    nikto_output, nikto_error = run_nikto_scan(url)
    if nikto_error:
        logging.error(f"Nikto scan failed for {url}: {nikto_error}")
    nikto_xss_vulns = parse_nikto_output(nikto_output)
    
    # Run XSSer Scan
    xsser_output, xsser_error = run_xsser_scan(url)
    if xsser_error:
        logging.error(f"XSSer scan failed for {url}: {xsser_error}")
    else:
        logging.info(f"XSSer scan output for {url}: {xsser_output}")
    
    # Check if vulnerable
    is_vulnerable = bool(nikto_xss_vulns or "XSS" in xsser_output)

    # Compile results
    results = {
        "nikto_xss_vulns": nikto_xss_vulns,
        "xsser_output": xsser_output,
        "is_vulnerable": is_vulnerable
    }

    return results

def main():
    parser = argparse.ArgumentParser(description="Automate XSS vulnerability scanning.")
    parser.add_argument('-u', '--url', type=str, help="Single URL to scan")
    parser.add_argument('-l', '--list', type=str, help="File with list of URLs to scan")
    parser.add_argument('-o', '--output', type=str, default='xss_scan_report.txt', help="Output file for the scan results")
    args = parser.parse_args()

    # Display ASCII art
    print(border_ascii)
    print(ascii_art)
    print(border_ascii)

    # Display tool name and author
    print("\033[1m\033[95m💻 AJAXSSER - Automated XSS Vulnerability Scanner 💻\033[0m")
    print("\033[1m\033[96mAuthor: Ajay Jachak\n\033[0m") 
    print("\033[1m\033[94mCreated on: May 20, 2024 📅\n\033[0m")
    print("\033[1m\033[92m❤️ from India \n\033[0m")
    print("="*50 + "\n")

    urls = []

    if args.url:
        urls.append(args.url)
    elif args.list:
        if not os.path.isfile(args.list):
            print(f"File {args.list} does not exist.")
            return
        with open(args.list, 'r') as file:
            urls = [url.strip() for url in file.readlines() if url.strip()]
    else:
        print("Either a single URL or a file containing URLs must be provided.")
        return

    all_results = {}
    vulnerable_urls = {}

    for url in urls:
        print(f"\033[1m\033[92mScanning {url}...\033[0m")
        results = scan_url(url)
        all_results[url] = results

        is_vulnerable = results['is_vulnerable']
        vulnerable_urls[url] = is_vulnerable

        status = "\033[1m\033[91mVulnerable 😟\033[0m" if is_vulnerable else "\033[1m\033[92mNot Vulnerable 🙂\033[0m"
        print(f"\033[1m{url}\033[0m - {status}")

    # Generate Report
    generate_report(all_results, args.output, vulnerable_urls)
    print(f"\033[1m\033[94mReport generated: {args.output}\033[0m")

    if vulnerable_urls:
        print("\033[1m\033[91mVulnerable URLs:\033[0m")
        for v_url, is_vulnerable in vulnerable_urls.items():
            status = "Vulnerable 😟" if is_vulnerable else "Not Vulnerable 🙂"
            print(f"\033[1m{v_url} - {status}\033[0m")

if __name__ == "__main__":
    main()