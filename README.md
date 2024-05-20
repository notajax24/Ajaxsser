# XSS Automation Tool - AJAXSSER 🖥️☠️

##	**Overview** ☑️
This is an automated XSS (Cross-Site Scripting) vulnerability scanning tool developed in Python. The tool uses Nikto and XSSer to scan URLs for potential XSS vulnerabilities and generates a detailed report with the scan results.

## **Features** 🚀
Scans single URLs or URLs from a list in a file.
Live scanning progress and results display.
Generates a comprehensive report with identified vulnerabilities.
Supports customization of scan parameters.

## How to Use 🐧
### **Prerequisites**
Python 3.x installed on your machine.
Internet connectivity for scanning tools (Nikto and XSSer).

## Usage ✅
1- Clone the repository: 

``` git clone https://github.com/notajax24/ajaxsser.git ``` ✅

2- Navigate to the repository:

``` cd xss-automation-tool ``` ✅


### To scan a single URL:
``` python xss_automation_tool.py -u "https://example.com/page?param=value" ``` ✅

### To scan multiple URLs from a file:
``` python xss_automation.py -l urls.txt ``` ✅

Create a text file named urls.txt containing URLs, with each URL on a new line.

## View the results:  ♻️
The script will display live scanning progress and results for each URL or parameter.
After completion, a report file (xss_scan_report.txt) will be generated with detailed results.
Review the report:

Open the generated report file (xss_scan_report.txt) to view the final results, including vulnerable URLs and XSS vulnerabilities found.

## Author 🧑‍💻
Made with ❤️ By  Ajay Jachak 

🔗 LinekedIn - https://in.linkedin.com/in/ajay-jachak-990964212

📲 InstaGram - https://www.instagram.com/ajax.pvt/

## Created On 
20/05/2024 📅

 ## License
This project is licensed under the MIT License - see the LICENSE file for details.




