import CyberNews
import Malpedia
import MITRE
import ThreatProfiling
import YARAandArticle
import IndicatorsOfCompromises
import LatestThreatData
import pyfiglet
import os

directory = "CTI DB"
try:
    os.makedirs(directory)
except FileExistsError:
    pass

def print_threat_compas():
    text = "ThreatCompas"
    figlet_text = pyfiglet.figlet_format(text)
    print(figlet_text)

def description():
    print("-"*200)
    description_text = """ThreatCompass is a cutting-edge cybersecurity tool designed to provide real-time threat data collection and analysis. It leverages web scraping techniques to gather information on over 2500 malware and 400 threat actors. By using YARA rules, ThreatCompass has collected over 1000 validated malicious indicators, enabling efficient threat profiling with an 80% increased effectiveness. The tool amplifies threat profiling by 50% by facilitating the identification of malicious software and TTPs (Tactics, Techniques, and Procedures) employed by threat actors through the MITRE ATT&CK framework. This comprehensive approach allows for a more in-depth understanding of cyber threats and their potential impact on organizations. In addition to threat profiling, ThreatCompass distributes over 200 recent cyber news and CVE (Common Vulnerabilities and Exposures) reports, enabling stakeholders to identify and respond to threats more effectively. By staying up-to-date with the latest cybersecurity vulnerabilities, organizations can better protect their digital assets and mitigate potential risks. Overall, ThreatCompass is a powerful cybersecurity tool that combines real-time data collection, advanced threat profiling, and timely distribution of cyber news and CVE reports to help organizations stay ahead of emerging threats and protect their digital assets.
    """
    print(description_text)
    print("-"*200)

print_threat_compas()
description()
print("Welcome to ThreatCompass! Please select an option below: ")
print("-"*200)
scarpe_option = input("Are you trying it for first time! Please enter Y or N to get started: ")
if scarpe_option == "Y" or scarpe_option == "y":
    print("Please wait while we scrape the data for you!")
    CyberNews.main()
    Malpedia.main()
    MITRE.main()
elif scarpe_option == "N" or scarpe_option == "n":
    update_option = input("Do you want to update the data? Please enter Y or N to get started: ")
    if update_option == "Y" or update_option == "y":
        CyberNews.main()
        Malpedia.main()
        MITRE.main()
    else:
        pass

print("-"*200)
print("Please select an option below: ")
print("1. Threat Profiling")
print("2. Latest Threat Data")
print("3. Indicators of Compromise")
print("4. YARA and Article")
print("5. Exit")
input_option = input("Please enter your option: ")
if input_option == "1":
    ThreatProfiling.main()
elif input_option == "2":
    LatestThreatData.main()
elif input_option == "3":
    IndicatorsOfCompromises.main()
elif input_option == "4":
    YARAandArticle.main()
elif input_option == "5":
    print("Thank you for using ThreatCompass!")
    print("Exiting...")
    print("-"*200)
    exit()