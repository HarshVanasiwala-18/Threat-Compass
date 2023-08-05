import re
import requests
from bs4 import BeautifulSoup

# regex_ipv6 = r"([a-f0-9:]+:+)+[a-f0-9]+"
regex_filepath = r"[a-z A-Z]:(\\([0-9 a-z A-Z _]+))+"
regex_sha1 = r"[a-f0-9]{40}|[A-F0-9]{40}"
regex_sha256 = r"[a-f0-9]{64}|[A-F0-9]{64}"
regex_sha512 = r"[a-f0-9]{128}|[A-F0-9]{128}"
regex_md5 = r"[a-f0-9]{32}|[A-F0-9]{32}"
regex_cve = r"CVE-[0-9]{4}-[0-9]{4,6}"
regex_domain = (
    r"[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\[\.\]|\{\.\}|\(\.\)|\.)[a-zA-Z]{2,6}"
)
regex_url = r"(https?|ftp|file|http)://[-A-Za-z0-9+&@#/%?=∼ _|! : , .;]+[-A-Za-z0-9+&@#/%?=∼ _|]"
regex_email = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
regex_filename = r"\b([a-zA-Z0-9_-]+)(?:\[\.\]|\{\.\}|\(\.\)|\.)([a-zA-Z0-9]+)\b"
regex_ipv4 = r"\d{1,3}(?:\[\.\]|\{\.\}|\(\.\)|\.)\d{1,3}(?:\[\.\]|\{\.\}|\(\.\)|\.)\d{1,3}(?:\[\.\]|\{\.\}|\(\.\)|\.)\d{1,3}"

pattern_sict = {
    # "ipv6": regex_ipv6,
    "filepath": regex_filepath,
    "sha1": regex_sha1,
    "sha256": regex_sha256,
    "sha512": regex_sha512,
    "md5": regex_md5,
    "cve": regex_cve,
    "domain": regex_domain,
    "url": regex_url,
    "email": regex_email,
    "filename": regex_filename,
    "ipv4": regex_ipv4,
}


def regex_finder(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, "html.parser")
        if response.status_code == 200:
            text = soup.get_text()
            for key, value in pattern_sict.items():
                matches = re.finditer(value, text, re.MULTILINE)
                for matches in matches:
                    print("Type: " + key.upper() + " : ", matches.group())
    except Exception as e:
        print(e)


if __name__ == "__main__":
    input_url = input("Enter the URL: ")
    regex_finder(input_url)
