import re

regex_ipv6 = r'([a-f0-9:]+:+)+[a-f0-9]+'
# regex_ipv4 = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
# regex_filename = r'[A-Za-z0-9-_\·]+\.(txt|php|exe|dll|bat|sys|htm|html|js|jar|jpg|png|vb|scr|pif|chm|zip|rar|cab|pdf|doc|docx|ppt|pptx|xls|xlsx|swf|gif|bat|pdf)'
regex_filepath = r'[a-z A-Z]:(\\([0-9 a-z A-Z _]+))+'
regex_sha1 = r'[a-f0-9]{40}|[A-F0-9]{40}'
regex_sha256 = r'[a-f0-9]{64}|[A-F0-9]{64}'
regex_sha512 = r'[a-f0-9]{128}|[A-F0-9]{128}'
regex_md5 = r'[a-f0-9]{32}|[A-F0-9]{32}'
regex_cve = r'CVE-[0-9]{4}-[0-9]{4,6}'
regex_domain = r'[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\[\.\]|\{\.\}|\(\.\)|\.)[a-zA-Z]{2,6}'
regex_url = r'(https?|ftp|file|http)://[-A-Za-z0-9+&@#/%?=∼ _|! : , .;]+[-A-Za-z0-9+&@#/%?=∼ _|]'
regex_email = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
regex_filename= r'\b([a-zA-Z0-9_-]+)(?:\[\.\]|\{\.\}|\(\.\)|\.)([a-zA-Z0-9]+)\b'
regex_ipv4 = r'\d{1,3}(?:\[\.\]|\{\.\}|\(\.\)|\.)\d{1,3}(?:\[\.\]|\{\.\}|\(\.\)|\.)\d{1,3}(?:\[\.\]|\{\.\}|\(\.\)|\.)\d{1,3}'

