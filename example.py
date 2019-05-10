from virustotalapi import VirusTotalAPI

vt = VirusTotalAPI('<your_api_key>')

print vt.file_scan('malware.png')
print vt.file_report('malware.png')
print vt.url_report("https://www.google.gr")
print vt.domain_report("google.gr")