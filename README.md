# VirusTotalAPI
This is a class to consum the VirusTotal Public API 2.0 as documented here:

https://www.virustotal.com/en/documentation/public-api/

and here:

https://developers.virustotal.com/reference#getting-started

## Example

```
from virustotalapi import VirusTotalAPI

vt = VirusTotalAPI('<your_api_key>')

print vt.file_scan('malware.png')
print vt.file_report('malware.png')
print vt.url_report("https://www.malware.com")
print vt.domain_report("malware.com")
```
## Generating a VirusTotal API key

Instructions to generate your API key can be found here:

https://developers.virustotal.com/reference#getting-started
