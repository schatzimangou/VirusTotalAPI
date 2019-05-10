import logging
import hashlib
import json
import os

try:
    import requests
except:
    logging.error('Requests module is missing. Please install it by running: pip install requests')

class VirusTotalAPI:

    def __init__(self,api_key):
        self.api_key = api_key
        self.api_url = 'https://www.virustotal.com/vtapi/v2/'

    def handle_api_response(self, response_code):
        if response_code == 403:
            logging.error( '[x] Response Code 403: You do not have the required privileges to make this api call!')
        elif response_code == 204:
            logging.error( '[x] Response Code 204: You have exceeded the public API request rate limit!')
        elif response_code == 200:
            logging.debug( '[i] Response Code 200: HTTP Success')
        else:
            logging.error('[x] Response Code %s: Unspecified error!' %response_code)

    def file_scan(self, file):
        url = self.api_url + 'file/scan'
        params = {'apikey': self.api_key}
        files = {'file': (file, open(file, 'rb'))}
        try:
            r = requests.post(url, files=files, params=params)
            self.handle_api_response(r.status_code)
            json = r.json()
            vt_response_code = json['response_code']
            vt_verbose_msg =  json['verbose_msg']
            if vt_response_code == 1:
                logging.debug(vt_verbose_msg)
                return json
            else:
                logging.error(vt_verbose_msg)
        except ValueError:
            logging.error('[x] Response from VirusTotal API is empty!')
        except Exception:
            import traceback
            logging.error('[x] Unhandled Exception! \r\n' + traceback.format_exc())           

    def file_report(self, file):
        url = self.api_url + 'file/report' 
        if os.path.isfile(file):
            with open(file, 'rb') as f:
                fhash = hashlib.sha256(f.read()).hexdigest()
        params = {'apikey': self.api_key, 'resource': fhash}
        try:
            r = requests.get(url, params=params)
            self.handle_api_response(r.status_code)
            json = r.json()
            vt_response_code = json['response_code']
            vt_verbose_msg =  json['verbose_msg']
            if vt_response_code == 1:
                logging.debug(vt_verbose_msg)
                return json
            else:
                logging.error(vt_verbose_msg)
        except ValueError:
            logging.error('[x] Response from VirusTotal API is empty!')
        except Exception:
            import traceback
            logging.error('[x] Unhandled Exception! \r\n' + traceback.format_exc())

              
    def file_rescan(self, resource):
        url = self.api_url + 'file/rescan'
        if os.path.isfile(file):
            with open(file, 'rb') as f:
                fhash = hashlib.sha256(f.read()).hexdigest()
        params = {'apikey': self.api_key, 'resource': fhash}
        try:
            r = requests.get(url, params=params)
            self.handle_api_response(r.status_code)
            json = r.json()
            vt_response_code = json['response_code']
            vt_verbose_msg =  json['verbose_msg']
            if vt_response_code == 1:
                logging.debug(vt_verbose_msg)
                return json
            else:
                logging.error(vt_verbose_msg)
        except ValueError:
            logging.error('[x] Response from VirusTotal API is empty!')
        except Exception:
            import traceback
            logging.error('[x] Unhandled Exception! \r\n' + traceback.format_exc())

    def url_scan(self, link):
        url = self.api_url + 'url/scan'
        params = {'apikey': self.api_key, 'url': link}
        try:
            r = requests.post(url, params=params)
            self.handle_api_response(r.status_code)
            json = r.json()
            vt_response_code = json['response_code']
            vt_verbose_msg =  json['verbose_msg']
            if vt_response_code == 1:
                logging.debug(vt_verbose_msg)
                return json
            else:
                logging.error(vt_verbose_msg)
        except ValueError:
            logging.error('[x] Response from VirusTotal API is empty!')
        except Exception:
            import traceback
            logging.error('[x] Unhandled Exception! \r\n' + traceback.format_exc())
        
    def url_report(self, link):
        url = self.api_url + 'url/report' 
        params = {'apikey': self.api_key, 'resource': link}
        try:
            r = requests.get(url, params=params)
            self.handle_api_response(r.status_code)
            json = r.json()
            print json
            vt_response_code = json['response_code']
            vt_verbose_msg =  json['verbose_msg']
            if vt_response_code == 1:
                logging.debug(vt_verbose_msg)
                return json
            else:
                logging.error(vt_verbose_msg)
        except ValueError:
            logging.error('[x] Response from VirusTotal API is empty!')
        except Exception:
            import traceback
            logging.error('[x] Unhandled Exception! \r\n' + traceback.format_exc())

    def ip_report(self, ip):
        url = self.api_url + 'ip-address/report'
        parameters = 'apikey=%s&ip=%s'%(self.api_key,ip)
        try:
            r = requests.get('%s?%s' %(url,parameters))
            self.handle_api_response(r.status_code)
            json = r.json()
            print json
            vt_response_code = json['response_code']
            vt_verbose_msg =  json['verbose_msg']
            if vt_response_code == 1:
                logging.debug(vt_verbose_msg)
                return json
            else:
                logging.error(vt_verbose_msg)
        except ValueError:
            logging.error('[x] Response from VirusTotal API is empty!')
        except Exception:
            import traceback
            logging.error('[x] Unhandled Exception! \r\n' + traceback.format_exc()) 

    def domain_report(self, domain):
        url = self.api_url + 'domain/report'
        parameters = 'apikey=%s&domain=%s'%(self.api_key,domain)
        try:
            r = requests.get('%s?%s' %(url,parameters))
            self.handle_api_response(r.status_code)
            json = r.json()
            print json
            vt_response_code = json['response_code']
            vt_verbose_msg =  json['verbose_msg']
            if vt_response_code == 1:
                logging.debug(vt_verbose_msg)
                return json
            else:
                logging.error(vt_verbose_msg)
        except ValueError:
            logging.error('[x] Response from VirusTotal API is empty!')
        except Exception:
            import traceback
            logging.error('[x] Unhandled Exception! \r\n' + traceback.format_exc()) 