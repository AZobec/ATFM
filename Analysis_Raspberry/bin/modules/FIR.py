# coding: utf8
#!/usr/bin/env python

import requests

def create_event(configurations):

    url="http://"+"127.0.0.1"+":8000/events/new/"
    data= {
        'csrfmiddlewaretoken': 'JrDSAkAfHh5kwA7UERzchoDI0RVR10pZ',
        'subject': 'test ARNAUD ZOBEC',
        'category': '1',
        'status': 'O',
        'detection': '2',
        'severity': '1',
        'date': '17/07/2015 16:01:04',
        'actor': '',
        'plan': '',
        'confidentiality': '1',
        'description': '<p>bonjour</p>',
        }
    cookies = {'sessionid' : 'umd71fiphl7hq15sr3cvee9x1ljjql9w',
                'csrftoken' : 'JrDSAkAfHh5kwA7UERzchoDI0RVR10pZ',
                }
    headers = {'Accept-Language' : 'fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3' }

    cookies2 = dict (sessionid = 'umd71fiphl7hq15sr3cvee9x1ljjql9w',
        csrftoken = 'JrDSAkAfHh5kwA7UERzchoDI0RVR10pZ' )
    r = requests.post(url, data=data, cookies=cookies2, headers=headers)
    print r.status_code

if __name__ == '__main__':
    configurations = parse_configuration_file("../../etc/Analysis_Sender.conf")
    create_event(configurations)