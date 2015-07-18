# coding: utf8
#!/usr/bin/env python

import requests


def create_event(configurations):

    url="http://"+configurations["FirIP"]+":8000/events/new/"
    data= {
        'csrfmiddlewaretoken': 'JrDSAkAfHh5kwA7UERzchoDI0RVR10pZ',
        'subject': 'test ARNAUD ZOBEC 2',
        'category': '1',
        'status': 'O',
        'detection': '2',
        'severity': '1',
        'date': '18/07/2015 16:01:04',
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

    try:
        r = requests.post(url, data=data, cookies=cookies2, headers=headers)
        print r.status_code
        if r.status_code == requests.codes.ok:
            print("Event Created")
        else:
            print("Erreur lors de la création (cookie?)")
    except requests.exceptions.Timeout:
        print(">>> Requete TimeOut")
    except requests.exceptions.TooManyRedirects:
        print(">>> TooManyRedirects")
    except requests.exceptions.RequestException:
        pass


if __name__ == '__main__':
    configurations = parse_configuration_file("../../etc/Analysis_Sender.conf")
    create_event(configurations)