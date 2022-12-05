import json, re, os,logging
from urllib.parse import urlencode, urlparse, urlunparse
import requests
import warnings

warnings.filterwarnings('ignore', message='Unverified HTTPS request')
class tokenCentral:
    def __init__(
        self,
        client_id,
        client_secret,
        customer_id,
        username,
        password,
        base_url,
        ssl_verify=True,
    ):

        self.client_id = client_id
        self.client_secret = client_secret
        self.customer_id = customer_id
        self.username = username
        self.password = password
        self.base_url = base_url
        csrf_token = None
        session_token = None
        self.headers = {'Content-Type':'application/json'}
        self.path = "/oauth2/authorize/central/api/login?"
        self.ssl_verify = ssl_verify


        self.payload = {"grant_type": "client_credentials","client_id": self.client_id, "client_secret": self.client_secret}

    def oauthLogin(self):
        """        Step1 of the OAUTH mechanism. Aruba Central
        """

        url = f"{self.base_url}{self.path}client_id={self.client_id}"
        headers = {'Content-Type': 'application/json'}
        data = json.dumps({"username": self.username,
                           "password": self.password})
        data = data.encode("utf-8")

        try:
            s = requests.Session()
            req = requests.Request(method="POST", url=url, data=data,headers=headers)
            prepped = s.prepare_request(req)
            settings = s.merge_environment_settings(prepped.url, {},None, self.ssl_verify, None)
            resp = s.send(prepped, **settings)

            if resp.status_code == 200:
                cookies = resp.cookies.get_dict()

                return cookies['csrftoken'], cookies['session']

        except Exception as e:
            print("Central Login Step1 failed.. Unable to obtain CSRF token!")
            raise e

    def oauthCode(self, csrf_token, session_token):
        """
        Step2 of the OAUTH mechanism. Obtain
                 authentication code using CSRF token and session token.
        """
        auth_code = None
        path = "/oauth2/authorize/central/api?"

        url = f"{self.base_url}{path}client_id={self.client_id}&response_type=code&scope=all"

        customer_id = self.customer_id
        data = json.dumps({'customer_id': customer_id})
        headers = {'X-CSRF-Token': csrf_token,
                    'Content-Type': 'application/json',
                    'Cookie': "session="+session_token}

        try:
            s = requests.Session()
            req = requests.Request(method="POST", url=url, data=data,headers=headers)
            prepped = s.prepare_request(req)
            settings = s.merge_environment_settings(prepped.url, {},None, self.ssl_verify, None)
            resp = s.send(prepped, **settings)
            if resp.status_code == 200:
                result = json.loads(resp.text)
                auth_code = result['auth_code']
                return auth_code

        except Exception as e:
            self.logger.error("Central Login Step2 failed.."
                              " Unable to obtain Auth code!")
            raise e


    def oauthAccessToken(self, auth_code):
            """     step3 of the OAUTH mechanism. Obtain
                    access token by using auth_code.
            """
            access_token = None
            headers = {'Content-Type': 'application/json'}

            path =  "/oauth2/token?"
            query = {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "grant_type": "authorization_code",
                "code": auth_code
            }
            url = f"{self.base_url}{path}client_id={self.client_id}&&client_secret={self.client_secret}&grant_type=authorization_code&code={auth_code}"

            try:
                s = requests.Session()
                req = requests.Request(method="POST", url=url)
                prepped = s.prepare_request(req)
                settings = s.merge_environment_settings(prepped.url, {},
                                                        None, self.ssl_verify, None)
                resp = s.send(prepped, **settings)
                if resp.status_code == 200:
                    result = json.loads(resp.text)
                    token = result['access_token']
                    return token
            except Exception as e:
                self.logger.error("Central Login Step3 failed.."
                                  " Unable to obtain access token!")
                raise e
                
    def UpdateZabbix(self, token_access,hostmacroid):

        base_url = "http://ciussszabbix.r03.rtss.qc.ca/zabbix/api_jsonrpc.php"
        url = f"{base_url}"
        data = json.dumps({
                             "jsonrpc": "2.0",
                             "method": "usermacro.update",
                             "params": {
                                "hostmacroid": hostmacroid,
                                "value": token_access
                              },
                              "auth": "Zbbix auth token",
                              "id": 1
        })
        headers = {'Content-Type': 'application/json-rpc'}

        try:
             s = requests.Session()
             req = requests.Request(method="POST", url=url, data=data,headers=headers)
             prepped = s.prepare_request(req)
             settings = s.merge_environment_settings(prepped.url, {},None, self.ssl_verify, None)
             resp = s.send(prepped, **settings)
             if resp.status_code == 200:
                 result = json.loads(resp.text)
                 return result

        except Exception as e:
                self.logger.error("Central Login Step2 failed.."
                                " Unable to obtain Auth code!")
                raise e