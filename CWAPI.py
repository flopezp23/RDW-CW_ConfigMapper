import requests
import json
from lxml import html
import http.client
import csv
import time


class CloudWAFAPI(object):

  def __init__(self,username,password):
    self.username=username
    self.password=password
    self.tenantID=""
    self.bearerToken=""
    self.oktacookie = None

  def login(self):
    payload = {"username": "","password": "","options": {"multiOptionalFactorEnroll": True,"warnBeforePasswordExpired": True}}
    payload["username"] = self.username
    payload["password"] = self.password

    headers = {'Content-Type': 'application/json'}
    data = json.dumps(payload)

    response=requests.request("POST","https://radware-public.okta.com/api/v1/authn",headers=headers, data=data)
    if response.status_code != 200:
      raise Exception("Cannot authenticate to Cloud WAF, invalid credentials")

    responsePayload=response.json()

    ##retrieve tocken and nounce to be used in the authorization request
    sessionToken=responsePayload["sessionToken"]
    nonce=responsePayload["_embedded"]["user"]["id"]

    params = {'client_id': 'M1Bx6MXpRXqsv3M1JKa6','nonce':'','prompt':'none','redirect_uri':'https://portal.radwarecloud.com',
              'response_mode':'form_post','response_type':'token','scope':'api_scope','sessionToken':'','state':'parallel_af0ifjsldkj'}

    params["sessionToken"]=sessionToken
    params["nonce"]=nonce

    ##print("nonce="+nonce)

    ##retrieve the bearerToken to be used for subsequent calls
    response=requests.request("GET","https://radware-public.okta.com/oauth2/aus7ky2d5wXwflK5N1t7/v1/authorize",params=params)
    if response.status_code != 200:
      raise Exception("Not authorized, please make sure you are using a Cloud WAF API account.")

    self.oktacookie=response.cookies

    ###extract bearer token form response
    tree=html.fromstring(response.content)
    self.bearerToken = tree.xpath('//form[@id="appForm"]/input[@name="access_token"]/@value')[0]
    ##print("bearerToken="+self.bearerToken)

    ## Use the bearerToken to retrieve the tenant ID
    headers = {"Authorization": "Bearer %s" % self.bearerToken}

    response=requests.request("GET","https://portal.radwarecloud.com/v1/users/me/summary",headers=headers)
    responsePayload=response.json()

    self.tenantID=responsePayload["tenantEntityId"]

    #print("tenantID="+self.tenantID)
    print("login successful")

  def AppList(self):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    headers = {
        'Authorization': 'Bearer ' + self.bearerToken,
        'requestEntityids': self.tenantID,
        'Cookie': 'Authorization=' + self.bearerToken,
        'Content-Type': 'application/json;charset=UTF-8'
      }
    conn.request("GET", "/v1/gms/applications?size=200", headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata
  
  def Mapper(self,page):
    conn = http.client.HTTPSConnection("portal.radwarecloud.com")
    headers = {
        'Authorization': 'Bearer ' + self.bearerToken,
        'requestEntityids': self.tenantID,
        'Cookie': 'Authorization=' + self.bearerToken,
        'Content-Type': 'application/json;charset=UTF-8'
      }
    conn.request("GET", f"/v1/gms/applications?size=200&page={page}", headers=headers)
    res = conn.getresponse()
    if res.status != 200:
      raise Exception("Error retrieving events from Cloud WAF")

    appdata = json.loads(res.read().decode())
    
    return appdata
