import requests
import json
import base64
import time


msgraph = { "resource":"https://graph.microsoft.com/", "appId": "14d82eec-204b-4c2f-b7e8-296a70dab67e" }

tenant = "contoso.onmicrosoft.com"

userName= "admin@contoso.onmicrosoft.com" 
password ="" 

scope = "Group.ReadWrite.All User.ReadWrite.All openid offline_access Directory.ReadWrite.All"

target_UPN_suffix = "@contoso.net"
default_password = "P@ssword!"

def GetOAuthTokenByUser(tenant, appID,userName, password, scope = ".default"):
  tokenBaseEndpoint = "https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0/"
  tokenEndpoint = tokenBaseEndpoint + "token"
  headers = {}
  headers.update({"Content-Type":"application/x-www-form-urlencoded"})
  headers.update({"Accept":"application/json"})
  postBody = { "client_id":appID , 
    "grant_type":"password", 
    "username":userName,
    "password":password,
    "scope":scope} 
                
  token= requests.post(tokenEndpoint, data = postBody, headers = headers)
  return token.json()


def GetOAuthTokenByClientSecret(tenant, resource, appID,clientSecret, scope = ".default"):
  tokenBaseEndpoint = "https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0/"
  tokenEndpoint = tokenBaseEndpoint + "token"
  headers = {}
  headers.update({"Content-Type":"application/x-www-form-urlencoded"})
  headers.update({"Accept":"application/json"})
  postBody = { "client_id":appID , 
    "grant_type":"client_credentials", 
    "client_secret":clientSecret,
    "scope":scope} 
                
  token= requests.post(tokenEndpoint, data = postBody, headers = headers)
  return token.json()

def StartOAuthTokenByDeviceLogin(tenant, appID, scope = ".default"):
  tokenBaseEndpoint = "https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0/"
  tokenEndpoint = tokenBaseEndpoint + "devicecode"
  headers = {}
  headers.update({"Content-Type":"application/x-www-form-urlencoded"})
  headers.update({"Accept":"application/json"})
  postBody = {  "client_id":appID , 
                "scope":scope} 
                
  response = requests.post(tokenEndpoint, data = postBody, headers = headers)
  print(response.json()["message"])
  return response

def GetOAuthTokenByDeviceLogin(tenant,  appID, devicecode):
  tokenBaseEndpoint = "https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0/"
  tokenEndpoint = tokenBaseEndpoint + "token"
  headers = {}
  headers.update({"Content-Type":"application/x-www-form-urlencoded"})
  headers.update({"Accept":"application/json"})
  postBody = {  "client_id":appID ,
                "grant_type":"device_code", 
                "code":devicecode} 
                
  token= requests.post(tokenEndpoint, data = postBody, headers = headers)
  return token.json()

def GetAccessTokenFromRefreshToken( appID,refresh_token ):
  tokenBaseEndpoint = "https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0/"
  tokenEndpoint = tokenBaseEndpoint + "token"
  headers = {}
  headers.update({"Content-Type":"application/x-www-form-urlencoded"})
  headers.update({"Accept":"application/json"})
  postBody = {  "client_id":appID , 
                "grant_type":"refresh_token", 
                "refresh_token":refresh_token} 
                
  token= requests.post(tokenEndpoint, data = postBody, headers = headers)
  return token.json()

def JWTDecoder(token):
  base64_string = token
  base64_string = base64_string.split('.')
  base64_string = base64_string[1]
  base64_string = base64_string.replace('-','+')
  base64_string = base64_string.replace('_','/')
  if ((len(base64_string) % 4) > 0):
    base64_padding = "=" * (4 - (len(base64_string) % 4))
    base64_string = base64_string + base64_padding

  base64_bytes = base64_string.encode("utf-8") 
  base64_string_bytes = base64.b64decode(base64_bytes) 
  decoded_string = base64_string_bytes.decode("utf-8") 
  return json.loads(decoded_string)

def CheckJWTToken(token, appID ):
  time_min_seconds_expiry = 300

  jwt_access_token = JWTDecoder(token["access_token"])

  time_now = time.time()
  time_token_expiry = jwt_access_token["exp"]
  print("seconds for token expiry:", (time_token_expiry -  (time_now + time_min_seconds_expiry)))

  if (time_token_expiry <  (time_now + time_min_seconds_expiry)):
    token = GetAccessTokenFromRefreshToken( appID, token["refresh_token"])
    print("refreshed new token")

  return token

def GetGraphObjectsByType(token, object_type, maxobjects = 50, api_version = "beta"):
  page_size = 25
  objects_returned = 0
  objects_to_return = []
  
  graph_uri = "https://graph.microsoft.com/" + api_version + "/" + object_type + "?&$top=" + str(page_size)
  headers = {}
  headers.update({"Content-Type":"application/json"})
  headers.update({"Accept":"application/json"})
  headers.update({"Authorization":("Bearer " + token["access_token"])})
  objects = requests.get(graph_uri,headers= headers)  

  for object_returned in objects.json()["value"]: 
    objects_to_return.append(object_returned)
    objects_returned += 1
    if (objects_returned >= maxobjects):
      break

  try:
    while ((objects.json()["@odata.nextLink"]) and (objects_returned < maxobjects)):
      graph_uri = objects.json()["@odata.nextLink"]
      objects = requests.get(graph_uri,headers= headers)  
      for object_returned in objects.json()["value"]: 
        objects_to_return.append(object_returned)
        objects_returned += 1
        if (objects_returned >= maxobjects):
          break
  except:
    print("no more objects")    
    pass
  
  return objects_to_return

def GetGraphObjectByTypeID(token, object_type,object_id, api_version = "beta"):
  graph_uri = "https://graph.microsoft.com/" + api_version + "/" + object_type + "/" + object_id
  headers = {}
  headers.update({"Content-Type":"application/json"})
  headers.update({"Accept":"application/json"})
  headers.update({"Authorization":("Bearer " + token["access_token"])})
  objects = requests.get(graph_uri,headers= headers)  
  return objects

def DeleteGraphObjectByTypeID(token, object_type,object_id, api_version = "beta"):
  graph_uri = "https://graph.microsoft.com/" + api_version + "/" + object_type + "/" + object_id
  headers = {}
  headers.update({"Content-Type":"application/json"})
  headers.update({"Accept":"application/json"})
  headers.update({"Authorization":("Bearer " + token["access_token"])})
  objects = requests.delete(graph_uri,headers= headers)  
  return objects


def UpdateGraphObjectByType(token, object_type, oid, object_in_json, api_version = "beta"):
  graph_uri = "https://graph.microsoft.com/" + api_version + "/" + object_type  + "/" + oid 
  headers = {}
  headers.update({"Content-Type":"application/json"})
  headers.update({"Accept":"application/json"})
  headers.update({"Authorization":("Bearer " + token["access_token"])})
  objects = requests.patch(graph_uri, json=object_in_json, headers= headers )  
  return objects


def NewGraphObjectByType(token, object_type,object_in_json, api_version = "beta"):
  graph_uri = "https://graph.microsoft.com/" + api_version + "/" + object_type  
  headers = {}
  headers.update({"Content-Type":"application/json"})
  headers.update({"Accept":"application/json"})
  headers.update({"Authorization":("Bearer " + token["access_token"])})
  objects = requests.post(graph_uri, json=object_in_json, headers= headers )  
  return objects

def NewGraphUser(token, displayName, mailNickName, userPrincipalName, password, accountEnabled = True, forceChangePasswordNextSignIn = True,
        city = None, companyName= None, country = None, department = None, employeeId = None, employeeHireDate = None, employeeOrgData = None,
        employeeType = None, ageGroup = None, businessPhones = None, faxNumber = None, givenName=None, jobTitle = None, mail = None, mobilePhone = None,
        officeLocation = None, postalCode = None, preferredDataLocation = None, preferredLanguage = None, proxyAddresses = None, state = None,
        streetAddress  =None, surname = None, usageLocation = None, extensionAttribute1 = None, extensionAttribute2 = None, extensionAttribute3 = None,
        extensionAttribute4 = None, extensionAttribute5 = None, extensionAttribute6 = None, extensionAttribute7 = None, extensionAttribute8 = None, 
        extensionAttribute9 = None, extensionAttribute10 = None, extensionAttribute11 = None, extensionAttribute12 = None,
        extensionAttribute13 = None, extensionAttribute14 = None, extensionAttribute15 = None   
       ):
    
  userConfig = { "accountEnabled": accountEnabled,
                    "displayName": displayName,
                    "mailNickname":mailNickName,
                    "userPrincipalName":userPrincipalName,
                    "passwordProfile": {"forceChangePasswordNextSignIn":forceChangePasswordNextSignIn,
                                        "password": password
                                        }
           }
           
  if ( city): userConfig.update({"city":city} )
  if ( companyName): userConfig.update({"companyName":companyName} )
  if ( country): userConfig.update({"country":country} )
  if ( department): userConfig.update({"department":department} )
  if ( employeeId): userConfig.update({"employeeId":employeeId} )
  if ( employeeHireDate): userConfig.update({"employeeHireDate":employeeHireDate} )
  if ( employeeOrgData): userConfig.update({"employeeOrgData":employeeOrgData} )
  if ( employeeType): userConfig.update({"employeeType":employeeType} )
  if ( ageGroup): userConfig.update({"ageGroup":ageGroup} )
  if ( businessPhones): userConfig.update({"businessPhones":businessPhones} )
  if ( faxNumber): userConfig.update({"faxNumber":faxNumber} )
  if ( givenName): userConfig.update({"givenName":givenName} )
  if ( jobTitle): userConfig.update({"jobTitle":jobTitle} )
  if ( mail): userConfig.update({"mail":mail} )
  if ( mobilePhone): userConfig.update({"mobilePhone":mobilePhone} )
  if ( officeLocation): userConfig.update({"officeLocation":officeLocation} )
  if ( postalCode): userConfig.update({"postalCode":postalCode} )
  if ( preferredDataLocation): userConfig.update({"preferredDataLocation":preferredDataLocation} )
  if ( preferredLanguage): userConfig.update({"preferredLanguage":preferredLanguage} )
  if ( proxyAddresses): userConfig.update({"proxyAddresses":proxyAddresses} )
  if ( state): userConfig.update({"state":state} )
  if ( streetAddress): userConfig.update({"streetAddress":streetAddress} )
  if ( surname): userConfig.update({"surname":surname} )
  if ( usageLocation): userConfig.update({"usageLocation":usageLocation} )

  if ( extensionAttribute1 or extensionAttribute2 or extensionAttribute3 or extensionAttribute4 or extensionAttribute5 or 
    extensionAttribute6 or extensionAttribute7 or extensionAttribute8 or extensionAttribute9 or extensionAttribute10 or  
    extensionAttribute11 or extensionAttribute12 or extensionAttribute13 or extensionAttribute14 or extensionAttribute15 ):
    onPremisesExtensionAttributes = {}
    if ( extensionAttribute1): onPremisesExtensionAttributes.update({"extensionAttribute1":extensionAttribute1})
    if ( extensionAttribute2): onPremisesExtensionAttributes.update({"extensionAttribute2":extensionAttribute2})
    if ( extensionAttribute3): onPremisesExtensionAttributes.update({"extensionAttribute3":extensionAttribute3})
    if ( extensionAttribute4): onPremisesExtensionAttributes.update({"extensionAttribute4":extensionAttribute4})
    if ( extensionAttribute5): onPremisesExtensionAttributes.update({"extensionAttribute5":extensionAttribute5})
    if ( extensionAttribute6): onPremisesExtensionAttributes.update({"extensionAttribute6":extensionAttribute6})
    if ( extensionAttribute7): onPremisesExtensionAttributes.update({"extensionAttribute7":extensionAttribute7})
    if ( extensionAttribute8): onPremisesExtensionAttributes.update({"extensionAttribute8":extensionAttribute8})
    if ( extensionAttribute9): onPremisesExtensionAttributes.update({"extensionAttribute9":extensionAttribute9})
    if ( extensionAttribute10): onPremisesExtensionAttributes.update({"extensionAttribute10":extensionAttribute10})
    if ( extensionAttribute11): onPremisesExtensionAttributes.update({"extensionAttribute11":extensionAttribute11})
    if ( extensionAttribute12): onPremisesExtensionAttributes.update({"extensionAttribute12":extensionAttribute12})
    if ( extensionAttribute13): onPremisesExtensionAttributes.update({"extensionAttribute13":extensionAttribute13})
    if ( extensionAttribute14): onPremisesExtensionAttributes.update({"extensionAttribute14":extensionAttribute14})
    if ( extensionAttribute15): onPremisesExtensionAttributes.update({"extensionAttribute15":extensionAttribute15})
    userConfig.update({"onPremisesExtensionAttributes":onPremisesExtensionAttributes})
  #print(userConfig)
  new_user = NewGraphObjectByType(token, "users" , userConfig)
  return new_user

def UpdateGraphUser(token, userPrincipalName, displayName=None, mailNickName=None , password=None, accountEnabled = None, forceChangePasswordNextSignIn = None,
        city = None, companyName= None, country = None, department = None, employeeId = None, employeeHireDate = None, employeeOrgData = None,
        employeeType = None, ageGroup = None, businessPhones = None, faxNumber = None, givenName=None, jobTitle = None, mail = None, mobilePhone = None,
        officeLocation = None, postalCode = None, preferredDataLocation = None, preferredLanguage = None, proxyAddresses = None, state = None,
        streetAddress  =None, surname = None, usageLocation = None, extensionAttribute1 = None, extensionAttribute2 = None, extensionAttribute3 = None,
        extensionAttribute4 = None, extensionAttribute5 = None, extensionAttribute6 = None, extensionAttribute7 = None, extensionAttribute8 = None, 
        extensionAttribute9 = None, extensionAttribute10 = None, extensionAttribute11 = None, extensionAttribute12 = None,
        extensionAttribute13 = None, extensionAttribute14 = None, extensionAttribute15 = None   
       ):
    
  userConfig = {}

  if (forceChangePasswordNextSignIn or password):
    passwordProfile = {}
    if ( forceChangePasswordNextSignIn): passwordProfile.update({"forceChangePasswordNextSignIn":forceChangePasswordNextSignIn} )
    if ( password): passwordProfile.update({"password":password} )
    userConfig.update({"passwordProfle":passwordProfile})
  if ( mailNickName): userConfig.update({"mailNickName":mailNickName} )
  if ( displayName): userConfig.update({"displayName":displayName} )
  if ( accountEnabled): userConfig.update({"accountEnabled":accountEnabled} )         
  if ( city): userConfig.update({"city":city} )
  if ( companyName): userConfig.update({"companyName":companyName} )
  if ( country): userConfig.update({"country":country} )
  if ( department): userConfig.update({"department":department} )
  if ( employeeId): userConfig.update({"employeeId":employeeId} )
  if ( employeeHireDate): userConfig.update({"employeeHireDate":employeeHireDate} )
  if ( employeeOrgData): userConfig.update({"employeeOrgData":employeeOrgData} )
  if ( employeeType): userConfig.update({"employeeType":employeeType} )
  if ( ageGroup): userConfig.update({"ageGroup":ageGroup} )
  if ( businessPhones): userConfig.update({"businessPhones":businessPhones} )
  if ( faxNumber): userConfig.update({"faxNumber":faxNumber} )
  if ( givenName): userConfig.update({"givenName":givenName} )
  if ( jobTitle): userConfig.update({"jobTitle":jobTitle} )
  if ( mail): userConfig.update({"mail":mail} )
  if ( mobilePhone): userConfig.update({"mobilePhone":mobilePhone} )
  if ( officeLocation): userConfig.update({"officeLocation":officeLocation} )
  if ( postalCode): userConfig.update({"postalCode":postalCode} )
  if ( preferredDataLocation): userConfig.update({"preferredDataLocation":preferredDataLocation} )
  if ( preferredLanguage): userConfig.update({"preferredLanguage":preferredLanguage} )
  if ( proxyAddresses): userConfig.update({"proxyAddresses":proxyAddresses} )
  if ( state): userConfig.update({"state":state} )
  if ( streetAddress): userConfig.update({"streetAddress":streetAddress} )
  if ( surname): userConfig.update({"surname":surname} )
  if ( usageLocation): userConfig.update({"usageLocation":usageLocation} )

  if ( extensionAttribute1 or extensionAttribute2 or extensionAttribute3 or extensionAttribute4 or extensionAttribute5 or 
    extensionAttribute6 or extensionAttribute7 or extensionAttribute8 or extensionAttribute9 or extensionAttribute10 or  
    extensionAttribute11 or extensionAttribute12 or extensionAttribute13 or extensionAttribute14 or extensionAttribute15 ):
    onPremisesExtensionAttributes = {}
    if ( extensionAttribute1): onPremisesExtensionAttributes.update({"extensionAttribute1":extensionAttribute1})
    if ( extensionAttribute2): onPremisesExtensionAttributes.update({"extensionAttribute2":extensionAttribute2})
    if ( extensionAttribute3): onPremisesExtensionAttributes.update({"extensionAttribute3":extensionAttribute3})
    if ( extensionAttribute4): onPremisesExtensionAttributes.update({"extensionAttribute4":extensionAttribute4})
    if ( extensionAttribute5): onPremisesExtensionAttributes.update({"extensionAttribute5":extensionAttribute5})
    if ( extensionAttribute6): onPremisesExtensionAttributes.update({"extensionAttribute6":extensionAttribute6})
    if ( extensionAttribute7): onPremisesExtensionAttributes.update({"extensionAttribute7":extensionAttribute7})
    if ( extensionAttribute8): onPremisesExtensionAttributes.update({"extensionAttribute8":extensionAttribute8})
    if ( extensionAttribute9): onPremisesExtensionAttributes.update({"extensionAttribute9":extensionAttribute9})
    if ( extensionAttribute10): onPremisesExtensionAttributes.update({"extensionAttribute10":extensionAttribute10})
    if ( extensionAttribute11): onPremisesExtensionAttributes.update({"extensionAttribute11":extensionAttribute11})
    if ( extensionAttribute12): onPremisesExtensionAttributes.update({"extensionAttribute12":extensionAttribute12})
    if ( extensionAttribute13): onPremisesExtensionAttributes.update({"extensionAttribute13":extensionAttribute13})
    if ( extensionAttribute14): onPremisesExtensionAttributes.update({"extensionAttribute14":extensionAttribute14})
    if ( extensionAttribute15): onPremisesExtensionAttributes.update({"extensionAttribute15":extensionAttribute15})
    userConfig.update({"onPremisesExtensionAttributes":onPremisesExtensionAttributes})
  print(userConfig)
  updated_user = UpdateGraphObjectByType(token, "users" , userPrincipalName, userConfig)
  return updated_user


token = GetOAuthTokenByUser(tenant,  msgraph["appId"],userName, password, scope )


##examopke calls

#objects= GetGraphObjectsByType(token, "users")

#object_json =objects

#for entries in object_json:
#  for key, value in entries.items():
#    if (key == "displayName"):
#      print(key, ' : ', value)

#print(objects)

#print(token)

#return_val = NewGraphUser(token, displayName = "Test User2", userPrincipalName="test2@Contoso.net", mailNickName="testuser2", 
#          accountEnabled=True, password = "P@ssword!" , extensionAttribute10="tete", )

#return_val = UpdateGraphObjectByType(token, "users","test2@contoso.net", update_attrs )

#return_val = UpdateGraphUser(token, userPrincipalName="test2@contoso.net", password="JasonFriday13th", forceChangePasswordNextSignIn=True)

#print(return_val)
#print(return_val.text)

#access_token = JWTDecoder(token["access_token"])

#for key, value in access_token.items():
#  print(key, ' : ', value)

#token = GetAccessTokenFromRefreshToken( msgraph["appId"], token["refresh_token"])

#token = GetOAuthTokenByClientSecret(tenant, msgraph["resource"], aid, csecret, ".default" )

#response = StartOAuthTokenByDeviceLogin(tenant, msgraph["appId"], scope)
#devicecode = response.json()["device_code"]
#token = GetOAuthTokenByDeviceLogin(tenant,  msgraph["appId"], devicecode)

#token2 = GetAccessTokenFromRefreshToken(tenant,msgraph["resource"],msgraph["appId"], token.json()["refresh_token"])

#users = GetGraphObjectsByType(token,"users")
#for s in users:
#  print(s["userPrincipalName"])
#print(len(users))

#print(users[21])
#adminuser = GetGraphObjectByTypeID(token,"users","admin@contoso.onmicrosoft.com")

#for key, value in token.items():
#  print(key, ' : ', value)

#access_token = JWTDecoder(token["access_token"])

#for key, value in access_token.items():
#  print(key, ' : ', value)

#token = CheckJWTToken(token, msgraph["appId"])

#return_val = DeleteGraphObjectByTypeID(token, "users", "GaryBrown@contoso.net")
