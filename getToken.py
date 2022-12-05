import json
import tok
import warnings
import sys



#hostmacroid
# https://developer.arubanetworks.com/aruba-central/docs/api-oauth-access-token
# https://apigw-ca.central.arubanetworks.com/swagger/apps/nms/
# Step 0: connect = tok.tokenCentral("client_id","client_secret,"customer_id","username","password","base_url")
connect = tok.tokenCentral('xx','xxxxx','xxxxxx','kamal.ait-hammou@cpu.ca','xxxxxxx','https://apigw-ca.central.arubanetworks.com')
# Step 1: Login and obtain csrf token and session key
csrf_token, session_token = connect.oauthLogin()
# Step 2: Obtain Auth Code
auth_code = connect.oauthCode(csrf_token, session_token)
# Step 3: Swap the auth_code for access token
access_token = connect.oauthAccessToken(auth_code)
print (f'Central Token est  : {access_token}')

result = connect.UpdateZabbix(access_token, sys.argv[1])