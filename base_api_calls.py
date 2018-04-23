"""
This script provides a function to get ISE authentication token
and functions to make REST APIs request
All required modules are imported in this script so from other scripts just need to import this script
"""
import requests   # We use Python external "requests" module to do HTTP query
from requests.auth import HTTPBasicAuth
import json
import sys

# All ISE PAN configuration is in ise_mgmt_config.py
import ise_mgmt_config as imc # ISE PAN IP is assigned in ise_mgmt_config.py
#from tabulate import tabulate # Pretty-print tabular data in Python

# It's used to get rid of certificate warning messages when using Python 3.  This may be the preferred approach for a
# multi-customer use case of these scripts as many internal ISE servers will have self-signed/untrusted certificates.
# For more information please refer to: https://urllib3.readthedocs.org/en/latest/security.html
requests.packages.urllib3.disable_warnings() # Disable warning message

def get_CSRF_token(ip=imc.ISE_PAN_IP,uname=imc.USERNAME,pword=imc.PASSWORD,csrf=imc.CSRF_ENABLED,api=''):
    """
    This function returns a new CSRF ticket.  If the ISE has CSRF enabled,
    this command must be ran before each POST operation to get the latest
    CSRF token.

    Parameters
    ----------
    ip (str): ISE Policy Admin Node routable DNS address or ip
    uname (str): user name of ERS capable user as defined on ISE Policy Admin Node to authenticate with
    pword (str): password of ERS capable user to authenticate with

    Return:
    ----------
    str: ISE CSRF authentication token
    """
    #print("we've made it into the csrf call")
    if (csrf == True):

        # test variables - these variable are provided in the imc file
        #uname = "admin"
        #pword = "Cisc0123!"
        #ip = "192.168.200.10"

        #To retrieve a CSRF token, a GET request with any valid URL is acceptable.  This URL was randomly chosen.
        #api = "ers/config/internaluser"
        print("api sent into this process is = " + api)

        # The url for the post ticket API request
        url = "https://"+ip+":9060/"+api
        print("CSRF URL = " + url)

        # All ISE REST API query and response content type is JSON or XML - for this iteration, we'll focus on JSON
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-CSRF-TOKEN': 'fetch'}
        # POST request and response
        try:
            r = requests.get(url, auth=(uname, pword), headers=headers, verify=False, stream=True)
            # DEBUG: Remove '#' if need to print out response
            #print (r.text)
            #print (r.request.headers)
            #print (r.headers)
            #print (r.content)
            #print (r.headers['X-CSRF-Token'])
            csrfToken = r.headers['X-CSRF-Token']
            # return service CSRF Token
            return csrfToken
        except:
            # Something wrong, cannot get service ticket
            # print ("Status: %s"%r.status_code)
            # print ("Response: %s"%r.text)
            print ("ISE ERS was not reachable.  Please confirm that the ISE Policy Admin Node is reachable, the ERS service is enabled, and that CSRF is required.")
            sys.exit ()
    #else:
        #print("CSRF is disabled...no CSRF to worry about!")


def get(ip=imc.ISE_PAN_IP,uname=imc.USERNAME,pword=imc.PASSWORD,csrf=imc.CSRF_ENABLED,api='',params=''):
    """
    To simplify requests.get with default configuration. Return is the same as requests.get

    Parameters
    ----------
    ip (str): ISE Policy Admin Node routable DNS address or ip
    uname (str): user name of ERS capable user as defined on ISE Policy Admin Node to authenticate with
    pword (str): password of ERS capable user to authenticate with
    api (str): ISE api without prefix
    params (str): optional parameter for GET request

    Return:
    -------
    object: an instance of the Response object (of requests module)
    """
    if (csrf == True):
        csrfToken = get_CSRF_token(ip,uname,pword,csrf,api)
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-CSRF-TOKEN': csrfToken}
        # print("Got a new CSRF = " + csrfToken)
    else:
        #print("@GET: CSRF isn't needed!")
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}

    url = "https://"+ip+":9060/"+api
    #To see the URL calls that are getting made, uncomment the following line
    #print ("\nExecuting GET '%s'\n"%url)
    try:
    # The request and response of "GET" request
        resp = requests.get(url, auth=(uname, pword), headers=headers, params=params, verify = False)

        # If you want to see the details of the request headers, uncomment the following line
        # print(resp.request.headers)

        # If you want to see the response code of the 'GET' request, uncomment the following line:
        # print ("GET '%s' Status: "%api,resp.status_code,'\n') # This is the http request status

        return(resp)
    except:
       print ("Something wrong with GET /",api)
       sys.exit()

def post(ip=imc.ISE_PAN_IP,uname=imc.USERNAME,pword=imc.PASSWORD,csrf=imc.CSRF_ENABLED,api='',data='',json=''):
    """
    To simplify requests.post with default configuration. Return is the same as requests.post

    Parameters
    ----------
    ip (str): ISE Policy Admin Node routable DNS address or ip
    uname (str): user name of ERS capable user as defined on ISE Policy Admin Node to authenticate with
    pword (str): password of ERS capable user to authenticate with
    api (str): ISE api without prefix
    data (JSON): JSON object

    Return:
    -------
    object: an instance of the Response object (of requests module)
    """
    if (csrf == True):
        csrfToken = get_CSRF_token(ip,uname,pword,csrf,api)
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-CSRF-TOKEN': csrfToken, 'User-Agent': 'python-requests/2.18.4','Accept-Encoding': 'gzip,deflate','Connection': 'keep-alive','Cache-Control': 'no-cache'}
    else:
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json','User-Agent': 'python-requests/2.18.4','Accept-Encoding': 'gzip,deflate','Connection': 'keep-alive','Cache-Control': 'no-cache'}
    url = "https://"+ip+":9060/"+api
    #print ("\nExecuting POST '%s'\n"%url)
    try:
    # The request and response of "POST" request

        resp = requests.post(url,data=data,auth=(uname, pword), headers=headers,verify = False,stream= True)
        print("POST '%s' Status: "%api,resp.status_code,'\n') # This is the http request status
        return(resp)
    except:
       print ("Something wrong with POST /",api)
       sys.exit()

def put(ip=imc.ISE_PAN_IP,uname=imc.USERNAME,pword=imc.PASSWORD,csrf=imc.CSRF_ENABLED,api='',data=''):
    """
    To simplify requests.put with default configuration.Return is the same as requests.put

    Parameters
    ----------
    ip (str): ISE Policy Admin Node routable DNS address or ip
    uname (str): user name of ERS capable user as defined on ISE Policy Admin Node to authenticate with
    pword (str): password of ERS capable user to authenticate with
    api (str): ISE api without prefix
    data (JSON): JSON object

    Return:
    -------
    object: an instance of the Response object(of requests module)
    """
    if (csrf == True):
        csrfToken = get_CSRF_token(ip,uname,pword,csrf)
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-CSRF-TOKEN': csrfToken}
    else:
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
    url = "https://"+ip+":9060/"+api
    #print ("\nExecuting PUT '%s'\n"%url)
    try:
    # The request and response of "PUT" request
        resp = requests.put(url,data=data,auth=(uname, pword),headers=headers,verify = False, stream = True)
        #print ("PUT '%s' Status: "%api,resp.status_code,'\n') # This is the http request status
        return(resp)
    except:
       print ("Something wrong with PUT /",api)
       sys.exit()

def delete(ip=imc.ISE_PAN_IP,uname=imc.USERNAME,pword=imc.PASSWORD,csrf=imc.CSRF_ENABLED,api='',params=''):
    """
    To simplify requests.delete with default configuration.Return is the same as requests.delete

    Parameters
    ----------
    ip (str): ISE Policy Admin Node routable DNS address or ip
    uname (str): user name of ERS capable user as defined on ISE Policy Admin Node to authenticate with
    pword (str): password of ERS capable user to authenticate with
    api (str): ISE api without prefix
    params (str): optional parameter for DELETE request

    Return:
    -------
    object: an instance of the Response object(of requests module)
    """
    if (csrf == True):
        csrfToken = get_CSRF_token(ip,uname,pword,csrf)
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-CSRF-TOKEN': csrfToken}
    else:
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
    url = "https://"+ip+":9060/"+api
    #print ("\nExecuting DELETE '%s'\n"%url)
    try:
        resp = requests.delete(url,auth=(uname, pword),headers=headers,params=params,verify = False, stream = True)
        #print ("DELETE '%s' Status: "%api,resp.status_code,'\n') # This is the http request status
        return(resp)
    except:
       print ("Something wrong with DELETE /",api)
       sys.exit()

# These are the XML versions of the CRUD calls.  We'll leave the option for CSRF in case it is needed down the road.  But we do NOT need the :9060 port.
# The API uses the APIADMIN, so we will use a different username/pass for these calls.

def getx(ip=imc.ISE_PAN_IP,uname=imc.APIUSER,pword=imc.APIPASS,csrf=imc.CSRF_ENABLED,api='',params=''):
    """
    To simplify requests.get with default configuration. Return is the same as requests.get

    Parameters
    ----------
    ip (str): ISE Policy Admin Node routable DNS address or ip
    uname (str): user name of ERS capable user as defined on ISE Policy Admin Node to authenticate with
    pword (str): password of ERS capable user to authenticate with
    api (str): ISE api without prefix
    params (str): optional parameter for GET request

    Return:
    -------
    object: an instance of the Response object (of requests module)
    """
    if (csrf == True):
        csrfToken = get_CSRF_token(ip,uname,pword,csrf)
        headers = {'Content-Type': 'application/xml', 'Accept': 'application/xml', 'X-CSRF-TOKEN': csrfToken}
    else:
        headers = {'Content-Type': 'application/xml', 'Accept': 'application/xml'}
    url = "https://"+ip+api
    #print ("\nExecuting GET '%s'\n"%url)
    try:
        resp = requests.get(url, auth=(uname, pword), headers=headers, params=params, verify = False)
        # print ("GET '%s' Status: "%api,resp.status_code,'\n') # This is the http request status
        return(resp)
    except:
       print ("Something wrong with GET /",api)
       sys.exit()

def postx(ip=imc.ISE_PAN_IP,uname=imc.APIUSER,pword=imc.APIPASS,csrf=imc.CSRF_ENABLED,api='',data=''):
    """
    To simplify requests.post with default configuration. Return is the same as requests.post

    Parameters
    ----------
    ip (str): ISE Policy Admin Node routable DNS address or ip
    uname (str): user name of ERS capable user as defined on ISE Policy Admin Node to authenticate with
    pword (str): password of ERS capable user to authenticate with
    api (str): ISE api without prefix
    data (JSON): JSON object

    Return:
    -------
    object: an instance of the Response object(of requests module)
    """
    if (csrf == True):
        csrfToken = get_CSRF_token(ip,uname,pword,csrf)
        headers = {'Content-Type': 'application/xml', 'Accept': 'application/xml', 'X-CSRF-TOKEN': csrfToken}
    else:
        headers = {'Content-Type': 'application/xml', 'Accept': 'application/xml'}
    url = "https://"+ip+api
    #print ("\nExecuting POST '%s'\n"%url)
    try:
        resp = requests.post(url,json.dumps(data),auth=(uname, pword),headers=headers,verify = False)
        #print ("POST '%s' Status: "%api,resp.status_code,'\n') # This is the http request status
        return(resp)
    except:
       print ("Something wrong with POST /",api)
       sys.exit()

def putx(ip=imc.ISE_PAN_IP,uname=imc.APIUSER,pword=imc.APIPASS,csrf=imc.CSRF_ENABLED,api='',data=''):
    """
    To simplify requests.put with default configuration.Return is the same as requests.put

    Parameters
    ----------
    ip (str): ISE Policy Admin Node routable DNS address or ip
    uname (str): user name of ERS capable user as defined on ISE Policy Admin Node to authenticate with
    pword (str): password of ERS capable user to authenticate with
    api (str): ISE api without prefix
    data (JSON): JSON object

    Return:
    -------
    object: an instance of the Response object(of requests module)
    """
    if (csrf == True):
        csrfToken = get_CSRF_token(ip,uname,pword,csrf)
        headers = {'Content-Type': 'application/xml', 'Accept': 'application/xml', 'X-CSRF-TOKEN': csrfToken}
    else:
        headers = {'Content-Type': 'application/xml', 'Accept': 'application/xml'}
    url = "https://"+ip+api
    #print ("\nExecuting PUT '%s'\n"%url)
    try:
        resp = requests.put(url,json.dumps(data),auth=(uname, pword),headers=headers,verify = False)
        #print ("PUT '%s' Status: "%api,resp.status_code,'\n') # This is the http request status
        return(resp)
    except:
       print ("Something wrong with PUT /",api)
       sys.exit()

def deletex(ip=imc.ISE_PAN_IP,uname=imc.APIUSER,pword=imc.APIPASS,csrf=imc.CSRF_ENABLED,api='',params=''):
    """
    To simplify requests.delete with default configuration.Return is the same as requests.delete

    Parameters
    ----------
    ip (str): ISE Policy Admin Node routable DNS address or ip
    uname (str): user name of ERS capable user as defined on ISE Policy Admin Node to authenticate with
    pword (str): password of ERS capable user to authenticate with
    api (str): ISE api without prefix
    params (str): optional parameter for DELETE request

    Return:
    -------
    object: an instance of the Response object(of requests module)
    """
    if (csrf == True):
        csrfToken = get_CSRF_token(ip,uname,pword,csrf)
        headers = {'Content-Type': 'application/xml', 'Accept': 'application/xml', 'X-CSRF-TOKEN': csrfToken}
    else:
        headers = {'Content-Type': 'application/xml', 'Accept': 'application/xml'}
    url = "https://"+ip+api
    #print ("\nExecuting DELETE '%s'\n"%url)
    try:
        resp = requests.delete(url,auth=(uname, pword),headers=headers,params=params,verify = False)
        #print ("DELETE '%s' Status: "%api,resp.status_code,'\n') # This is the http request status
        return(resp)
    except:
       print ("Something wrong with DELETE /",api)
       sys.exit()
