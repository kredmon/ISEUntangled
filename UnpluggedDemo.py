from __future__ import print_function
# All ISE PAN configuration is in ise_mgmt_config.py including ISE_PAN_IP
# and USERNAME and PASSWORD.
import ise_mgmt_config as imc
import base_api_calls as bac

import requests   # We use Python external "requests" module to do HTTP query
from requests.auth import HTTPBasicAuth
from requests_toolbelt import MultipartEncoder
import json
import sys
import os
import re
from lxml import etree #This will help to simplify the parsing of XML results

#These are used by the RADIUS Probe Function
from pyrad.client import Client
from pyrad.dictionary import Dictionary
import pyrad.packet
import time
import datetime


# It's used to get rid of certificate warning messages when using Python 3.
# This may be the preferred approach for a multi-customer use case of these
# scripts as many internal ISE servers will have self-signed/untrusted
# certificates.  For more information please refer to:
# https://urllib3.readthedocs.org/en/latest/security.html
requests.packages.urllib3.disable_warnings() # Disable warning message
os.system("stty erase '^H'")

# We'll define a few variables that we'll use often.
#ip = imc.ISE_PAN_IP
#uname = imc.USERNAME
#pword = imc.PASSWORD

#global variables
choice = ""
bearerTokenISEBot = "MzlkMzQ3YWMtODA0MC00NjI5LTgwYzktNTlhOGU1NWNhMzkzYTBhNWZlNDEtNmQ5"
roomIDISEBot = "Y2lzY29zcGFyazovL3VzL1JPT00vZjliMTcwZDAtNDQ1My0xMWU4LWE3ZGQtMDM1MzBmMTVkMGNl"

def printMenu():
    global choice
    os.system("clear")
    print("Main Menu")
    print("=========")
    print("1. Network Device Group Menu")
    print("2. Endpoint/Endpoint Identity Group Menu")
    print("3. Authorization Profiles")
    print("4. Radius Probe")
    print("5. Portal Information")
    print("6. Threat Remediation")
    print("7. Downloadable ACLs")
    print("")
    choice = input("Please choose the task from above list (q to quit): ")
# End <printMenu>

def printNasMenu():
    global nChoice
    os.system("clear")
    print("Network Device Group Menu")
    print("=========================")
    print("1. List Network Devices")
    print("2. Delete Network Device")
    print("3. Import Network Device(s) from File")
    print("4. List Network Device Groups")
    print("5. Create Network Device Group")
    print("6. Delete Network Device Group")
    print("")
    nChoice = input("Please choose the task from the above list (q to go to previous menu): ")
# End <printNasMenu>

def listNetworkDevices():
    """
    This function will list all Network Access Devices that are currently in the ISE database
    """
    # Get the API call from imc - in this case, we'll get all of the
    # Network Devices
    api = imc.networkDevice().getAll

    # If CSRF is enabled, we'll include the CSRF Token into the headers for this section
    if (imc.CSRF_ENABLED==True):
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-CSRF-Token': bac.get_CSRF_token(ip=imc.ISE_PAN_IP,uname=imc.USERNAME,pword=imc.PASSWORD,csrf=imc.CSRF_ENABLED)}
    else:
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}

    # Make the CRUD call into ISE - the response will be JSON
    lndOutput = bac.get(api=api)

    # Store the JSON output into a variable into a python dictionary structure
    jLndOutput = lndOutput.json()
    lndIds=[]
    noLnd = 1

    # Pull the "useful" data from the JSON data
    for values in jLndOutput['SearchResult']['resources']:
        lndURL = values['link']['href']
        lndResp = requests.get(lndURL, auth=(imc.USERNAME, imc.PASSWORD), headers=headers, params='', verify = False)
        jLndResp = lndResp.json()
        #print(jLndResp)
        ipAddressString = jLndResp['NetworkDevice']['NetworkDeviceIPList'][0]['ipaddress']+"/"+str(jLndResp['NetworkDevice']['NetworkDeviceIPList'][0]['mask'])
        lndIds.append((noLnd,jLndResp['NetworkDevice']['name'],jLndResp['NetworkDevice']['authenticationSettings']['networkProtocol'], jLndResp['NetworkDevice']['profileName'],ipAddressString,jLndResp['NetworkDevice']['id']))
        noLnd += 1

    # This table will be an array of records - each entry equals the relevant
    # information from a Network Device - Name, Protocol, Profile, IP address, and ID
    validLnd = len(lndIds)

    # We'll clear the screen and provide a parsed table of the output.
    os.system("clear")
    print('{:^5}'.format(str("Index")) + " | " + '{:<30}'.format(str("Name")) + " | " + '{:<20}'.format(str("Network Protocol")) + " | " + '{:<20}'.format(str("Profile Name"))+ " | " + '{:<20}'.format(str("IP Address")))
    print("="*95 + "="*12)
    index = 0
    for x in lndIds:
        print('{:^5}'.format(str(x[0])) + " | " + '{:<30}'.format(str(x[1])) + " | " + '{:<20}'.format(str(x[2])) + " | " + '{:<20}'.format(str(x[3]))+ " | " + '{:<20}'.format(str(x[4])))
        index += 1
    input("Press <Enter> to continue...")
# End <listNetworkDevices>

def deleteNetworkDevice():
    """
    This function will delete a network device by it's ID from the ISE database.
    """

    # Get the API call from imc - we'll get all network devices - then we'll delete
    # by number
    api = imc.networkDevice().getAll

    # If CSRF is being used, this will include the CSRF Token in the HTML headers.
    if (imc.CSRF_ENABLED==True):
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-CSRF-Token': bac.get_CSRF_token(ip=imc.ISE_PAN_IP,uname=imc.USERNAME,pword=imc.PASSWORD,csrf=imc.CSRF_ENABLED)}
    else:
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}

    # Make the CRUD call into ISE - the response will be JSON
    dndOutput = bac.get(api=api)

    # Convert the JSON output from the CRUD call into a python dictionary
    jDndOutput = dndOutput.json()
    dndIds=[]
    noDnd = 1

    # Pull the "useful" data from the JSON data
    for values in jDndOutput['SearchResult']['resources']:
        dndURL = values['link']['href']
        dndResp = requests.get(dndURL, auth=(imc.USERNAME, imc.PASSWORD), headers=headers, params='', verify = False)
        jDndResp = dndResp.json()
        #print(jDndResp)
        ipAddressString = jDndResp['NetworkDevice']['NetworkDeviceIPList'][0]['ipaddress']+"/"+str(jDndResp['NetworkDevice']['NetworkDeviceIPList'][0]['mask'])
        dndIds.append((noDnd,jDndResp['NetworkDevice']['name'],jDndResp['NetworkDevice']['authenticationSettings']['networkProtocol'], jDndResp['NetworkDevice']['profileName'],ipAddressString,jDndResp['NetworkDevice']['id']))
        noDnd += 1
    validDnd = len(dndIds)

    # This loop will list the network devices and then test the input for the
    # device that should be deleted.  If the input is not valid, we'll reset
    # the screen with the list of the devices again and ask for the user to
    # reselect the item to delete.
    selectDnd = ""
    while (selectDnd == ""):
        # We'll clear the screen and provide a parsed table of the output.
        os.system("clear")
        print('{:^5}'.format(str("Index")) + " | " + '{:<30}'.format(str("Name")) + " | " + '{:<20}'.format(str("Network Protocol")) + " | " + '{:<20}'.format(str("Profile Name"))+ " | " + '{:<20}'.format(str("IP Address")))
        print("="*95 + "="*12)
        index = 0
        for x in dndIds:
            print('{:^5}'.format(str(x[0])) + " | " + '{:<30}'.format(str(x[1])) + " | " + '{:<20}'.format(str(x[2])) + " | " + '{:<20}'.format(str(x[3]))+ " | " + '{:<20}'.format(str(x[4])))
            index += 1

        # Now that we've printed out the current network devices, the user will
        # provide input as to which one should be deleted.
        try:
            # Let's ensure that the input is an integer - if not, we'll hit the 'except' and try again.
            print("")
            selectDnd = int(input("Please provide the number of the Network Device to delete ('0' to quit): "))

            # If the user inputs '0', they intend to quit this function without
            # deleting any device, so we'll exit this function without a return value.
            if (selectDnd == 0):
                return

        # If anything goes wrong with the input - ie NOT providing an integer value -
        # we'll throw an error and ask that they provide the correct values.
        except:
            print("Error - Please provide a value between 1-" + str(validDnd) + " or '0' to quit - Please try again!")
            input("Press <Enter> to continue...")
            continue

        # Let's ensure that the entry is valid given the number of Network Devices
        if not ((selectDnd>=0) and (selectDnd<validDnd+1)):
            selectDnd = ""
            print("Error - Please provide a value between 1-" + str(validDnd) + " - Please try again!")
            input("Press <Enter> to continue...")

    # The user did NOT select '0' and the value they provided must be within the
    # valid range...and it didn't throw an error (ie must be an integer).
    if (selectDnd !=0):
        # We'll validate that the user truly wants to delete the device in question.
        confirmProfDel = input("Please type 'yes' to confirm that you would like to delete the Network Device '" + dndIds[selectDnd-1][1] + "': ")

        if (confirmProfDel == "yes"):

            # The fifth index of the dndIds list is the ID of the Network Device
            # We'll retrieve the API for Delete By ID for the Network Device
            delApi = imc.networkDevice().delete_ById(dndIds[selectDnd-1][5])

            # Let's make the DELETE call using the Delete By ID API.
            try:
                dndOutput = bac.delete(api=delApi)
                print("The Network Device '" + dndIds[selectDnd-1][1] + "' has been deleted!")
            except:
                print("There may have been an error in the deletion process - please confirm deletion!")

        # If the user did NOT provide an affirmative "yes" answer, we'll exit
        # without deleting any device.
        else:
            print("Operation aborted!")
    input("Press <Enter> to continue...")
# End <deleteNetworkDevice>

def importNetworkDevice():
    """
    This function will import a list of devices from a CSV file.
    """

    # If CSRF is being used, this will include the CSRF Token in the HTML headers.
    if (imc.CSRF_ENABLED==True):
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-CSRF-Token': bac.get_CSRF_token(ip=imc.ISE_PAN_IP,uname=imc.USERNAME,pword=imc.PASSWORD,csrf=imc.CSRF_ENABLED)}
    else:
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}

    # We'll clear the screen and then create a template file for the user to
    # use when creating his list of devices to import.
    os.system("clear")
    template = open("NetworkDeviceTemplate.csv",'w')
    template.write("name,ip,mask,radiusSharedSecret,NDG1;NDG2;NDG3...\n")
    template.write("Switch1,10.1.1.1,32,Cisco123!,Location#All Locations;IPSEC#Is IPSEC Device#No;Device Type#All Device Types\n")
    template.close()
    print("File 'NetworkDeviceTemplate.csv' was created - modify this file with the appropriate Network Devices and their respective Network Device Groups and save as a new name.")
    print("Note: Capitalization does matter - and leave the column headers in tact.")
    print("WARNING: If the Network Device name contains a space, the spaces will be converted to a '-'.")

    # This array will store those groups that are in the list that is imported
    # that don't yet exist in the Network Device Groups.
    createdGroups=[]

    # Let's open the file and start importing the data.
    getInputFile = input("Please provide the filename of the file to import: ")
    try:
        with open(getInputFile) as inFile:
            content = inFile.read().splitlines()
    except:
        print("There must be a problem with the filename - please try again!")
        input("Press <Enter> to Continue...")
        return

    # Remove the header row if it was left behind within the template file.
    del content[0]

    # Read the Lines from the file and put the contents into a list/array.
    addedNetworkDevices = []
    for line in content:
        deviceName = line.split(',')[0]
        ipAddress = line.split(',')[1]
        mask = line.split(',')[2]
        sharedSecret = line.split(',')[3]
        ndgList = line.split(',')[4]

        # Because Network Device Groups can not have whitespace, we'll change
        # spaces to hyphens.
        if " " in deviceName:
            deviceName = deviceName.replace(' ','-')

        # We'll create a table of each device that we want to add to the database
        # and the relevant data that we'll store.
        addedEntry = [deviceName,ipAddress,mask,sharedSecret,ndgList.split(';')]
        addedNetworkDevices.append(addedEntry)

    # This section will make individual POST calls into ISE to add each
    # device into the ISE database.
    # First, let's retrieve the POST API for creating a Network Device.
    newApi = imc.networkDevice().postCreate

    # For each Network Device in the array, we'll create the necessary
    # datastring to add it to the ISE database.
    for newDevice in addedNetworkDevices:
        ndgString = ""
        for ndg in newDevice[4]:
            if (len(ndgString) > 0):
                ndgString += ', "' + ndg + '"'
            else:
                ndgString = '"' + ndg + '"'

        #This data string will be the JSON body of the POST call
        data = '{"NetworkDevice" : {"name" : "'+newDevice[0]+'","description" : "DEFAULT","authenticationSettings" : {"networkProtocol": "RADIUS","radiusSharedSecret" : "'+newDevice[3]+'","keyInputFormat" : "ASCII"},"profileName" : "Cisco","NetworkDeviceIPList" : [ {"ipaddress" : "'+newDevice[1]+'","mask" : '+newDevice[2]+'} ],"NetworkDeviceGroupList" : [ '+ndgString+' ]}}'
        try:
            negOutput = bac.post(api=newApi,data=data)
            print("Network Device '" + newDevice[0] + "' was created!")
        except:
            print("There must be a problem with the creation - please try again!")
    input("Press <Enter> to Continue...")
# End <importNetworkDevice>

def listNasGroups():
    """
    This function will retrieve the list of Network Access Devices from ISE
    and print them to the screen in a nice table format.
    """

    # Retrieve the appropriate API for getting all Network Devices to be listed
    api = imc.networkDeviceGroup().getAll

    # Let's call the HTTP GET function using the Get All Network Devices.
    lngOutput = bac.get(api=api)
    jLngOutput = lngOutput.json()

    # Let's clear the screen and print the data to the screen in a pretty table.
    os.system("clear")
    print('{:^5}'.format(str("Index")) + " | " + '{:<50}'.format(str("Name")) + " | " + '{:<45}'.format(str("Description")))
    print("="*100 + "======")
    index = 1
    for x in jLngOutput['SearchResult']['resources']:
        print('{:^5}'.format(str(index)) + " | " + '{:<50}'.format(x['name']) + " | " + '{:<45}'.format(str(x['description'])))
        index += 1

    input("Press <Enter> to Continue...")
# End <listNasGroups>

def createNasGroup():
    """
    This function will allow you to create a Network Device Group.
    """

    # Retrieve the appropriate API for getting all Network Device Groups
    api = imc.networkDeviceGroup().getAll
    lngOutput = bac.get(api=api)
    jLngOutput = lngOutput.json()

    # Let's print the current Network Device Groups - the formatting of a NDG
    # is rather peculiar, so we'll use this list to copy/paste the format.
    os.system("clear")
    print("Current Network Device Groups:")
    print("")
    print('{:^5}'.format(str("Index")) + " | " + '{:<50}'.format(str("Name")) + " | " + '{:<45}'.format(str("Description")))
    print("="*100 + "======")
    index = 1
    for x in jLngOutput['SearchResult']['resources']:
        print('{:^5}'.format(str(index)) + " | " + '{:<50}'.format(x['name']) + " | " + '{:<45}'.format(str(x['description'])))
        index += 1
    print("")

    # Retrieve the API to create the new Network Device Group.
    newApi = imc.networkDeviceGroup().postCreate

    # Prompt the user for the relevant data to create the new Network Device Group.
    ndgNameRaw = input("Please provide a name for the new Device Group: ")
    ndgName = str(ndgNameRaw)

    # The "shortName" below has to be the first portion of the Device Group Name.
    shortName = ndgName.split('#')[0]
    ndgDescRaw = input("Please provide a brief description for the new Device Group: ")
    ndgDesc = str(ndgDescRaw)

    # The 'data' variable below will be the content of the POST body and will
    # create the respective Network Device Group.
    data = '{"NetworkDeviceGroup" : {"name" : "' + ndgName + '","description" : "' + ndgDesc + '","othername" : "' + shortName + '"}}'

    # Let's call the POST operation and "assume" our data went over without issue.
    cngOutput = bac.post(api=newApi,data=data)
    input("Press <Enter> to Continue...")
# End <createNasGroup>

def deleteNasGroup():
    """
    This function will allow you to delete a Network Device Group from ISE.
    """

    # Let's list all Profiles and allow the user to delete them by number - not
    # Name.  This array will store the necessary data for the Network Device Group
    # until we need it.
    ndgIds=[]

    # Let's retrieve the API to list all Network Device Groups.
    api = imc.networkDeviceGroup().getAll

    # If we are using CSRF, this will include the CSRF Token into the HTTP headers.
    if (imc.CSRF_ENABLED==True):
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-CSRF-Token': bac.get_CSRF_token(ip=imc.ISE_PAN_IP,uname=imc.USERNAME,pword=imc.PASSWORD,csrf=imc.CSRF_ENABLED)}
    else:
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}

    # Let's' retrieve all of the Network Device Groups and then Delete by Number.
    dngOutput = bac.get(api=api)

    # Let's parse the response and store it as a python dictionary.
    jDngOutput = dngOutput.json()

    # This 'for' loop will grab the most relevant data from the Device Group
    # that will be useful in deleting it.
    for values in jDngOutput['SearchResult']['resources']:
        ndgIds.append((values['name'],values['description'],values['id']))
    validEntries = len(ndgIds)

    # We'll print the list to the user and cycle through this section until the
    # user provides valid input.
    selectNdg = ""
    while (selectNdg == ""):
        # Print out the current list of Network Device Groups in a nice table.
        os.system("clear")
        print('{:^5}'.format(str("Index")) + " | " + '{:<50}'.format(str("Name")) + " | " + '{:<45}'.format(str("Description")))
        print("="*100 + "======")
        index = 0
        for x in ndgIds:
            print('{:^5}'.format(str(index+1)) + " | " + '{:<50}'.format(str(x[0])) + " | " + '{:<45}'.format(str(x[1])))
            index += 1

        # Since we want the user to Delete the Network Device Group by number,
        # we still have to check his input to ensure it is a valid NDG selection.
        try:
            # Let's ensure that the input is an integer - if not, we'll hit the 'except' and try again.
            selectNdg = int(input("Please provide the number of the Authorization Profile to delete ('0' to quit): "))

            # If the user selects '0', they must want to quit - let's exit the
            # function without returning a value.
            if (selectNdg == 0):
                return
        except:
            print("Error - Please provide a value between 1-" + str(validEntries) + " - Please try again!")
            exit()

        # Let's ensure that the entry is valid given the number of Network Device Groups.
        if not ((selectNdg>=0) and (selectNdg<validEntries+1)):
            selectNdg = ""
            print("Error - Please provide a value between 1-" + str(validEntries) + " - Please try again!")
            input("Press <Enter> to continue...")

    # The user must have selected a numerical value and that value is NOT '0'
    if (selectNdg !=0):

        # Let's confirm that the user indeed wants to delete the selected NDG.
        confirmNdgDel = input("Please type 'yes' to confirm that you would like to delete Authorization Profile '" + ndgIds[selectNdg-1][0] + "': ")
        if (confirmNdgDel == "yes"):

            # The second index of the ndgIds list is the ID of the Network Device Group
            # We'll call the Delete By ID API call for the Network Device Group.
            delApi = imc.networkDeviceGroup().delete_ById(ndgIds[selectNdg-1][2])

            # We'll try to make the call to ISE to delete the device.
            try:
                dNdgOutput = bac.delete(api=delApi)
                print("The Network Device Group '" + ndgIds[selectNdg-1][0] + "' has been deleted!")
            except:
                print("There may have been an error in the deletion process - please confirm deletion!")

        # The user's input was NOT 'yes' so we'll abort the delete process.
        else:
            print("Operation aborted!")
        input("Press <Enter> to continue...")
# End <deleteNasGroup>

def printEndpointMenu():
    """
    The Endpoint Menu will give the user access to Endpoint related functions.
    """
    # This variable is used to track the users selection on the Endpoint menus.
    global eChoice

    # Clear the screen and print the list.
    os.system("clear")
    print("Endpoint/Endpoint Identity Group Menu")
    print("=====================================")
    print("1. List All Endpoints")
    print("2. List All Endpoint Identity Groups")
    print("3. Add Endpoint List")
    print("4. Add Endpoint to Endpoint List")
    print("5. Import Endpoint to Identity Groups")
    print("6. Delete Endpoint")
    print("7. Delete Endpoint Identity Group")
    eChoice = input("Please choose the task from the above list (q to go to previous menu): ")
# End <printEndpointMenu>

def printAllEndpoints():
    """
    This function will print out all of the Endpoints that are in the ISE
    database.
    """

    # Retrieve the API to Get All of the Endpoints.
    api = imc.endPoint().getAll

    # If CSRF is being used, we'll need to include the CSRF Token in the HTTP headers.
    if (imc.CSRF_ENABLED==True):
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-CSRF-Token': bac.get_CSRF_token(ip=imc.ISE_PAN_IP,uname=imc.USERNAME,pword=imc.PASSWORD,csrf=imc.CSRF_ENABLED)}
    else:
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}

    # Make the GET call to the API above to retrieve the enpdoint data.
    EndpointOutput = bac.get(api=api)

    # The data from the GET call is JSON - let's store that data in a python dictionary.
    jEndpointOutput = EndpointOutput.json()

    # Get the relevant/important data from each endpoint and store it in an array.
    noEndpoint = 1
    endpointIds = []
    for values in jEndpointOutput['SearchResult']['resources']:
        endpointURL = values['link']['href']
        endpointResp = requests.get(endpointURL, auth=(imc.USERNAME, imc.PASSWORD), headers=headers, params='', verify = False)
        jEndpointResp = endpointResp.json()
        endpointGroupId = jEndpointResp['ERSEndPoint']['groupId']

        #Let's resolve the groupId for a human readable Endpoint Identity Group name
        gApi = imc.endPointIdentityGroup().get_ById(endpointGroupId)
        groupOutput = bac.get(api=gApi)
        jGroupOutput = groupOutput.json()
        endpointGroupName = jGroupOutput['EndPointGroup']['name']

        # Some of the endpoints will have a profileId.  If there is an ID,
        # retrieve the Profile Name with a second API call.
        if jEndpointResp['ERSEndPoint']['profileId'] != '':
            api = 'ers/config/profilerprofile/'+jEndpointResp['ERSEndPoint']['profileId']
            profileResp = bac.get(api=api)
            jProfileResp = profileResp.json()
            endpointProf = jProfileResp['ProfilerProfile']['name']

        # If it doesn't have a ProfileID, we'll print that it is 'Unknown'.
        else:
            endpointProf = "Unknown"

        # We'll put all of the useful data into an array and then print it to the screen.
        endpointIds.append((noEndpoint,jEndpointResp['ERSEndPoint']['name'],jEndpointResp['ERSEndPoint']['mac'], endpointProf, endpointGroupName, jEndpointResp['ERSEndPoint']['portalUser'], values['id']))
        noEndpoint += 1

    # We'll print it out into a nice pretty table now.
    os.system("clear")
    print('{:^5}'.format(str("Index")) + " | " + '{:<30}'.format(str("Name")) + " | " + '{:<18}'.format(str("MAC Address")) + " | " + '{:<30}'.format(str("Endpoint Profile")) + " | " + '{:<40}'.format(str("Endpoint Identity Group")) + " | " + '{:<30}'.format(str("Portal User")))
    print("="*153 + "==================")
    index = 0
    for x in endpointIds:
        print('{:^5}'.format(str(x[0])) + " | " + '{:<30}'.format(str(x[1])) + " | " + '{:<18}'.format(str(x[2])) + " | " + '{:<30}'.format(str(x[3])) + " | " + '{:<40}'.format(str(x[4])) + " | " + '{:<30}'.format(str(x[5])))
        index += 1

    input("Press <Enter> to Continue...")
# End <printAllEndpoints>

def printAllEndpointGroups():
    """
    This function will print all of the Endpoint Groups.
    """

    #Retrieve the Get All Endpoint Group API`
    api = imc.endPointIdentityGroup().getAll

    # If CSRF is being used, we'll want to include the CSRF Token into the HTTP headers.
    if (imc.CSRF_ENABLED==True):
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-CSRF-Token': bac.get_CSRF_token(ip=imc.ISE_PAN_IP,uname=imc.USERNAME,pword=imc.PASSWORD,csrf=imc.CSRF_ENABLED)}
    else:
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
    epgOutput = bac.get(api=api)

    # The result from the HTTP GET is JSON - we'll convert that to a python dictionary.
    jEpgOutput = epgOutput.json()

    # Let's store the useful data for the Endpoint Groups into an array for easy
    # access for printing.
    epgIds=[]
    noEpg = 1
    for values in jEpgOutput['SearchResult']['resources']:
        epgURL = values['link']['href']
        epgResp = requests.get(epgURL, auth=(imc.USERNAME, imc.PASSWORD), headers=headers, params='', verify = False)
        jEpgResp = epgResp.json()
        epgIds.append((noEpg,jEpgResp['EndPointGroup']['name'],jEpgResp['EndPointGroup']['description'], jEpgResp['EndPointGroup']['systemDefined'],jEpgResp['EndPointGroup']['id']))
        noEpg += 1

    # Let's clear the screen and print the Endpoint Groups into a pretty table.
    os.system("clear")
    print('{:^5}'.format(str("Index")) + " | " + '{:<30}'.format(str("Name")) + " | " + '{:<60}'.format(str("Description")) + " | " + '{:<30}'.format(str("System Defined")))
    print("="*125 + "=========")
    index = 0
    for x in epgIds:
        print('{:^5}'.format(str(x[0])) + " | " + '{:<30}'.format(str(x[1])) + " | " + '{:<60}'.format(str(x[2])) + " | " + '{:<30}'.format(str(x[3])))
        index += 1

    input("Press <Enter> to Continue...")
# End <printAllEndpointGroups>

def addEndpointList():
    """
    This function will allow the user to add an Endpoint Identity Group.
    """

    # Retrieve the API for current Endpoint Identity Groups.
    api = imc.endPointIdentityGroup().getAll

    # If CSRF is being used, we'll need to include the CSRF Token in the HTTP headers.
    if (imc.CSRF_ENABLED==True):
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-CSRF-Token': bac.get_CSRF_token(ip=imc.ISE_PAN_IP,uname=imc.USERNAME,pword=imc.PASSWORD,csrf=imc.CSRF_ENABLED)}
    else:
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}

    # Make the HTTP GET call to retrieve the list of Endpoint Groups.
    epgOutput = bac.get(api=api)

    # Convert the JSON output from the HTTP GET into a python dictionary.
    jEpgOutput = epgOutput.json()

    # Let's store the relevant Endpoint Group data into an array.
    epgIds=[]
    noEpg = 1
    for values in jEpgOutput['SearchResult']['resources']:
        epgURL = values['link']['href']
        epgResp = requests.get(epgURL, auth=(imc.USERNAME, imc.PASSWORD), headers=headers, params='', verify = False)
        jEpgResp = epgResp.json()
        epgIds.append((noEpg,jEpgResp['EndPointGroup']['name'],jEpgResp['EndPointGroup']['description'], jEpgResp['EndPointGroup']['systemDefined']))
        noEpg += 1

    # We'll print the current Endpoint Identity Groups on the screen.
    os.system("clear")
    print("Current Endpoint Identity Groups")
    print("")
    print('{:^5}'.format(str("Index")) + " | " + '{:<30}'.format(str("Name")) + " | " + '{:<60}'.format(str("Description")) + " | " + '{:<30}'.format(str("System Defined")))
    print("="*125 + "=========")
    index = 0
    for x in epgIds:
        print('{:^5}'.format(str(x[0])) + " | " + '{:<30}'.format(str(x[1])) + " | " + '{:<60}'.format(str(x[2])) + " | " + '{:<30}'.format(str(x[3])))
        index += 1

    # Let's get the API to create a new Endpoint Identity Group.
    newApi = imc.endPointIdentityGroup().postCreate

    # Let's get some data for the user so we can create a new Endpoint Identity Group.
    negName = input("Please provide a name for the new Endpoint Identity Group: ")
    negDesc = input("Please provide a brief description for the new Endpoint Identity Group: ")

    # This 'data' will be the HTML Body of the POST command to create the Endpoint Identity Group.
    data = '{"EndPointGroup" : {"name" : "' + negName + '","description" : "' + negDesc + '"}}'

    # Let's send the data now to the ISE database and ensure it got there.
    try:
        negOutput = bac.post(api=newApi,data=data)
        print("Endpoint Identity Group '" + negName + "' was created!")
    except:
        print("There was a problem creating the Endpoint Identity Group!")
    input("Press <Enter> to Continue...")
# End <addEndpointList>

def addEndpointToList():
    """
    This function will allow the user to add a particular MAC address to an
    Endpoint Identity Group.
    """
    # Get the MAC Address from the user and convert it to upper-case for consistency.
    macAddr = input("Please provide the MAC Address of the endpoint to add: ")
    macAddrUpper = macAddr.upper()

    # Let's get the API to print all of the current endpoints.
    epApi = imc.endPoint().getAll

    # Let's issue the HTTP GET with the Endpoint API to get the endpoint data.
    EndpointOutput = bac.get(api=epApi)

    # The HTTP GET output is JSON - let's convert it into a python dictionary.
    jEndpointOutput = EndpointOutput.json()

    noEndpoint = 1

    # If CSRF is enabled, we'll need to include the CSRF token in the HTTP headers.
    if (imc.CSRF_ENABLED==True):
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-CSRF-Token': bac.get_CSRF_token(ip=imc.ISE_PAN_IP,uname=imc.USERNAME,pword=imc.PASSWORD,csrf=imc.CSRF_ENABLED)}
    else:
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}

    # Let's create an array of all of the relevant Endpoint data that we'll need.
    endpointIds = []
    for values in jEndpointOutput['SearchResult']['resources']:
        endpointURL = values['link']['href']
        endpointResp = requests.get(endpointURL, auth=(imc.USERNAME, imc.PASSWORD), headers=headers, params='', verify = False)
        jEndpointResp = endpointResp.json()

        # If a profile ID is given for a particular endpoint, let's resolve it
        # for some additional information in our output.
        if jEndpointResp['ERSEndPoint']['profileId'] != '':
            api = 'ers/config/profilerprofile/'+jEndpointResp['ERSEndPoint']['profileId']

            # This GET command will perform a get Profile by ID request.
            profileResp = bac.get(api=api)

            # Let's parse the JSON output from the HTTP Get into a python dictionary.
            jProfileResp = profileResp.json()

            # We only care about the Profile Name - let's parse the dictionary
            # for that information.
            endpointProf = jProfileResp['ProfilerProfile']['name']
        else:
            endpointProf = "Unknown"

        # We'll store the information that is important into an array for each endpoint.
        endpointIds.append((noEndpoint,jEndpointResp['ERSEndPoint']['name'],jEndpointResp['ERSEndPoint']['mac'], endpointProf, jEndpointResp['ERSEndPoint']['portalUser'], values['id']))
        noEndpoint += 1

    # So we can update the Endpoint by ID, we need to have the ID for each endpoint.
    updateId = "No Device ID"
    for updateEndpoint in endpointIds:
        if (updateEndpoint[2]== macAddr):
            updateId = updateEndpoint[5]

    # List Current Endpoint Identity Groups
    api = imc.endPointIdentityGroup().getAll

    # Let's get the list of the Current Endpoint Identity Groups via HTTP GET.
    epgOutput = bac.get(api=api)
    jEpgOutput = epgOutput.json()

    # We'll store the Endpoint Identity Groups so we can add the Endpoint by number.
    epgIds=[]
    noEpg = 1
    for values in jEpgOutput['SearchResult']['resources']:
        epgURL = values['link']['href']
        epgResp = requests.get(epgURL, auth=(imc.USERNAME, imc.PASSWORD), headers=headers, params='', verify = False)
        jEpgResp = epgResp.json()
        epgIds.append((noEpg,jEpgResp['EndPointGroup']['name'],jEpgResp['EndPointGroup']['description'], jEpgResp['EndPointGroup']['systemDefined'],jEpgResp['EndPointGroup']['id']))
        noEpg += 1

    # Have the user select the Endpoint Identity Group by number - and validate
    # the input.
    selectNdg = ""
    while (selectNdg == ""):

        # Print the current Endpoint Identity Groups to the screen.
        os.system("clear")
        print("Current Endpoint Identity Groups")
        print("")
        print('{:^5}'.format(str("Index")) + " | " + '{:<30}'.format(str("Name")) + " | " + '{:<60}'.format(str("Description")) + " | " + '{:<30}'.format(str("System Defined")))
        print("="*125 + "=========")
        index = 0
        for x in epgIds:
            print('{:^5}'.format(str(x[0])) + " | " + '{:<30}'.format(str(x[1])) + " | " + '{:<60}'.format(str(x[2])) + " | " + '{:<30}'.format(str(x[3])))
            index += 1

        # Get the input from the user and validate the input.
        try:
            # Let's ensure that the input is an integer - if not, we'll hit the 'except' and try again.
            selectNdg = int(input("Please select the Endpoint Identity Group ('0' to quit): "))

            # If the user selects '0', they want to quit - let's leave the function
            # without returning a value.
            if (selectNdg == 0):
                return
        except:
            print("Error - Please provide a value between 1-" + str(index+1) + " - Please try again!")
            input("Press <Enter> to continue...")
            continue
        # If the value is indeed an integer and NOT zero, we still need to make
        # sure that the selection is within the valid range.
        if not ((selectNdg>=0) and (selectNdg<index+1)):
            selectNdg = ""
            print("Error - Please provide a value between 1-" + str(index) + " - Please try again!")
            input("Press <Enter> to continue...")

        # If the user has indeed selected a NON-zero value, give them an opportunity
        # to confirm their selection.
        if (selectNdg !=0):
            confirmNdgAssign = input("Please type 'yes' to confirm that you would like to move the device to Endpoint Identity Group '" + epgIds[selectNdg-1][1] + "': ")
            if (confirmNdgAssign == "yes"):
                # The Endpoint Already exists in the database.
                if (updateId != "No Device ID"):

                    # The endpoint already exists in the database - we'll just update it.
                    # This is the data that we'll include in the BODY of the HTTP PUT.
                    data = '{"ERSEndPoint" : {"groupId" : "' + epgIds[selectNdg-1][4] + '","staticGroupAssignment" : true}}'

                    # Retrieve the API for updating an Endpoint by HTTP PUT.
                    ndgApi = imc.endPoint().putUpdate_ById(updateId)

                    # Put the data into the ISE database.
                    try:
                        assignNdgOutput = bac.put(api=ndgApi,data=data)
                        print("The Endpoint's Identity Group was updated to '" + epgIds[selectNdg-1][1] + "'!")
                    except:
                        print("There may have been an error in the assignment process - please confirm proper Endpoint Identity Group Assignment!")
                # The endpoint does NOT exist yet in the database.
                else:
                    # The endpoint does NOT already exist in the database - we'll create the endpoint in the database.
                    data = '{"ERSEndPoint" : {"mac" : "' + macAddr + '", "groupId" : "' + epgIds[selectNdg-1][4] + '","staticGroupAssignment" : true}}'

                    # Let's do an HTTP POST to add the Endpoint to the database.
                    ndgApi = imc.endPoint().postCreate
                    try:
                        assignNdgOutput = bac.post(api=ndgApi,data=data)
                        print("The Endpoint was created and added to '" + epgIds[selectNdg-1][1] + "'!")
                    except:
                        print("There may have been an error in the assignment process - please confirm proper Endpoint Identity Group Assignment!")
            # The user did NOT say "yes" to the change and we'll therefore abort.
            else:
                print("Operation aborted!")

    input("Press <Enter> to Continue...")
# End <addEndpointToList>

def importEndpointIntoGroup():
    """
    This function will allow a user to import Endpoints into a particular group -
    creating the Endpoint Identity Groups as needed.
    """

    # If CSRF is being used, include the CSRF token within the headers.
    if (imc.CSRF_ENABLED==True):
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-CSRF-Token': bac.get_CSRF_token(ip=imc.ISE_PAN_IP,uname=imc.USERNAME,pword=imc.PASSWORD,csrf=imc.CSRF_ENABLED)}
    else:
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}

    # We'll create a quick template file for the user to leverage for proper file
    # content format.
    os.system("clear")
    template = open("EndpointGroupTemplate.csv",'w')
    template.write("macAddr,endpointGroupName\n")
    template.write("DE:AD:BE:EF:CA:FE,Apple iDevice")
    template.close()
    print("File 'EndpointGroupTemplate.csv' was created - modify this file with the appropriate endpoints and endpoint Identity Groups and save as a new name.")
    print("Note: Capitalization does matter.")
    print("WARNING: If the Endpoint Identity Groups contain a space, the spaces will be converted to a '-'.")

    # This array will store any groups that we'll need to create.
    createdGroups=[]

    # Let's read the file and parse its contents.
    getInputFile = input("Please provide the filename of the file to import: ")
    try:
        with open(getInputFile) as inFile:
            content = inFile.read().splitlines()
    except:
        print("There must be a problem with the filename - please try again!")
        input("Press <Enter> to Continue...")
        return

    # Remove the header row if it was left behind within the template file.
    if (content[0] == "macAddr,endpointGroupName"):
        del content[0]

    # Read the Lines from the file and put the contents into a list.
    addedEndpoints = []
    addedEntry = []
    for line in content:
        macAddr = line.split(',')[0]
        groupName = line.split(',')[1]
        if (groupName == ''):
            groupName = "Unknown"
        # If the groupname contains any space, we'll delete the space.
        if " " in groupName:
            groupName = groupName.replace(' ','-')

        # We'll set macFound and groupFound = False - if we already have either in our database, we'll update the variable accordingly.
        macFound = False
        groupFound = False

        # The content of the addedEndpoints array will help us determine what
        # steps to take for each enpoint being imported.
        addedEntry = [macAddr,groupName,macFound,groupFound]
        addedEndpoints.append(addedEntry)

    # Let's load all endpoints and Endpoint Groups from ISE and see if they intersect with those from the new file.
    api = imc.endPoint().getAll
    EndpointOutput = bac.get(api=api)

    # Convert the JSON input from HTTP GET into a python dictionary.
    jEndpointOutput = EndpointOutput.json()

    noEndpoint = 1
    endpointIds = []
    endpointEntry = []
    endpointDict = {} #This will store the macAddr to id mapping
    for values in jEndpointOutput['SearchResult']['resources']:
        endpointURL = values['link']['href']
        endpointResp = requests.get(endpointURL, auth=(imc.USERNAME, imc.PASSWORD), headers=headers, params='', verify = False)
        jEndpointResp = endpointResp.json()
        endpointGroupId = jEndpointResp['ERSEndPoint']['groupId']

        # Let's resolve the groupId for a human readable Endpoint Identity Group name
        gApi = imc.endPointIdentityGroup().get_ById(endpointGroupId)

        # If the endpoint has a Group ID associated with it - save it.  If not,
        # go onto the next endpoint.
        try:
            groupOutput = bac.get(api=gApi)
        except:
            continue

        # Store the response from the HTTP GET into a python dictionary.
        jGroupOutput = groupOutput.json()

        # Parse the useful data and store it into an endpoint array.
        endpointGroupName = jGroupOutput['EndPointGroup']['name']
        endpointEntry = [noEndpoint,jEndpointResp['ERSEndPoint']['name'],jEndpointResp['ERSEndPoint']['mac'], endpointGroupName, values['id']]
        endpointIds.append(endpointEntry)

        # While we are at it, let's do a MAC address to ID mapping for quick lookup.
        endpointDict[jEndpointResp['ERSEndPoint']['mac']] = values['id']
        noEndpoint += 1

    # Now that all of the groups are created, we'll add the new Endpoints to the database:
    # Before we can assign the Endpoints to the groups, we need to have the Group IDs for each Endpoint Identity Group.
    # Let's pull all groups from ISE and load them into a variable:
    api = imc.endPointIdentityGroup().getAll

    # We'll store the JSON output from the GET into a python dictionary.
    epgOutput = bac.get(api=api)
    jEpgOutput = epgOutput.json()

    # Let's create an Endpoint Group array
    epgIds=[]
    noEpg = 1
    for values in jEpgOutput['SearchResult']['resources']:
        epgURL = values['link']['href']
        epgResp = requests.get(epgURL, auth=(imc.USERNAME, imc.PASSWORD), headers=headers, params='', verify = False)
        jEpgResp = epgResp.json()

        # We'll store the important information about the Endpoint Groups.
        epgIds.append((noEpg,jEpgResp['EndPointGroup']['name'],jEpgResp['EndPointGroup']['description'], jEpgResp['EndPointGroup']['systemDefined'],jEpgResp['EndPointGroup']['id']))
        noEpg += 1

    # If the MAC Address is already an endpoint in the ISE database, we'll want
    # to know that.
    for x in addedEndpoints:
        for y in endpointIds:
            # This if statement checks to see if the macAddr is already an Endpoint
            # in the ISE database
            if (x[0] == y[2]):
                x[2] = True

    # Does the destination Endpoint Identity Group already exist - if not, we'll
    # add it.
    for x in addedEndpoints:
        for y in epgIds:
            # This if statement checks to see if the Endpoint Identity Group is
            # already present on ISE.
            if (x[1] == y[1]):
                x[3] = True

    #At this point, all of the endpoints macAddr and Endpoint Identity Groups have been validated as being new or already present.  Let's add only those that don't yet exist.
    groupsToAdd = set()

    for x in addedEndpoints:
        # Let's get a list of the Endpoint Identity Groups that we have to create first.
        # The use of a set here will ensure that we'll get a list of unique values with no duplicates.
        if (x[3]==False):
            groupsToAdd.update([x[1]])

    # Let's create the Endpoint Identity Groups that don't yet exist - those that are in the groupsToAdd set.
    newApi = imc.endPointIdentityGroup().postCreate
    for newGroup in groupsToAdd:
        data = '{"EndPointGroup" : {"name" : "' + newGroup + '"}}'
        try:
            negOutput = bac.post(api=newApi,data=data)
            print("Endpoint Identity Group '" + newGroup + "' was created!")
        except:
            print("There must be a problem with the creation - please try again!")


    # We'll store the endpoint groups that we care about into a group - we'll need to get their IDs.
    lookup = {}
    for addedGroup in addedEndpoints:
        for currentGroup in epgIds:
            if (addedGroup[1] == currentGroup[1]):
                lookup[addedGroup[1]] = currentGroup[4]


    for endpoint in addedEndpoints:
        # This endpoint does not yet exist in the ISE database.
        if (endpoint[2] == False):

            # This data will be provided as the body of the HTTP POST.
            data = '{"ERSEndPoint" : {"mac" : "' + endpoint[0] + '", "groupId" : "' + lookup[endpoint[1]] + '","staticGroupAssignment" : true}}'

            # Send this data to ISE.
            ndgApi = imc.endPoint().postCreate
            try:
                assignNdgOutput = bac.post(api=ndgApi,data=data)
                print("The Endpoint '" + endpoint[0] + "' was created and added to '" + endpoint[1] + "'!")
            except:
                print("There may have been an error in the assignment process - please confirm proper Endpoint Identity Group Assignment!")

    #The final step is to update any endpoints that are already in the database with their new group assignments.
    for endpoint in addedEndpoints:
        print("endpoint[0,1,2,3] = " + endpoint[0] + "," + endpoint[1] + "," + str(endpoint[2]) + "," + str(endpoint[3]))
        if (endpoint[2]==True):
            # If the Endpoint Identity Group is Unknown, we'll have to manually populate this as it is NOT retrievable via API.
            if (endpoint[1] == "Unknown"):
                data = '{"ERSEndPoint" : {"mac" : "' + endpoint[0] + '", "groupId" : "aa0e8b20-8bff-11e6-996c-525400b48521","staticGroupAssignment" : true}}'
            # If the Endpoint Identity Group IS known, we'll assign it here.
            else:
                data = '{"ERSEndPoint" : {"mac" : "' + endpoint[0] + '", "groupId" : "' + lookup[endpoint[1]] + '","staticGroupAssignment" : true}}'

            # We'll now do an HTTP PUT to update the endpoing by ID.
            updApi = imc.endPoint().putUpdate_ById(endpointDict[endpoint[0]])
            try:
                assignUpdOutput = bac.put(api=updApi,data=data)
                print("The Endpoint '" + endpoint[0] + "' was updated and added to '" + endpoint[1] + "'!")
            except:
                print("There may have been an error in the update process - please confirm proper Endpoint Identity Group update for the endpoint!")

    input("Press <Enter> to Continue...")
#End <importEndpointIntoGroup>

def deleteEndpoint():
    # Let's retrieve the API to get all current Endpoints.
    api = imc.endPoint().getAll

    # If CSRF is enabled, we'll need to include the CSRF Token in the header.
    if (imc.CSRF_ENABLED==True):
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-CSRF-Token': bac.get_CSRF_token(ip=imc.ISE_PAN_IP,uname=imc.USERNAME,pword=imc.PASSWORD,csrf=imc.CSRF_ENABLED)}
    else:
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}

    # Let's do the HTTP GET for all current endpoints.
    EndpointOutput = bac.get(api=api)

    # We'll parse the JSON and store the contents into a python dictionary.
    jEndpointOutput = EndpointOutput.json()

    # We'll store all of the Endpoints into an array with all of the relevant
    # useful data for easy lookup.
    noEndpoint = 1
    endpointIds = []
    for values in jEndpointOutput['SearchResult']['resources']:
        endpointURL = values['link']['href']
        endpointResp = requests.get(endpointURL, auth=(imc.USERNAME, imc.PASSWORD), headers=headers, params='', verify = False)
        jEndpointResp = endpointResp.json()
        endpointGroupId = jEndpointResp['ERSEndPoint']['groupId']

        # Let's resolve the groupId for a human readable Endpoint Identity Group name
        gApi = imc.endPointIdentityGroup().get_ById(endpointGroupId)
        groupOutput = bac.get(api=gApi)
        jGroupOutput = groupOutput.json()
        endpointGroupName = jGroupOutput['EndPointGroup']['name']

        # If the endpoint currently has a Profile assigned to it, we'll do a lookup for that.
        if jEndpointResp['ERSEndPoint']['profileId'] != '':
            api = 'ers/config/profilerprofile/'+jEndpointResp['ERSEndPoint']['profileId']
            profileResp = bac.get(api=api)
            jProfileResp = profileResp.json()
            endpointProf = jProfileResp['ProfilerProfile']['name']
        else:
            endpointProf = "Unknown"

        # Let's store the Endpoint data into an easy-to-use array for reference.
        endpointIds.append((noEndpoint,jEndpointResp['ERSEndPoint']['name'],jEndpointResp['ERSEndPoint']['mac'], endpointProf, endpointGroupName, jEndpointResp['ERSEndPoint']['portalUser'], values['id']))
        noEndpoint += 1
    validEndpoints = len(endpointIds)

    # We'll print out the current Endpoints and allow the user to delete by number.
    selectEndpoint = ""
    while (selectEndpoint == ""):

        # Print out the Endpoints into a pretty table.
        os.system("clear")
        print('{:^5}'.format(str("Index")) + " | " + '{:<30}'.format(str("Name")) + " | " + '{:<18}'.format(str("MAC Address")) + " | " + '{:<30}'.format(str("Endpoint Profile")) + " | " + '{:<40}'.format(str("Endpoint Identity Group")) + " | " + '{:<30}'.format(str("Portal User")))
        print("="*153 + "==================")
        index = 0
        for x in endpointIds:
            print('{:^5}'.format(str(x[0])) + " | " + '{:<30}'.format(str(x[1])) + " | " + '{:<18}'.format(str(x[2])) + " | " + '{:<30}'.format(str(x[3])) + " | " + '{:<40}'.format(str(x[4])) + " | " + '{:<30}'.format(str(x[5])))
            index += 1

        # Let's prompt the user for an integer and if they don't provide a valid
        # value, we'll ask them again.
        try:
            # Let's ensure that the input is an integer - if not, we'll hit the 'except' and try again.
            selectEndpoint = int(input("Please provide the number of the Endpoint to delete ('0' to quit): "))
            if (selectEndpoint == 0):
                return
        except:
            print("Error - Please provide a value between 1-" + str(validEndpoints) + " - Please try again!")
            input("Press <Enter> to continue...")
            continue

        # Let's ensure that the entry is valid given the number of Endpoints.
        if not ((selectEndpoint>=0) and (selectEndpoint<validEndpoints+1)):
            selectEndpoint = ""
            print("Error - Please provide a value between 1-" + str(validEndpoints) + " - Please try again!")
            input("Press <Enter> to continue...")
    if (selectEndpoint !=0):
        confirmProfDel = input("Please type 'yes' to confirm that you would like to delete the Endpoint '" + endpointIds[selectEndpoint-1][2] + "': ")

        # Let's give the user an opportunity to confirm their selection.
        if (confirmProfDel == "yes"):
            #The second index of the profIds list is the ID of the Authorization Profile
            delApi = imc.endPoint().delete_ById(endpointIds[selectEndpoint-1][6])
            try:
                dapOutput = bac.delete(api=delApi)
                print("The Endpoint '" + endpointIds[selectEndpoint-1][2] + "' has been deleted!")
            except:
                print("There may have been an error in the deletion process - please confirm deletion!")

        # If they don't type "yes", then we'll abort the deletion of the endpoint.
        else:
            print("Operation aborted!")
    input("Press <Enter> to continue...")
# End <deleteEndpoint>

def deleteEndpointIdGroup():
    api = imc.endPointIdentityGroup().getAll
    if (imc.CSRF_ENABLED==True):
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-CSRF-Token': bac.get_CSRF_token(ip=imc.ISE_PAN_IP,uname=imc.USERNAME,pword=imc.PASSWORD,csrf=imc.CSRF_ENABLED)}
    else:
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
    epgOutput = bac.get(api=api)
    jEpgOutput = epgOutput.json()
    epgIds=[]
    noEpg = 1
    for values in jEpgOutput['SearchResult']['resources']:
        epgURL = values['link']['href']
        epgResp = requests.get(epgURL, auth=(imc.USERNAME, imc.PASSWORD), headers=headers, params='', verify = False)
        jEpgResp = epgResp.json()
        #print(jEpgResp)
        epgIds.append((noEpg,jEpgResp['EndPointGroup']['name'],jEpgResp['EndPointGroup']['description'], jEpgResp['EndPointGroup']['systemDefined'],jEpgResp['EndPointGroup']['id']))
        noEpg += 1
    validEpg = len(epgIds)
    selectEpg = ""
    while (selectEpg == ""):
        os.system("clear")
        print('{:^5}'.format(str("Index")) + " | " + '{:<30}'.format(str("Name")) + " | " + '{:<60}'.format(str("Description")) + " | " + '{:<30}'.format(str("System Defined")))
        print("="*125 + "=========")
        index = 0
        for x in epgIds:
            print('{:^5}'.format(str(x[0])) + " | " + '{:<30}'.format(str(x[1])) + " | " + '{:<60}'.format(str(x[2])) + " | " + '{:<30}'.format(str(x[3])))
            index += 1
        try:
        #Let's ensure that the input is an integer - if not, we'll hit the 'except' and try again.
            selectEpg = int(input("Please provide the number of the Endpoint Identity Group to delete ('0' to quit): "))
            if (selectEpg == 0):
                continue
        except:
            print("Error - Please provide a value between 1-" + str(validEpg) + " or '0' to quit - Please try again!")
            input("Press <Enter> to continue...")
            continue
    #Let's ensure that the entry is valid given the number of Authz profiles.
        if not ((selectEpg>=0) and (selectEpg<validEpg+1)):
            selectEpg = ""
            print("Error - Please provide a value between 1-" + str(validEpg) + " - Please try again!")
            input("Press <Enter> to continue...")
    if (selectEpg !=0):
        confirmProfDel = input("Please type 'yes' to confirm that you would like to delete the Endpoint '" + epgIds[selectEpg-1][1] + "': ")
        if (confirmProfDel == "yes"):
            #The second index of the profIds list is the ID of the Authorization Profile
            delApi = imc.endPointIdentityGroup().delete_ById(epgIds[selectEpg-1][4])
            try:
                dapOutput = bac.delete(api=delApi)
                print("The Endpoint '" + epgIds[selectEpg-1][1] + "' has been deleted!")
            except:
                print("There may have been an error in the deletion process - please confirm deletion!")
        else:
            print("Operation aborted!")
    input("Press <Enter> to continue...")
# End <deleteEndpointIdGroup>

def printAuthzProfMenu():
    global aChoice
    os.system("clear")
    print("Authorization Profile Menu")
    print("==========================")
    print("1. List Authorization Profiles")
    print("2. Add RADIUS Authorization Profiles")
    print("3. Delete Authorization Profiles")
    print("4. Export Authorization Profiles to File")
    aChoice = input("Please choose the task from the above list (q to go to previous menu): ")

def listAuthzOptions():
    global laoChoice
    os.system("clear")
    print("List Authorization Profiles by Category")
    print("=======================================")
    print("1. RADIUS")
    print("2. TrustSec")
    print("3. TACACS")
    print("4. List All")
    laoChoice = input("Please choose the task from the above list (q to go to previous menu): ")

def listAuthzProfilesRadius():
    api = imc.authorizationProfile().getAll
    if (imc.CSRF_ENABLED==True):
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-CSRF-Token': bac.get_CSRF_token(ip=imc.ISE_PAN_IP,uname=imc.USERNAME,pword=imc.PASSWORD,csrf=imc.CSRF_ENABLED)}
    else:
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
    lapOutput = bac.get(api=api)
    jLapOutput = lapOutput.json()
    noEndpoint = 1
    for values in jLapOutput['SearchResult']['resources']:
        lapAuthzURL = values['link']['href']
        lapAuthzResp = requests.get(lapAuthzURL, auth=(imc.USERNAME, imc.PASSWORD), headers=headers, params='', verify = False)
        jLapAuthzResp = lapAuthzResp.json()
        if (jLapAuthzResp['AuthorizationProfile']['authzProfileType'] == "SWITCH"):
            os.system("clear")
            print("Authz Profile #" + str(noEndpoint))
            print("===============")
            print("Name: " + values['name'])
            print("Authorization Profile Type: RADIUS")
            print("Description: " + jLapAuthzResp['AuthorizationProfile']['description'])
            print("Access Type: " + jLapAuthzResp['AuthorizationProfile']['accessType'])
            if 'vlan' in jLapAuthzResp['AuthorizationProfile']:
                print("VLAN:")
                if 'nameID' in jLapAuthzResp['AuthorizationProfile']['vlan']:
                    print("\tName: " + jLapAuthzResp['AuthorizationProfile']['vlan']['nameID'])
                    print("\tNumber: " + str(jLapAuthzResp['AuthorizationProfile']['vlan']['tagID']))
                else:
                    print("VLAN: N/A")
            if 'reauth' in jLapAuthzResp['AuthorizationProfile']:
                print("Reauth:")
                print("\tReauth Timer: " + jLapAuthzResp['AuthorizationProfile']['reauth']['timer'] + "seconds")
                print("\tReauth Connectivity: " + jLapAuthzResp['AuthorizationProfile']['reauth']['connectivity'])
            else:
                print("Reauth Timer: N/A")
            if 'airespaceACL' in jLapAuthzResp['AuthorizationProfile']:
                print("Airespace ACL: " + jLapAuthzResp['AuthorizationProfile']['airespaceACL'])
            else:
                print("Airespace ACL: N/A")
            webOneFieldWorks = False
            if 'webRedirection' in jLapAuthzResp['AuthorizationProfile']:
                print("Web Redirection:")
                webString = ''
                if 'WebRedirectionType' in jLapAuthzResp['AuthorizationProfile']:
                    print("\tWeb Redirection Type: " + jLapAuthzResp['AuthorizationProfile']['webRedirection']['WebRedirectionType'])
                else:
                    print("\tWeb Redirection Type: N/A")
                if 'acl' in jLapAuthzResp['AuthorizationProfile']:
                    print("\tWeb Redirection ACL: " + jLapAuthzResp['AuthorizationProfile']['webRedirection']['acl'])
                else:
                    print("\tWeb Redirection ACL: N/A")
                if 'portalName' in jLapAuthzResp['AuthorizationProfile']:
                    print("\tWeb Portal Name: " + jLapAuthzResp['AuthorizationProfile']['webRedirection']['portalName'])
                else:
                    print("\tWeb Portal Name: N/A")
                if 'staticIPHostNameFQDN' in jLapAuthzResp['AuthorizationProfile']:
                    print("\tWeb Static Host Name: " + jLapAuthzResp['AuthorizationProfile']['webRedirection']['staticIPHostNameFQDN'])
                else:
                    print("\tWeb Static Host Name: N/A")
                if 'displayCertificatesRenewalMessages'in jLapAuthzResp['AuthorizationProfile']['webRedirection']:
                    print("\tDisplay Certificate Renewal Messages: " + str(jLapAuthzResp['AuthorizationProfile']['webRedirection']['displayCertificatesRenewalMessages']))
                else:
                    print("\tDisplay Certificate Renewal Messages: N/A")
            if 'daclName' in jLapAuthzResp['AuthorizationProfile']:
                print("Downloadable ACL: " + jLapAuthzResp['AuthorizationProfile']['daclName'])
            else:
                print("Downloadable ACL: N/A")
            if 'autoSmartPort' in jLapAuthzResp['AuthorizationProfile']:
                print("Auto SmartPort Profile: " + jLapAuthzResp['AuthorizationProfile']['autoSmartPort'])
            else:
                print("Auto SmartPort Profile: N/A")
            if 'avcProfile' in jLapAuthzResp['AuthorizationProfile']:
                print("AVC Profile: " + jLapAuthzResp['AuthorizationProfile']['avcProfile'])
            else:
                print("AVC Profile: N/A")
            # Populate the other key fields from RADIUS later...
            """
            {'AuthorizationProfile': {'trackMovement': True, 'serviceTemplate': False, 'easywiredSessionCandidate': True, 'voiceDomainPermission': True, 'neat': True, 'webAuth': True, , 'interfaceTemplate': 'Instance_Template', 'avcProfile': 'W00t', 'macSecPolicy': 'SHOULD_SECURE', 'asaVpn': 'Cisco-VPN3000:CVPN3000/ASA/PIX7x-Allow-Network-Extension-Mode', 'link': {'rel': 'self', 'href': 'https://x`x`192.168.200.10:9060/ers/config/authorizationprofile/f96cec50-3d85-11e8-b02e-000c2900668e', 'type': 'application/xml'}}}
            """
            noEndpoint+=1
            #print out the entire array - this can be useful for troubleshooting API calling_station_id
            #print(jLapAuthzResp)
            nextInput = input("Press <Enter> for next Record, 'q' to quit...")
            if (nextInput=="q"):
                return

    if (nextInput!="q"):
        input("Press <Enter> to Continue...")

def listAuthzProfilesTrustSec():
    api = imc.authorizationProfile().getAll
    if (imc.CSRF_ENABLED==True):
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-CSRF-Token': bac.get_CSRF_token(ip=imc.ISE_PAN_IP,uname=imc.USERNAME,pword=imc.PASSWORD,csrf=imc.CSRF_ENABLED)}
    else:
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
    lapOutput = bac.get(api=api)
    jLapOutput = lapOutput.json()
    noEndpoint = 1
    for values in jLapOutput['SearchResult']['resources']:
        lapAuthzURL = values['link']['href']
        lapAuthzResp = requests.get(lapAuthzURL, auth=(imc.USERNAME, imc.PASSWORD), headers=headers, params='', verify = False)
        jLapAuthzResp = lapAuthzResp.json()
        if (jLapAuthzResp['AuthorizationProfile']['authzProfileType'] == "TRUSTSEC"):
            os.system("clear")
            print("Authz Profile #" + str(noEndpoint))
            print("===============")
            print("Name: " + values['name'])
            print("Authorization Profile Type: TrustSec")
            print("Description: " + jLapAuthzResp['AuthorizationProfile']['description'])
            print("Access Type: " + jLapAuthzResp['AuthorizationProfile']['accessType'])
            noEndpoint+=1
            nextInput = input("Press <Enter> for next Record, 'q' to quit...")
            if (nextInput=="q"):
                return

    if (nextInput!="q"):
        input("Press <Enter> to Continue...")

def listAuthzProfilesTacacs():
    api = imc.authorizationProfile().getAll
    if (imc.CSRF_ENABLED==True):
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-CSRF-Token': bac.get_CSRF_token(ip=imc.ISE_PAN_IP,uname=imc.USERNAME,pword=imc.PASSWORD,csrf=imc.CSRF_ENABLED)}
    else:
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
    lapOutput = bac.get(api=api)
    jLapOutput = lapOutput.json()
    noEndpoint = 1
    for values in jLapOutput['SearchResult']['resources']:
        lapAuthzURL = values['link']['href']
        lapAuthzResp = requests.get(lapAuthzURL, auth=(imc.USERNAME, imc.PASSWORD), headers=headers, params='', verify = False)
        jLapAuthzResp = lapAuthzResp.json()
        if (jLapAuthzResp['AuthorizationProfile']['authzProfileType'] == "TACACS"):
            os.system("clear")
            print("Authz Profile #" + str(noEndpoint))
            print("===============")
            print("Name: " + values['name'])
            print("Authorization Profile Type: TACACS")
            print("Description: " + jLapAuthzResp['AuthorizationProfile']['description'])
            print("Access Type: " + jLapAuthzResp['AuthorizationProfile']['accessType'])
            noEndpoint+=1
            nextInput = input("Press <Enter> for next Record, 'q' to quit...")
            if (nextInput=="q"):
                return

    if (nextInput!="q"):
        input("Press <Enter> to Continue...")

def listAuthzProfilesAll():
    api = imc.authorizationProfile().getAll
    if (imc.CSRF_ENABLED==True):
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-CSRF-Token': bac.get_CSRF_token(ip=imc.ISE_PAN_IP,uname=imc.USERNAME,pword=imc.PASSWORD,csrf=imc.CSRF_ENABLED)}
    else:
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
    lapOutput = bac.get(api=api)
    jLapOutput = lapOutput.json()
    noEndpoint = 1
    for values in jLapOutput['SearchResult']['resources']:
        lapAuthzURL = values['link']['href']
        lapAuthzResp = requests.get(lapAuthzURL, auth=(imc.USERNAME, imc.PASSWORD), headers=headers, params='', verify = False)
        jLapAuthzResp = lapAuthzResp.json()
        os.system("clear")

        print("Authz Profile #" + str(noEndpoint))
        print("===============")
        print("Name: " + values['name'])
        if (jLapAuthzResp['AuthorizationProfile']['authzProfileType'] == "SWITCH"):
            print("Authorization Profile Type: RADIUS")
        elif (jLapAuthzResp['AuthorizationProfile']['authzProfileType'] == "TRUSTSEC"):
            print("Authorization Profile Type: TrustSec")
        elif (jLapAuthzResp['AuthorizationProfile']['authzProfileType'] == "TACACS"):
            print("Authorization Profile Type: TACACS")
        print("Description: " + jLapAuthzResp['AuthorizationProfile']['description'])
        print("Access Type: " + jLapAuthzResp['AuthorizationProfile']['accessType'])
        noEndpoint+=1
        nextInput = input("Press <Enter> for next Record, 'q' to quit...")
        if (nextInput=="q"):
            return

    if (nextInput!="q"):
        input("Press <Enter> to Continue...")

def addAuthzProfiles():
    api = imc.authorizationProfile().postCreate
    aapName = input("Please provide a name for the new Authorization Profile: ")
    aapDesc = input("Please provide a brief description for the new Authorization Profile: ")
    aapAccessType = "0"
    while (aapAccessType not in "123"):
        aapAccessType = input("Please enter 1 for ACCESS_ACCEPT or 2 for ACCESS_REJECT: ")
        if (aapAccessType == "1"):
            aapAccessText = "ACCESS_ACCEPT"
        elif (aapAccessType == "2"):
            aapAccessText = "ACCESS_REJECT"
        else:
            continue
    aapAuthzProfType = "0"
    while (aapAuthzProfType not in "12"):
        #For now, we'll only support adding the RADIUS Authz Profiles.
        aapAuthzProfType = "1"
        if (aapAuthzProfType == "1"):
            aapAuthzProfText = "SWITCH"
            aapVlanName = input("Please provide the name of the VLAN to assign to this Authorization profile or <ENTER> if no VLAN needed: ")
            if (aapVlanName !=""):
                aapVlanId = ""
                while (aapVlanId == ""):
                    try:
                        #Let's ensure that the input is an integer - if not, we'll hit the 'except' and try again.
                        aapVlanId = int(input("Please provide the number of the VLAN (1-4095) to assign to this Authorization profile or <ENTER> if no VLAN needed: "))
                    except:
                        print("Error - Please provide a value between 1-4095! Please try again!")
                        continue
                    if not ((aapVlanId>0) and (aapVlanId<4096)):
                        #The VLAN Value is NOT between 1-4095
                        aapVlanId=""
                        input("Press <Enter> to continue...")
            aapAirespaceACL = input("Please provide the Airespace/Named ACL to assign to this Authorization profile or <ENTER> if no Airespace ACL needed: ")
            aapDlACL = input("Please provide the Downloadable ACL to assign to this Authorization profile or <ENTER> if no ACL needed: ")
            data = '{"AuthorizationProfile" : {"name" : "' + aapName + '","description" : "' + aapDesc + '","accessType" : "' + aapAccessText + '","authzProfileType" : "' + aapAuthzProfText + '","vlan" : {"nameID" : "' + aapVlanName + '","tagID" : ' + str(aapVlanId) + '},"airespaceACL" : "' + aapAirespaceACL+ '","acl" : "' + aapDlACL + '"}}'

    print(data)
    try:
        aapOutput = bac.post(api=api,data=data)
    except:
        print("There was an error in creating your Authz Profile - " + aapOutput.status_code)
    #Currently Getting a 404
    input("Press <Enter> to Continue...")

def deleteAuthzProfiles():
    #Let's list all Profiles and allow the user to delete them by number - not Name
    profIds=[]
    api = imc.authorizationProfile().getAll
    if (imc.CSRF_ENABLED==True):
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-CSRF-Token': bac.get_CSRF_token(ip=imc.ISE_PAN_IP,uname=imc.USERNAME,pword=imc.PASSWORD,csrf=imc.CSRF_ENABLED)}
    else:
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
    lapOutput = bac.get(api=api)
    jLapOutput = lapOutput.json()
    for values in jLapOutput['SearchResult']['resources']:
        lapAuthzURL = values['link']['href']
        lapAuthzResp = requests.get(lapAuthzURL, auth=(imc.USERNAME, imc.PASSWORD), headers=headers, params='', verify = False)
        jLapAuthzResp = lapAuthzResp.json()
        aapAuthzProfType = jLapAuthzResp['AuthorizationProfile']['authzProfileType']
        if (aapAuthzProfType == "SWITCH"):
            authzProfText = "RADIUS"
        elif (aapAuthzProfType == "TRUSTSEC"):
            authzProfText = "TRUSTSEC"
        elif (aapAuthzProfType == "TACACS"):
            authzProfText = "TACACS"
        profIds.append((values['name'],authzProfText,values['id']))
    validEntries = len(profIds)
    selectProf = ""
    while (selectProf == ""):
        os.system("clear")
        print('{:^5}'.format(str("Index")) + " | " + '{:<30}'.format(str("Name")) + " | " + '{:<30}'.format(str("Profile Type")))
        print("="*65 + "======")
        index = 0
        for x in profIds:
            print('{:^5}'.format(str(index+1)) + " | " + '{:<30}'.format(str(x[0])) + " | " + '{:<30}'.format(str(x[1])))
            index += 1
        try:
            #Let's ensure that the input is an integer - if not, we'll hit the 'except' and try again.
            selectProf = int(input("Please provide the number of the Authorization Profile to delete ('0' to quit): "))
            if (selectProf == 0):
                continue
        except:
            print("Error - Please provide a value between 1-" + str(validEntries) + " - Please try again!")
            input("Press <Enter> to continue...")
            continue
        #Let's ensure that the entry is valid given the number of Authz profiles.
        if not ((selectProf>=0) and (selectProf<validEntries+1)):
            selectProf = ""
            print("Error - Please provide a value between 1-" + str(validEntries) + " - Please try again!")
            input("Press <Enter> to continue...")
    #selectProf is the number of the item on the list - but the index of the entry in profIds is selectProf - 1
    #print(profIds[selectProf-1])
    if (selectProf !=0):
        confirmProfDel = input("Please type 'yes' to confirm that you would like to delete Authorization Profile '" + profIds[selectProf-1][0] + "': ")
        if (confirmProfDel == "yes"):
            #The second index of the profIds list is the ID of the Authorization Profile
            delApi = imc.authorizationProfile().delete_ById(profIds[selectProf-1][2])
            try:
                dapOutput = bac.delete(api=delApi)
                print("The Authorization Profile '" + profIds[selectProf-1][0] + "' has been deleted!")
            except:
                print("There may have been an error in the deletion process - please confirm deletion!")
        else:
            print("Operation aborted!")
            input("Press <Enter> to continue...")

def exportAuthzProfiles():
    api = imc.authorizationProfile().getAll
    if (imc.CSRF_ENABLED==True):
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-CSRF-Token': bac.get_CSRF_token(ip=imc.ISE_PAN_IP,uname=imc.USERNAME,pword=imc.PASSWORD,csrf=imc.CSRF_ENABLED)}
    else:
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
    lapOutput = bac.get(api=api)
    jLapOutput = lapOutput.json()
    noEndpoint = 1
    fileName = input("Please provide a filename: ")
    print("WARNING: If the filename '" + fileName + "' exists, it will be deleted!")
    confirmOverwrite = input("Type 'yes' to confirm: ")
    if (confirmOverwrite == "yes"):
        newFile = open(fileName, 'w')
        for values in jLapOutput['SearchResult']['resources']:
            lapAuthzURL = values['link']['href']
            lapAuthzResp = requests.get(lapAuthzURL, auth=(imc.USERNAME, imc.PASSWORD), headers=headers, params='', verify = False)
            newFile.write(str(lapAuthzResp.content))
            newFile.write("\n")
        newFile.close()
        print("The Authorization Profiles were written to the file '" + fileName + "'.")
    else:
        print("The profiles were NOT exported and the filename '" + fileName + "' was NOT modified or overwritten.")
    input("Press <Enter> to continue...")

def radiusProbe():
    ISENode = {1:"192.168.200.10", 2:"192.168.200.11"} #The IP addresses of the RADIUS Servers
    nasIP = "192.168.255.254" #Define the IP address that the Probe will use
    nasSS = "PythonRadiusProbe" #Define the Shared Secret that the Probe will use
    userName = "PythonRadiusUser" #Define a local username that can authenticate
    userPass = "PythonRadiusPass" #Define the local user's password

    histDate = datetime.datetime.fromtimestamp(time.time()).strftime('%x %X')
    histFile = open("History.txt","a")
    pingHealth = {}
    radiusHealth = {}
    for nodeId in ISENode:
        #Start: Ping Health
        currentSvr = ISENode[nodeId]
        pStartTime = time.time()
        pingResponse = os.system("ping -c 1 -W 2 " + currentSvr)
        pStopTime = time.time()
        pingTime = round(((pStopTime - pStartTime)*100),3)

        #and then check the response...
        if pingResponse == 0:
            pingHealth[nodeId] = ["UP",pingTime]
        else:
            pingHealth[nodeId] = ["DOWN","N/A"]
        #End: Ping Health

        #Start: RADIUS Health
        srv = Client(server=bytes(currentSvr,'utf-8'),secret=bytes(nasSS,'utf-8'),dict=Dictionary("dictionary"))
        req = srv.CreateAuthPacket(code=pyrad.packet.AccessRequest, User_Name=userName, NAS_Identifier = nasIP)
        req["User-Password"] = req.PwCrypt(userPass)
        req["NAS-IP-Address"] = nasIP #Not sure if this is needed
        req["NAS-Port"] = 0
        req["Service-Type"] = "Login-User"
        req["NAS-Identifier"] = "RADIUSPROBE"
        req["Called-Station-Id"] = "00-04-5F-00-0F-D1"
        req["Calling-Station-Id"] = "00-01-24-80-B3-9C"
        req["Framed-IP-Address"] = "10.0.0.1"
        try:
            '''
            #This is the debug to see what RADIUS request will be sent
            print("Sending authentication request")
            print("The request that will be sent is:")
            print(req)
            print("")
            '''
            rStartTime = time.time()
            reply = srv.SendPacket(req)
            rStopTime = time.time()
            rTime = round((rStopTime - rStartTime)*1000,3)
        except:
            radiusHealth[nodeId] = ["DOWN","N/A"]
            continue

        if reply.code == pyrad.packet.AccessAccept:
            print("Access accepted")
            print(currentSvr + " RADIUS is up!")
            radiusHealth[nodeId] = ["UP",rTime]
        else:
            print("Access denied")
            print("PLEASE CONFIRM POLICY FOR RADIUS PROBE ON ISE!")
            radiusHealth[nodeId] = ["UNKNOWN","N/A"]

        print("Attributes returned by server:")
        for i in reply.keys():
            print("%s: %s" % (i, reply[i]))
        #End: RADIUS Health

    print(pingHealth)
    print(radiusHealth)
    for node in ISENode:
        histEntry = '{:>18}'.format(str(histDate)) + " |" + '{:>3}'.format(str(node)) + "|" + '{:>8}'.format(str(pingHealth[node][0])) + "|" + '{:>6}'.format(str(pingHealth[node][1])) + "|" + '{:>8}'.format(str(radiusHealth[node][0])) + "|" + '{:>6}'.format(str(radiusHealth[node][1])) + "|" + "\n"
        histFile.writelines(histEntry)
    histFile.close()
    input("Press <Enter> to Continue...")

def printPortalMenu():
    global pChoice
    os.system("clear")
    print("Portal Menu")
    print("===========")
    print("1. Print Portal Information")
    print("2. Print Current Guest Users")
    print("3. Create Single Guest Account (WebEx Team Message to End User)")
    print("4. Create Random Guest Accounts (WebEx Team Message to Sponsor)")
    pChoice = input("Please choose the task from the above list (q to go to previous menu): ")

def printPortalInfo():
    portalIds=[]
    api = imc.portal().getAll
    if (imc.CSRF_ENABLED==True):
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-CSRF-Token': bac.get_CSRF_token(ip=imc.ISE_PAN_IP,uname=imc.USERNAME,pword=imc.PASSWORD,csrf=imc.CSRF_ENABLED)}
    else:
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
    ppOutput = bac.get(api=api)
    jPpOutput = ppOutput.json()
    for values in jPpOutput['SearchResult']['resources']:
        ppURL = values['link']['href']
        ppResp = requests.get(ppURL, auth=(imc.USERNAME, imc.PASSWORD), headers=headers, params='', verify = False)
        jPpResp = ppResp.json()
        portalIds.append((values['name'],jPpResp['ERSPortal']['description'],jPpResp['ERSPortal']['portalType'],values['id']))
    validEntries = len(portalIds)
    os.system("clear")
    print('{:^5}'.format(str("Index")) + " | " + '{:<45}'.format(str("Name")) + " | " + '{:<75}'.format(str("Description")) + " | " + '{:<15}'.format(str("Portal Type")))
    print("="*140 + "=========")
    index = 0
    for x in portalIds:
        print('{:^5}'.format(str(index+1)) + " | " + '{:<45}'.format(str(x[0])[0:43],width=43) + " | " + '{:<75}'.format(str(x[1])[0:75],width=75) + " | " + '{:<15}'.format(str(x[2])))
        index += 1
    input("Press <Enter> to continue...")

def printGuestUsers():
    guestIds=[]
    api = imc.guestUser().getAll
    if (imc.CSRF_ENABLED==True):
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-CSRF-Token': bac.get_CSRF_token(ip=imc.ISE_PAN_IP,uname=imc.USERNAME,pword=imc.PASSWORD,csrf=imc.CSRF_ENABLED)}
    else:
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
    guOutput = bac.get(uname=imc.GUESTUSER, pword=imc.GUESTPASS,api=api)
    jGuOutput = guOutput.json()
    for values in jGuOutput['SearchResult']['resources']:
        guURL = values['link']['href']
        guResp = requests.get(guURL, auth=(imc.GUESTUSER, imc.GUESTPASS), headers=headers, params='', verify = False)
        jGuResp = guResp.json()
        userName = jGuResp['GuestUser']['guestInfo']['userName']
        userPass = jGuResp['GuestUser']['guestInfo']['password']
        userType = jGuResp['GuestUser']['guestType']
        userStatus = jGuResp['GuestUser']['status']
        userFromDate = jGuResp['GuestUser']['guestAccessInfo']['fromDate']
        userToDate = jGuResp['GuestUser']['guestAccessInfo']['toDate']
        userValidDays = jGuResp['GuestUser']['guestAccessInfo']['validDays']
        userId = jGuResp['GuestUser']['id']
        guestIds.append((userName,userPass,userType,userStatus,userFromDate,userToDate,userValidDays,userId))
    validEntries = len(guestIds)
    os.system("clear")
    print('{:^5}'.format(str("Index")) + " | " + '{:<10}'.format(str("Name")) + " | " + '{:<10}'.format(str("Password")) + " | " + '{:<20}'.format(str("Guest Type")) + " | " + '{:<20}'.format(str("Status")) + " | " + '{:<20}'.format(str("From Date")) + " | " + '{:<20}'.format(str("To Date")) + " | " + '{:<20}'.format(str("Valid Days")))
    print("="*140 + "=========")
    index = 0
    for x in guestIds:
        print('{:^5}'.format(str(index+1)) + " | " + '{:<10}'.format(str(x[0])[0:10]) + " | " + '{:<10}'.format(str(x[1])[0:10]) + " | " + '{:<20}'.format(str(x[2])[0:20]) + " | " + '{:<20}'.format(str(x[3])[0:20]) + " | " + '{:<20}'.format(str(x[4])[0:20]) + " | " + '{:<20}'.format(str(x[5])[0:20]) + " | " + '{:<20}'.format(str(x[6])[0:20]))
        index += 1
    input("Press <Enter> to continue...")

def createSingleGuest():
    api = imc.guestUser().postCreate

    if (imc.CSRF_ENABLED==True):
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-CSRF-Token': bac.get_CSRF_token(ip=imc.ISE_PAN_IP,uname=imc.USERNAME,pword=imc.PASSWORD,csrf=imc.CSRF_ENABLED)}
    else:
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}

    portalId = "f10871e0-7159-11e7-a355-005056aba474"
    utApi = imc.guestType().getAll
    utOutput = bac.get(uname=imc.USERNAME, pword=imc.PASSWORD,api=utApi)
    jUtOutput = utOutput.json()
    utIds=[]
    for values in jUtOutput['SearchResult']['resources']:
        utName = values['name']
        utDesc = values['description']
        utId = values['id']
        utIds.append((utName,utDesc,utId))
    validEntries = len(utIds)
    utTypeInt = ""
    while utTypeInt=="":
        os.system("clear")
        print('{:^5}'.format(str("Index")) + " | " + '{:<20}'.format(str("Name")) + " | " + '{:<60}'.format(str("Description")))
        print("="*75 + "======")
        index = 0
        for x in utIds:
            print('{:^5}'.format(str(index+1)) + " | " + '{:<20}'.format(str(x[0])[0:20]) + " | " + '{:<60}'.format(str(x[1])[0:60]))
            index += 1

        try:
            #Let's ensure that the input is an integer - if not, we'll hit the 'except' and try again.
            utTypeInt = int(input("Which group will this new guest be a part of from the list above (0 to quit)? "))
            if (utTypeInt == 0):
                return
            if ((utTypeInt > validEntries) or (utTypeInt<0)):
                print("Error - Please provide a value between 1-" + str(validEntries) + " - Please try again!")
                input("Press <Enter> to continue...")
                utTypeInt=""
                continue
        except:
            print("Error - Please provide a value between 1-" + str(validEntries) + " - Please try again!")
            input("Press <Enter> to continue...")
            continue
    utTypeText = utIds[utTypeInt-1][0]
    guName = input("Please provide a name for this Guest User account (<Enter> for randomly generated): ")
    if (guName != ""):
        guPass = input("Please provide a password for this Guest User account (<Enter> for randomly generated): ")
    guDays = ""
    while guDays == "":
        try:
            guDays = int(input("How many days of access (0 to quit)? "))
            if guDays == 0:
                return
        except:
            print("Error Invalid Input - Please try again!")
            guDays = ""
            continue
    guStart = input("What day would you like this access to begin (MM/DD/YYYY)? ")
    guEnd = input("What day would you like this access to end (MM/DD/YYYY)? ")

    if (guName==""):
        # No Username was given, so we'll create a random user/password
        data = '{"GuestUser": {"guestType": "'+utTypeText+'","portalId": "f10871e0-7159-11e7-a355-005056aba474","guestAccessInfo": {"validDays": '+str(guDays)+',"fromDate": "'+guStart+' 00:01","toDate": "'+guEnd+' 23:59","location": "San Jose"},"customFields": {}}}'
    else:
        # The username was given, we'll create a random username.
        data = '{"GuestUser": {"guestType": "'+utTypeText+'","portalId": "f10871e0-7159-11e7-a355-005056aba474","guestInfo" : {"userName": "'+guName+'","password": "'+guPass+'"},"guestAccessInfo": {"validDays": '+str(guDays)+',"fromDate": "'+guStart+' 00:01","toDate": "'+guEnd+' 23:59","location": "San Jose"},"customFields": {}}}'
    try:
        csgOutput = bac.post(uname=imc.GUESTUSER,pword=imc.GUESTPASS,api=api,data=data)
    except:
        print("There was an error in creating your Guest User - " + csgOutput.status_code)

    # Now that we've created the guest, let's send the output to a Spark Room.
    # To ensure that we have any randomly generated content, we will retrieve
    # guest user information from ISE.

    guestIds=[]
    api = imc.guestUser().getAll
    guOutput = bac.get(uname=imc.GUESTUSER, pword=imc.GUESTPASS,api=api)
    jGuOutput = guOutput.json()
    for values in jGuOutput['SearchResult']['resources']:
        guURL = values['link']['href']
        guResp = requests.get(guURL, auth=(imc.GUESTUSER, imc.GUESTPASS), headers=headers, params='', verify = False)
        jGuResp = guResp.json()
        userName = jGuResp['GuestUser']['guestInfo']['userName']
        userPass = jGuResp['GuestUser']['guestInfo']['password']
        userType = jGuResp['GuestUser']['guestType']
        userStatus = jGuResp['GuestUser']['status']
        userFromDate = jGuResp['GuestUser']['guestAccessInfo']['fromDate']
        userToDate = jGuResp['GuestUser']['guestAccessInfo']['toDate']
        userValidDays = jGuResp['GuestUser']['guestAccessInfo']['validDays']
        userId = jGuResp['GuestUser']['id']
        guestIds.append((userName,userPass,userType,userStatus,userFromDate,userToDate,userValidDays,userId))
    validEntries = len(guestIds)
    msg1 = '{:^5}'.format(str("Index")) + " | " + '{:<10}'.format(str("Name")) + " | " + '{:<10}'.format(str("Password")) + " | " + '{:<20}'.format(str("Guest Type")) + " | " + '{:<20}'.format(str("Status")) + " | " + '{:<20}'.format(str("From Date")) + " | " + '{:<20}'.format(str("To Date")) + " | " + '{:<20}'.format(str("Valid Days"))
    webexTeamsMessage(msg1)
    msg2 = "="*140 + "========="
    webexTeamsMessage(msg2)
    index = 0
    for x in guestIds:
        msgx = '{:^5}'.format(str(index+1)) + " | " + '{:<10}'.format(str(x[0])[0:10]) + " | " + '{:<10}'.format(str(x[1])[0:10]) + " | " + '{:<20}'.format(str(x[2])[0:20]) + " | " + '{:<20}'.format(str(x[3])[0:20]) + " | " + '{:<20}'.format(str(x[4])[0:20]) + " | " + '{:<20}'.format(str(x[5])[0:20]) + " | " + '{:<20}'.format(str(x[6])[0:20])
        webexTeamsMessage(msgx)
        index += 1

    input("Press <Enter> to continue...")

def createMultiRandomGuest():
    api = imc.guestUser().postCreate

    if (imc.CSRF_ENABLED==True):
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-CSRF-Token': bac.get_CSRF_token(ip=imc.ISE_PAN_IP,uname=imc.USERNAME,pword=imc.PASSWORD,csrf=imc.CSRF_ENABLED)}
    else:
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}

    portalId = "f10871e0-7159-11e7-a355-005056aba474"
    utApi = imc.guestType().getAll
    utOutput = bac.get(uname=imc.USERNAME, pword=imc.PASSWORD,api=utApi)
    jUtOutput = utOutput.json()
    utIds=[]
    for values in jUtOutput['SearchResult']['resources']:
        utName = values['name']
        utDesc = values['description']
        utId = values['id']
        utIds.append((utName,utDesc,utId))
    validEntries = len(utIds)
    utTypeInt = ""
    while utTypeInt=="":
        os.system("clear")
        print('{:^5}'.format(str("Index")) + " | " + '{:<20}'.format(str("Name")) + " | " + '{:<60}'.format(str("Description")))
        print("="*75 + "======")
        index = 0
        for x in utIds:
            print('{:^5}'.format(str(index+1)) + " | " + '{:<20}'.format(str(x[0])[0:20]) + " | " + '{:<60}'.format(str(x[1])[0:60]))
            index += 1

        try:
            #Let's ensure that the input is an integer - if not, we'll hit the 'except' and try again.
            utTypeInt = int(input("Which group will this new guest be a part of from the list above (0 to quit)? "))
            if (utTypeInt == 0):
                return
            if ((utTypeInt > validEntries) or (utTypeInt<0)):
                print("Error - Please provide a value between 1-" + str(validEntries) + " - Please try again!")
                input("Press <Enter> to continue...")
                utTypeInt=""
                continue
        except:
            print("Error - Please provide a value between 1-" + str(validEntries) + " - Please try again!")
            input("Press <Enter> to continue...")
            continue
    utTypeText = utIds[utTypeInt-1][0]
    guDays = ""
    while guDays == "":
        try:
            guDays = int(input("How many days of access (0 to quit)? "))
            if guDays == 0:
                return
        except:
            print("Error Invalid Input - Please try again!")
            guDays = ""
            continue
    guStart = input("What day would you like this access to begin (MM/DD/YYYY)? ")
    guEnd = input("What day would you like this access to end (MM/DD/YYYY)? ")
    groupTag = input("Please provide a group tag for the Guest accounts: ")
    guCount = ""
    while (guCount == ""):
        try:
            #Let's ensure that the input is an integer - if not, we'll hit the 'except' and try again.
            guCount = int(input("How many Random Accounts would you like to create (1-20) (0 to quit)? "))
            if (guCount == 0):
                return
            if ((guCount > 20) or (guCount<0)):
                print("Error - Please provide a value between 1-20 - Please try again!")
                input("Press <Enter> to continue...")
                guCount=""
                continue
        except:
            print("Error - Please provide a value between 1-20 - Please try again!")
            input("Press <Enter> to continue...")
            guCount ==""
            continue
    yourEmail = input("Please provide your email address - a WebEx Teams message will be sent with your requested accounts: ")

    currentGu = 0
    while (currentGu<guCount):
        # No Username was given, so we'll create a random user/password
        data = '{"GuestUser": {"guestType": "'+utTypeText+'","portalId": "f10871e0-7159-11e7-a355-005056aba474","guestAccessInfo": {"validDays": '+str(guDays)+',"fromDate": "'+guStart+' 00:01","toDate": "'+guEnd+' 23:59","location": "San Jose","groupTag": "' + groupTag + '"},"customFields": {}}}'
        try:
            csgOutput = bac.post(uname=imc.GUESTUSER,pword=imc.GUESTPASS,api=api,data=data)
            currentGu += 1
        except:
            print("There was an error in creating your Guest User - " + csgOutput.status_code)

    guestIds=[]
    api = imc.guestUser().getAll + "?filter=groupTag.EQ." + groupTag
    guOutput = bac.get(uname=imc.GUESTUSER, pword=imc.GUESTPASS,api=api)
    jGuOutput = guOutput.json()
    for values in jGuOutput['SearchResult']['resources']:
        guURL = values['link']['href']
        guResp = requests.get(guURL, auth=(imc.GUESTUSER, imc.GUESTPASS), headers=headers, params='', verify = False)
        jGuResp = guResp.json()
        userName = jGuResp['GuestUser']['guestInfo']['userName']
        userPass = jGuResp['GuestUser']['guestInfo']['password']
        userType = jGuResp['GuestUser']['guestType']
        userStatus = jGuResp['GuestUser']['status']
        userFromDate = jGuResp['GuestUser']['guestAccessInfo']['fromDate']
        userToDate = jGuResp['GuestUser']['guestAccessInfo']['toDate']
        userValidDays = jGuResp['GuestUser']['guestAccessInfo']['validDays']
        userId = jGuResp['GuestUser']['id']
        guestIds.append((userName,userPass,userType,userStatus,userFromDate,userToDate,userValidDays,userId))
    validEntries = len(guestIds)

    fileName = groupTag + ".txt"
    fileHandle = open(fileName,'w')

    fileHandle.write('{:^5}'.format(str("Index")) + " | " + '{:<10}'.format(str("Name")) + " | " + '{:<10}'.format(str("Password")) + " | " + '{:<20}'.format(str("Guest Type")) + " | " + '{:<20}'.format(str("Status")) + " | " + '{:<20}'.format(str("From Date")) + " | " + '{:<20}'.format(str("To Date")) + " | " + '{:<20}'.format(str("Valid Days")))
    fileHandle.write("\n")
    fileHandle.write("="*140 + "=========\n")
    index = 0
    for x in guestIds:
        fileHandle.write('{:^5}'.format(str(index+1)) + " | " + '{:<10}'.format(str(x[0])[0:10]) + " | " + '{:<10}'.format(str(x[1])[0:10]) + " | " + '{:<20}'.format(str(x[2])[0:20]) + " | " + '{:<20}'.format(str(x[3])[0:20]) + " | " + '{:<20}'.format(str(x[4])[0:20]) + " | " + '{:<20}'.format(str(x[5])[0:20]) + " | " + '{:<20}'.format(str(x[6])[0:20]))
        fileHandle.write("\n")
        index += 1
    fileHandle.close()
    filepath = fileName
    msg = "Here are your requested guest user accounts for Group " + groupTag + "."
    webexTeamsFile(filepath,yourEmail,msg)

    input("Press <Enter> to continue...")

def webexTeamsMessage(msg):
    api = "https://api.ciscospark.com/v1/messages"
    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'Authorization': "Bearer " + bearerTokenISEBot}
    data = '{"roomId": "' + roomIDISEBot + '","text": "' + msg + '"}'
    try:
        wtResp = requests.post(api, data=data, headers=headers, params='', verify = False, stream = True)
    except:
        print("Something went wrong ")
        e = sys.exc_info()[0]
        print( "Error: %s" % e )

def webexTeamsFile(filepath,yourEmail,msg):

    filepath = filepath
    filetype = 'text/plain'
    toPersonEmail = yourEmail
    api = "https://api.ciscospark.com/v1/messages"

    my_fields={'toPersonEmail': yourEmail,
           'text': msg,
           'files': ('Guest Users', open(filepath, 'rb'), filetype)
           }
    data = MultipartEncoder(fields=my_fields)
    headers = {'Content-Type': data.content_type, 'Authorization': "Bearer " + bearerTokenISEBot}
    wtResp = requests.post(api, data=data, headers=headers, params='', verify = False, stream = True)

def printThreatMenu():
    global tChoice
    os.system("clear")
    print("Threat Remediation Menu")
    print("=======================")
    print("1. List Adaptive Network Control Policies")
    print("2. List Adaptive Network Control Endpoints")
    print("3. Quarantine Device")
    print("4. Unquarantine Device")
    print("")
    tChoice = input("Please choose the task from the above list (q to go to previous menu): ")
# End <printNasMenu>

def listANCPolicy():
    # Let's retrieve the API to get all current Endpoints.
    api = imc.ancPolicy().getAll

    # If CSRF is enabled, we'll need to include the CSRF Token in the header.
    if (imc.CSRF_ENABLED==True):
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-CSRF-Token': bac.get_CSRF_token(ip=imc.ISE_PAN_IP,uname=imc.USERNAME,pword=imc.PASSWORD,csrf=imc.CSRF_ENABLED)}
    else:
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}

    # Let's do the HTTP GET for all current endpoints.
    ancPolOutput = bac.get(api=api)

    # We'll parse the JSON and store the contents into a python dictionary.
    jAncPolOutput = ancPolOutput.json()

    # We'll store all of the Policies into an array with all of the relevant
    # useful data for easy lookup.
    noPolicy = 1
    policyIds = []
    for values in jAncPolOutput['SearchResult']['resources']:
        polURL = values['link']['href']
        polResp = requests.get(polURL, auth=(imc.USERNAME, imc.PASSWORD), headers=headers, params='', verify = False)
        jPolResp = polResp.json()
        ancPolId = jPolResp['ErsAncPolicy']['id']
        ancPolName = jPolResp['ErsAncPolicy']['name']
        ancPolActions = ""
        for x in jPolResp['ErsAncPolicy']['actions']:
            ancPolActions += x

        # Let's store the Policy data into an easy-to-use array for reference.
        policyIds.append((noPolicy,ancPolId,ancPolName,ancPolActions))
        noPolicy += 1
    # Print out the Policies into a pretty table.
    os.system("clear")
    print('{:^5}'.format(str("Index")) + " | " + '{:<30}'.format(str("ID")) + " | " + '{:<30}'.format(str("Name")) + " | " + '{:<60}'.format(str("Actions")))
    print("="*125 + "=========")
    index = 0
    for x in policyIds:
        print('{:^5}'.format(str(x[0])) + " | " + '{:<30}'.format(str(x[1])) + " | " + '{:<30}'.format(str(x[2])) + " | " + '{:<60}'.format(str(x[3])))
        index += 1

    input("Press <Enter> to continue...")
# End <listANCPolicy>

def listANCEndpoint():
        # Let's retrieve the API to get all current Endpoints.
        api = imc.ancEndpoint().getAll

        # If CSRF is enabled, we'll need to include the CSRF Token in the header.
        if (imc.CSRF_ENABLED==True):
            headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-CSRF-Token': bac.get_CSRF_token(ip=imc.ISE_PAN_IP,uname=imc.USERNAME,pword=imc.PASSWORD,csrf=imc.CSRF_ENABLED)}
        else:
            headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}

        # Let's do the HTTP GET for all current endpoints.
        ancEndpointOutput = bac.get(api=api)

        # We'll parse the JSON and store the contents into a python dictionary.
        jAncEpOutput = ancEndpointOutput.json()

        # We'll store all of the Endpoints into an array with all of the relevant
        # useful data for easy lookup.
        noEndpoint = 1
        endpointIds = []
        for values in jAncEpOutput['SearchResult']['resources']:
            epURL = values['link']['href']
            epResp = requests.get(epURL, auth=(imc.USERNAME, imc.PASSWORD), headers=headers, params='', verify = False)
            jEpResp = epResp.json()
            ancEpMac = jEpResp['ErsAncEndpoint']['macAddress']
            ancEpPolName = jEpResp['ErsAncEndpoint']['policyName']
            ancEpId = jEpResp['ErsAncEndpoint']['id']
            # Let's store the Endpoint data into an easy-to-use array for reference.
            endpointIds.append((noEndpoint,ancEpMac,ancEpPolName,ancEpId))
            noEndpoint += 1
        # Print out the Endpoints into a pretty table.
        os.system("clear")
        print('{:^5}'.format(str("Index")) + " | " + '{:<30}'.format(str("MAC Address")) + " | " + '{:<30}'.format(str("Policy Name")))
        print("="*65 + "======")
        index = 0
        for x in endpointIds:
            print('{:^5}'.format(str(x[0])) + " | " + '{:<30}'.format(str(x[1])) + " | " + '{:<30}'.format(str(x[2])))
            index += 1

        input("Press <Enter> to continue...")
# End <listANCEndpoint>

def quarantineUser():
    # Let's retrieve the API to get all current ANC Endpoints.
    api = imc.endPoint().getAll

    # If CSRF is enabled, we'll need to include the CSRF Token in the header.
    if (imc.CSRF_ENABLED==True):
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-CSRF-Token': bac.get_CSRF_token(ip=imc.ISE_PAN_IP,uname=imc.USERNAME,pword=imc.PASSWORD,csrf=imc.CSRF_ENABLED)}
    else:
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}

    # Let's do the HTTP GET for all current endpoints.
    EndpointOutput = bac.get(api=api)

    # We'll parse the JSON and store the contents into a python dictionary.
    jEndpointOutput = EndpointOutput.json()

    # We'll store all of the Endpoints into an array with all of the relevant
    # useful data for easy lookup.
    noEndpoint = 1
    endpointIds = []
    for values in jEndpointOutput['SearchResult']['resources']:
        endpointURL = values['link']['href']
        endpointResp = requests.get(endpointURL, auth=(imc.USERNAME, imc.PASSWORD), headers=headers, params='', verify = False)
        jEndpointResp = endpointResp.json()
        endpointGroupId = jEndpointResp['ERSEndPoint']['groupId']

        # Let's resolve the groupId for a human readable Endpoint Identity Group name
        gApi = imc.endPointIdentityGroup().get_ById(endpointGroupId)
        groupOutput = bac.get(api=gApi)
        jGroupOutput = groupOutput.json()
        endpointGroupName = jGroupOutput['EndPointGroup']['name']

        # If the endpoint currently has a Profile assigned to it, we'll do a lookup for that.
        if jEndpointResp['ERSEndPoint']['profileId'] != '':
            api = 'ers/config/profilerprofile/'+jEndpointResp['ERSEndPoint']['profileId']
            profileResp = bac.get(api=api)
            jProfileResp = profileResp.json()
            endpointProf = jProfileResp['ProfilerProfile']['name']
        else:
            endpointProf = "Unknown"

        # Let's store the Endpoint data into an easy-to-use array for reference.
        endpointIds.append((noEndpoint,jEndpointResp['ERSEndPoint']['name'],jEndpointResp['ERSEndPoint']['mac'], endpointProf, endpointGroupName, jEndpointResp['ERSEndPoint']['portalUser'], values['id']))
        noEndpoint += 1
    validEndpoints = len(endpointIds)

    # We'll print out the current Endpoints and allow the user to delete by number.
    selectEndpoint = ""
    while (selectEndpoint == ""):

        # Print out the Endpoints into a pretty table.
        os.system("clear")
        print('{:^5}'.format(str("Index")) + " | " + '{:<30}'.format(str("Name")) + " | " + '{:<18}'.format(str("MAC Address")) + " | " + '{:<30}'.format(str("Endpoint Profile")) + " | " + '{:<40}'.format(str("Endpoint Identity Group")) + " | " + '{:<30}'.format(str("Portal User")))
        print("="*153 + "==================")
        index = 0
        for x in endpointIds:
            print('{:^5}'.format(str(x[0])) + " | " + '{:<30}'.format(str(x[1])) + " | " + '{:<18}'.format(str(x[2])) + " | " + '{:<30}'.format(str(x[3])) + " | " + '{:<40}'.format(str(x[4])) + " | " + '{:<30}'.format(str(x[5])))
            index += 1

        # Let's prompt the user for an integer and if they don't provide a valid
        # value, we'll ask them again.
        try:
            # Let's ensure that the input is an integer - if not, we'll hit the 'except' and try again.
            selectEndpoint = int(input("Please provide the number of the Endpoint to Remediate ('0' to quit): "))
            if (selectEndpoint == 0):
                return
        except:
            print("Error - Please provide a value between 1-" + str(validEndpoints) + " - Please try again!")
            input("Press <Enter> to continue...")
            continue

        # Let's ensure that the entry is valid given the number of Endpoints.
        if not ((selectEndpoint>=0) and (selectEndpoint<validEndpoints+1)):
            selectEndpoint = ""
            print("Error - Please provide a value between 1-" + str(validEndpoints) + " - Please try again!")
            input("Press <Enter> to continue...")

    # Let's retrieve the API to get all current Endpoints.
    pApi = imc.ancPolicy().getAll

    # Let's do the HTTP GET for all current endpoints.
    ancPolOutput = bac.get(api=pApi)

    # We'll parse the JSON and store the contents into a python dictionary.
    jAncPolOutput = ancPolOutput.json()

    # We'll store all of the Policies into an array with all of the relevant
    # useful data for easy lookup.
    noPolicy = 1
    policyIds = []
    for values in jAncPolOutput['SearchResult']['resources']:
        polURL = values['link']['href']
        polResp = requests.get(polURL, auth=(imc.USERNAME, imc.PASSWORD), headers=headers, params='', verify = False)
        jPolResp = polResp.json()
        ancPolId = jPolResp['ErsAncPolicy']['id']
        ancPolName = jPolResp['ErsAncPolicy']['name']
        ancPolActions = ""
        for x in jPolResp['ErsAncPolicy']['actions']:
            ancPolActions += x

        # Let's store the Policy data into an easy-to-use array for reference.
        policyIds.append((noPolicy,ancPolId,ancPolName,ancPolActions))
        noPolicy += 1

    validPol = len(policyIds)
    selectPol = ""
    # Print out the Policies into a pretty table.
    while (selectPol == ""):
        os.system("clear")
        print('{:^5}'.format(str("Index")) + " | " + '{:<30}'.format(str("ID")) + " | " + '{:<30}'.format(str("Name")) + " | " + '{:<60}'.format(str("Actions")))
        print("="*125 + "=========")
        index = 0
        for x in policyIds:
            print('{:^5}'.format(str(x[0])) + " | " + '{:<30}'.format(str(x[1])) + " | " + '{:<30}'.format(str(x[2])) + " | " + '{:<60}'.format(str(x[3])))
            index += 1
        # Let's prompt the user for an integer and if they don't provide a valid
        # value, we'll ask them again.
        try:
            # Let's ensure that the input is an integer - if not, we'll hit the 'except' and try again.
            selectPol = int(input("Please provide the number of the ANC Policy to Apply ('0' to quit): "))
            if (selectPol == 0):
                return
        except:
            print("Error - Please provide a value between 1-" + str(validPol) + " - Please try again!")
            input("Press <Enter> to continue...")
            continue

        # Let's ensure that the entry is valid given the number of Endpoints.
        if not ((selectPol>=0) and (selectPol<validPol+1)):
            selectPol = ""
            print("Error - Please provide a value between 1-" + str(validPol) + " - Please try again!")

    # This data will be pushed as the body of the API call to update the MAC address with the relevant
    # ANC Policy
    data = '{"OperationAdditionalData" : {"additionalData" : [ {"name" : "macAddress","value" : "'+ endpointIds[selectEndpoint-1][2]+'"},{"name" : "policyName","value" : "'+ policyIds[selectPol-1][2] +'"} ]}}'

    if (selectEndpoint !=0):
        confirmProfDel = input("Please type 'yes' to confirm that you would like to apply ANC Policy " + policyIds[selectPol-1][2] + " to the Endpoint '" + endpointIds[selectEndpoint-1][2] + "': ")

        # Let's give the user an opportunity to confirm their selection.
        if (confirmProfDel == "yes"):
            #
            updApi = imc.ancEndpoint().putApply
            try:
                updOutput = bac.put(api=updApi,data=data)
                print("The Endpoint '" + endpointIds[selectEndpoint-1][2] + "' has been given ANC Policy " + policyIds[selectPol-1][2] + "!")
            except:
                print("There may have been an error in the deletion process - please confirm deletion!")

        # If they don't type "yes", then we'll abort the deletion of the endpoint.
        else:
            print("Operation aborted!")
    input("Press <Enter> to continue...")
# End <quarantineUser>

def unquarantineUser():
    # Let's retrieve the API to get all current ANC Endpoints.
    api = imc.ancEndpoint().getAll

    # If CSRF is enabled, we'll need to include the CSRF Token in the header.
    if (imc.CSRF_ENABLED==True):
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-CSRF-Token': bac.get_CSRF_token(ip=imc.ISE_PAN_IP,uname=imc.USERNAME,pword=imc.PASSWORD,csrf=imc.CSRF_ENABLED)}
    else:
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}

    # Let's do the HTTP GET for all current endpoints.
    ancEndpointOutput = bac.get(api=api)

    # We'll parse the JSON and store the contents into a python dictionary.
    jAncEpOutput = ancEndpointOutput.json()

    # We'll store all of the Endpoints into an array with all of the relevant
    # useful data for easy lookup.
    noEndpoint = 1
    endpointIds = []
    for values in jAncEpOutput['SearchResult']['resources']:
        epURL = values['link']['href']
        epResp = requests.get(epURL, auth=(imc.USERNAME, imc.PASSWORD), headers=headers, params='', verify = False)
        jEpResp = epResp.json()
        ancEpMac = jEpResp['ErsAncEndpoint']['macAddress']
        ancEpPolName = jEpResp['ErsAncEndpoint']['policyName']
        ancEpId = jEpResp['ErsAncEndpoint']['id']
        # Let's store the Endpoint data into an easy-to-use array for reference.
        endpointIds.append((noEndpoint,ancEpMac,ancEpPolName,ancEpId))
        noEndpoint += 1
    # Print out the Endpoints into a pretty table.

    validEndpoints = len(endpointIds)
    selectEndpoint = ""
    while (selectEndpoint == ""):
        os.system("clear")
        print('{:^5}'.format(str("Index")) + " | " + '{:<30}'.format(str("MAC Address")) + " | " + '{:<30}'.format(str("Policy Name")))
        print("="*65 + "======")
        index = 0
        for x in endpointIds:
            print('{:^5}'.format(str(x[0])) + " | " + '{:<30}'.format(str(x[1])) + " | " + '{:<30}'.format(str(x[2])))
            index += 1
        try:
            # Let's ensure that the input is an integer - if not, we'll hit the 'except' and try again.
            selectEndpoint = int(input("Please provide the number of the Endpoint to Unquarantine ('0' to quit): "))
            if (selectEndpoint == 0):
                return
        except:
            print("Error - Please provide a value between 1-" + str(validEndpoints) + " - Please try again!")
            input("Press <Enter> to continue...")
            continue

        # Let's ensure that the entry is valid given the number of Endpoints.
        if not ((selectEndpoint>=0) and (selectEndpoint<validEndpoints+1)):
            selectEndpoint = ""
            print("Error - Please provide a value between 1-" + str(validEndpoints) + " - Please try again!")
            input("Press <Enter> to continue...")

    # This data will be pushed as the body of the API call to update the MAC address with the relevant
    # ANC Policy
    data = '{"OperationAdditionalData" : {"additionalData" : [ {"name" : "macAddress","value" : "'+ endpointIds[selectEndpoint-1][1]+'"}]}}'
    if (selectEndpoint !=0):
        confirmProfDel = input("Please type 'yes' to confirm that you would like to remove all ANC Policy from the Endpoint '" + endpointIds[selectEndpoint-1][1] + "': ")

        # Let's give the user an opportunity to confirm their selection.
        if (confirmProfDel == "yes"):
            #
            updApi = imc.ancEndpoint().putClear
            try:
                updOutput = bac.put(api=updApi,data=data)
                print("The Endpoint '" + endpointIds[selectEndpoint-1][1] + "' has been cleared of all ANC Policies.")
            except:
                print("There may have been an error in the deletion process - please confirm deletion!")

        # If they don't type "yes", then we'll abort the deletion of the endpoint.
        else:
            print("Operation aborted!")

    input("Press <Enter> to continue...")
# End <unquarantineUser>

def printACLMenu():
    global dChoice
    os.system("clear")
    print("Downloadable ACLs Menu")
    print("=======================")
    print("1. List Downloadable ACLs")
    print("2. Delete Downloadable ACLs")
    print("3. Import Downloadable ACLs")
    print("")
    dChoice = input("Please choose the task from the above list (q to go to previous menu): ")
# End <printACLMenu>

def listDacls():
    api = imc.downloadableACL().getAll
    if (imc.CSRF_ENABLED==True):
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-CSRF-Token': bac.get_CSRF_token(ip=imc.ISE_PAN_IP,uname=imc.USERNAME,pword=imc.PASSWORD,csrf=imc.CSRF_ENABLED)}
    else:
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
    ldaclOutput = bac.get(api=api)
    jDaclOutput = ldaclOutput.json()
    noDacl = 1
    daclIds = []
    for values in jDaclOutput['SearchResult']['resources']:
        lDaclURL = values['link']['href']
        lDaclResp = requests.get(lDaclURL, auth=(imc.USERNAME, imc.PASSWORD), headers=headers, params='', verify = False)
        jDaclResp = lDaclResp.json()
        daclName = jDaclResp['DownloadableAcl']['name']
        daclDesc = jDaclResp['DownloadableAcl']['description']
        daclDacl = jDaclResp['DownloadableAcl']['dacl']
        daclId = jDaclResp['DownloadableAcl']['id']
        daclIds.append((noDacl,daclName,daclDesc,daclDacl,daclId))
        noDacl += 1

    for x in daclIds:
        os.system("clear")
        print(x[1])
        print("="*len(x[1]))
        print("Description: " + x[2])
        print("ACEs:")
        print(x[3])
        nextInput = input("Press <Enter> for next Record, 'q' to quit...")
        if (nextInput=="q"):
            return

    if (nextInput!="q"):
        input("Press <Enter> to Continue...")
# End <listDacls>

def deleteDacls():
    api = imc.downloadableACL().getAll
    if (imc.CSRF_ENABLED==True):
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-CSRF-Token': bac.get_CSRF_token(ip=imc.ISE_PAN_IP,uname=imc.USERNAME,pword=imc.PASSWORD,csrf=imc.CSRF_ENABLED)}
    else:
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
    ldaclOutput = bac.get(api=api)
    jDaclOutput = ldaclOutput.json()
    noDacl = 1
    daclIds = []
    for values in jDaclOutput['SearchResult']['resources']:
        lDaclURL = values['link']['href']
        lDaclResp = requests.get(lDaclURL, auth=(imc.USERNAME, imc.PASSWORD), headers=headers, params='', verify = False)
        jDaclResp = lDaclResp.json()
        daclName = jDaclResp['DownloadableAcl']['name']
        daclDesc = jDaclResp['DownloadableAcl']['description']
        daclDacl = jDaclResp['DownloadableAcl']['dacl']
        daclId = jDaclResp['DownloadableAcl']['id']
        daclIds.append((noDacl,daclName,daclDesc,daclDacl,daclId))
        noDacl += 1
    validDacls = len(daclIds)
    selectDacl = ""
    while (selectDacl == ""):
        os.system("clear")
        print('{:^5}'.format(str("Index")) + " | " + '{:<30}'.format(str("Name")) + " | " + '{:<30}'.format(str("Description")))
        print("="*65 + "======")
        index = 0
        for x in daclIds:
            print('{:^5}'.format(str(x[0])) + " | " + '{:<30}'.format(str(x[1])) + " | " + '{:<30}'.format(str(x[2])))
            index += 1
        try:
            # Let's ensure that the input is an integer - if not, we'll hit the 'except' and try again.
            selectDacl = int(input("Please provide the number of the Downloadable ACL to delete ('0' to quit): "))
            if (selectDacl == 0):
                return
        except:
            print("Error - Please provide a value between 1-" + str(validDacls) + " - Please try again!")
            input("Press <Enter> to continue...")
            continue

        # Let's ensure that the entry is valid given the number of Endpoints.
        if not ((selectDacl>=0) and (selectDacl<validDacls+1)):
            selectDacl = ""
            print("Error - Please provide a value between 1-" + str(validDacls) + " - Please try again!")
            input("Press <Enter> to continue...")

    # This data will be pushed as the body of the API call to update the MAC address with the relevant
    # ANC Policy
    if (selectDacl !=0):
        confirmDaclDel = input("Please type 'yes' to confirm that you would like to remove Downloadable ACL '" + daclIds[selectDacl-1][1] + "': ")

        # Let's give the user an opportunity to confirm their selection.
        if (confirmDaclDel == "yes"):
            #
            delDaclApi = imc.downloadableACL().delete_ById(daclIds[selectDacl-1][4])
            try:
                updOutput = bac.delete(api=delDaclApi)
                print("The Downloadable ACL '" + daclIds[selectDacl-1][1] + "' has been deleted.")
            except:
                print("There may have been an error in the deletion process - please confirm deletion!")

        # If they don't type "yes", then we'll abort the deletion of the endpoint.
        else:
            print("Operation aborted!")

    input("Press <Enter> to Continue...")
# End <deleteDacls>

def importDacls():
    # If CSRF is being used, include the CSRF token within the headers.
    if (imc.CSRF_ENABLED==True):
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-CSRF-Token': bac.get_CSRF_token(ip=imc.ISE_PAN_IP,uname=imc.USERNAME,pword=imc.PASSWORD,csrf=imc.CSRF_ENABLED)}
    else:
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}

    # We'll create a quick template file for the user to leverage for proper file
    # content format.
    os.system("clear")
    template = open("DaclTemplate.csv",'w')
    for x in range(1,5):
        template.write("name:DaclNameNumber" + str(x) + "\n")
        template.write("description:Dacl Description\n")
        template.write(":beginDacl\n")
        template.write("permit ip any any\n")
        template.write("deny ip any any\n")
        template.write(":endDacl\n")
    template.close()
    print("File 'DaclTemplate.csv' was created - modify this file with the appropriate endpoints and endpoint Identity Groups and save as a new name.")
    print("Note: Capitalization does matter.")
    print("WARNING: Syntax checking of the ACL can sometimes affect the ACL - please confirm the proper ACL.")

    # This array will store any groups that we'll need to create.
    createdDacls=[]

    # Let's read the file and parse its contents.
    getInputFile = input("Please provide the filename of the file to import: ")
    try:
        with open(getInputFile) as inFile:
            content = inFile.read().splitlines()
    except:
        print("There must be a problem with the filename - please try again!")
        input("Press <Enter> to Continue...")
        return

    # The content of the DACL file is now stored in the variable 'content'
    # Let's parse the file and store into component parts.

    startAces = 0
    daclMatrix=[]
    for x in content:
        print(x)
        if ((startAces ==0) and (x.startswith("name:"))):
            daclName = x[5:]
            print("name - " + x)
        if ((startAces == 0) and (x.startswith("description:"))):
            daclDesc = x[12:]
            print("description - " + x)
        if (x==":beginDacl"):
            startAces = 1
            daclList = ""
            print("Begin DACL - " + x)
            continue
        if ((startAces == 1) and (x != ":endDacl")):
            daclList = daclList + x + "\\n"
            print("Add DACL - " + x)
        if ((startAces == 1) and (x == ":endDacl")):
            startAces = 0
            print("End DACL - " + x)
            daclMatrix.append((daclName,daclDesc,daclList))
    print(daclMatrix)

    input("Press <Enter> to Continue...")

    for x in daclMatrix:
        api = imc.downloadableACL().postCreate

        data = '{"DownloadableAcl" : {"name" : "' + x[0] + '","description" : "' + x[1] + '","dacl" : "' + x[2] + '"}}'
        try:
            daclOutput = bac.post(api=api,data=data)
            print("The Downloadable ACL was created!")
        except:
            print("There may have been an error in the creation process - please confirm proper Downloadable ACL content!")
    input("Press <Enter> to Continue...")
# End <importDacls>

# Start <main>
# This prints the main menu.
printMenu()

# This while loop will cycle through until the use enters 'q' for quit.
while (choice != "q"):

    # This choice is the Network Device/Network Device Groups Menu
    if (choice=="1"):
        nChoice = ""
        printNasMenu()
        while (nChoice != "q"):
            if (nChoice == "1"):
                listNetworkDevices()
            elif (nChoice == "2"):
                deleteNetworkDevice()
            elif (nChoice == "3"):
                importNetworkDevice()
            elif (nChoice == "4"):
                listNasGroups()
            elif (nChoice == "5"):
                createNasGroup()
            elif (nChoice == "6"):
                deleteNasGroup()
            else:
                nChoice = "q"
                continue
            printNasMenu()

    # This choice is the Endpoint Menu option.
    elif (choice=="2"):
        eChoice = ""
        printEndpointMenu()
        while (eChoice != "q"):
            if (eChoice == "1"):
                printAllEndpoints()
            elif (eChoice == "2"):
                printAllEndpointGroups()
            elif (eChoice == "3"):
                addEndpointList()
            elif (eChoice == "4"):
                addEndpointToList()
            elif (eChoice == "5"):
                importEndpointIntoGroup()
            elif (eChoice == "6"):
                deleteEndpoint()
            elif (eChoice == "7"):
                deleteEndpointIdGroup()
            else:
                eChoice = "q"
                continue
            printEndpointMenu()

    # This choice is the Authorization Menu option.
    elif (choice=="3"):
        aChoice = ""
        printAuthzProfMenu()
        while (aChoice != "q"):

            # This choice will print a sub-menu that allows the user
            # to print a particular type of Authz Profile.
            if (aChoice == "1"):
                laoChoice = ""
                listAuthzOptions()
                while (laoChoice !="q"):
                    if (laoChoice == "1"):
                        listAuthzProfilesRadius()
                    elif (laoChoice == "2"):
                        listAuthzProfilesTrustSec()
                    elif (laoChoice == "3"):
                        listAuthzProfilesTacacs()
                    elif (laoChoice == "4"):
                        listAuthzProfilesAll()
                    else:
                        laoChoice = "q"
                        continue
                    listAuthzOptions()
            elif (aChoice == "2"):
                addAuthzProfiles()
            elif (aChoice == "3"):
                deleteAuthzProfiles()
            elif (aChoice == "4"):
                exportAuthzProfiles()
            else:
                aChoice = "q"
                continue
            printAuthzProfMenu()

    # This menu will perform a RADIUS probe of all configured ISE Nodes.
    elif (choice=="4"):
        radiusProbe()

    # This menu will provide Portal functios - Guest creation mainly.
    elif (choice=="5"):
        pChoice = ""
        printPortalMenu()
        while (pChoice !="q"):
            if (pChoice == "1"):
                printPortalInfo()
            elif (pChoice == "2"):
                printGuestUsers()
            elif (pChoice == "3"):
                createSingleGuest()
            elif (pChoice == "4"):
                createMultiRandomGuest()
            else:
                pChoice = "q"
                continue
            printPortalMenu()

    # This menu will focus on Threat Remediation - ie Quarantining users.
    elif (choice=="6"):
        tChoice = ""
        printThreatMenu()
        while (tChoice !="q"):
            if (tChoice == "1"):
                listANCPolicy()
            elif (tChoice == "2"):
                listANCEndpoint()
            elif (tChoice == "3"):
                quarantineUser()
            elif (tChoice == "4"):
                unquarantineUser()
            else:
                tChoice = "q"
                continue
            printThreatMenu()

    # This menu will focus on Downloadable ACLs
    elif (choice=="7"):
        dChoice = ""
        printACLMenu()
        while (dChoice !="q"):
            if (dChoice == "1"):
                listDacls()
            elif (dChoice == "2"):
                deleteDacls()
            elif (dChoice == "3"):
                importDacls()
            else:
                dChoice = "q"
                continue
            printACLMenu()

    printMenu()
# End <main>
