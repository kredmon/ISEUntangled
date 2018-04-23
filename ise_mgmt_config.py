# Change the string below to the hostname/IP address of the Primary ISE Policy Admin Node Server
# Local ISE IP address
ISE_PAN_IP = "192.168.200.10"
# If CSRF is enabled on ISE ERS configuration, set the CSRF_ENABLED variable below to "true".  Otherwise,
# set CSRF_ENABLED to "false".
CSRF_ENABLED = False
# Enter user name and password for the ERS/Admin user that will have the requisite rights to the ISE PAN
# Username/Password for Local ISE
USERNAME = "apiadmin"
PASSWORD = "apiadmin"
# API Username/Password for both Local ISE
APIUSER = "apiadmin"
APIPASS = "apiadmin"
# Guest ERS Username/Password for Local ISE
GUESTUSER = "guestuser"
GUESTPASS = "Cisc0123!"

# This is a shorthand version of the ERS APIs
class ancEndpoint(object):

    """
    Adaptive Network Control (ANC) provides the ability to create network endpoint authorization controls based on ANC policies.
    """
    def get_ById(self,id1):
        return "ers/config/ancendpoint/" + id1;

    def getBulk_ById(self,id1):
        return "ers/config/ancendpoint/bulk/" + id1;

    putClear = "ers/config/ancendpoint/clear"
    putApply = "ers/config/ancendpoint/apply"
    getAll = "ers/config/ancendpoint"
    getVersion = "ers/config/ancendpoint/versioninfo"
    putBulk = "ers/config/ancendpoint/bulk/submit"

class ancPolicy(object):

    """
    Adaptive Network Control (ANC) provides the ability to create network endpoint authorization controls based on ANC policies.
    """
    def get_ByName(self,name):
        return "ers/config/ancpolicy/name/" + name;

    def get_ById(self,id1):
        return "ers/config/ancpolicy/" + id1;

    def putUpdate_ById(self,id1):
        return "ers/config/ancpolicy/" + id1;

    def delete_ById(self,id1):
        return "ers/config/ancpolicy/" + id1;

    def getBulk_ById(self,id1):
        return "ers/config/ancpolicy/bulk" + id1;

    putCreate = "ers/config/ancpolicy"
    getAll = "ers/config/ancpolicy"
    getVersion = "ers/config/ancpolicy/versioninfo"
    putBulk = "ers/config/ancpolicy/bulk/submit"

class activeDirectory(object):

    """
    Active Directory API allows the client to add, delete, search and perform actions on active directory domains through ISE's join points. In this documentation, for each available API you will find the request syntax including the required headers and a response example of a successful flow.
    """
    def putLeaveId(self,id1):
        return "ers/config/activedirectory/" + id1 + "/leave"

    def putGetUserGroupsId(self,id1):
        return "ers/config/activedirectory/" + id1 + "/getUserGroups"

    def putLoadGroupsId(self,id1):
        return "ers/config/activedirectory/" + id1 + "/addGroups"

    def putIsUserMemberOfId(self,id1):
        return "ers/config/activedirectory/" + id1 + "/isUserMemberOf"

    def putGetTrustedDomainsId(self,id1):
        return "ers/config/activedirectory/" + id1 + "/getTrustedDomains"

    def putGetGroupsByDomainId(self,id1):
        return "ers/config/activedirectory/" + id1 + "/getGroupsByDomain"

    def putJoinAllNodesId(self,id1):
        return "ers/config/activedirectory/" + id1 + "/joinAllNodes"

    def putLeaveAllNodesId(self,id1):
        return "ers/config/activedirectory/" + id1 + "/leaveAllNodes"

    def getJoinPointId(self,id1):
        return "ers/config/activedirectory" + id1

    def putJoinADomainId(self,id1):
        return "ers/config/activedirectory/" + id1 + "/join"

    def deleteJoinPoint_ById(self,id1):
        return "ers/config/activedirectory/" + id1

    postCreateJoinPoint = "ers/config/activedirectory"
    getAllJoinPoints = "ers/config/activedirectory"
    getVersion = "ers/config/activedirectory/versioninfo"

class adminUser (object):

    """
    """

    def get_ById(self,id1):
        return "ers/config/adminuser/" + id1

    getAll = "ers/config/adminuser"
    getVersion = "ers/config/adminuser/versioninfo"

class advancedCustomization(object):

    """
    Using this global setting we can customize the text that is displayed in ISE portals. This global setting controls whether HTML alone or both HTML and Javascript are permitted to be used in customized text. In this documentation, for each available API you will find the request syntax including the required headers and a response example of a successful flow.
    """
    def get_ById(self,id1):
        return "ers/config/portalglobalsetting/" + id1

    def putUpdate_ById(self,id1):
        return "ers/config/portalglobalsetting/" + id1

    getAll = "ers/config/portalglobalsetting"
    getVersion = "ers/config/portalglobalsetting/versioninfo"

class allowedProtocols(object):

    """
    Allowed Protocols API allows the client to add, delete, update, search and perform actions on allowed protocols. In this documentation, for each available API you will find the request syntax including the required headers and a response example of a successful flow.
    """
    def get_ByName(self,name):
        return "ers/config/allowedprotocols/name/" + name

    def get_ById(self, id1):
        return "ers/config/allowedprotocols/name/" + id1

    def putUpdate_ById(self,id1):
        return "ers/config/allowedprotocols/" + id1

    postCreate = "ers/config/allowedprotocols"
    getAll = "ers/config/allowedprotocols"

class authorizationProfile(object):

    """
    Authorization Profile API allows the client to add, delete, update, search and perform actions on authorization profiles. In this documentation, for each available API you will find the request syntax including the required headers and a response example of a successful flow.
    """
    def get_ByName(self,name):
        return "ers/config/authorizationprofile/name/" + name

    def get_ById(self,id1):
        return "ers/config/authorizationprofile/" + id1

    def putUpdate_ById(self,id1):
        return "ers/config/authorizationprofile/" + id1

    def delete_ById(self,id1):
        return "ers/config/authorizationprofile/" + id1

    postCreate = "ers/config/authorizationprofile"
    getAll = "ers/config/authorizationprofile"
    getVersion = "ers/config/authorizationprofile/versioninfo"

class byodPortal(object):

    """
    BYOD Portal API provides the ability to Create, Read, Update, Delete and Search byod portals. In this documentation, for each available API you will find the request syntax including the required headers and a response example of a successful flow.
    """
    def get_ById(self,id1):
        return "ers/config/byodportal/" + id1

    def putUpdate_ById(self,id1):
        return "ers/config/byodportal/" + id1

    def delete_ById(self,id1):
        return "ers/config/byodportal/" + id1

    postCreate = "ers/config/byodportal"
    getAll = "ers/config/byodportal"
    getVersion = "ers/config/byodportal/versioninfo"

class certificateTemplate(object):

    """
    Certificate Template API provides the ability to search certificate templates.
    """
    def get_ByName(self,userName):
        return "ers/config/certificatetemplate/name/" + userName

    def get_ById(self, id1):
        return "ers/config/certificatetemplate/" + id1

    getAll = "ers/config/certificatetemplate"
    getVersion = "ers/config/certificatetemplate/versioninfo"

class clearThreatsAndVuln(object):

    """
    Allows the user to delete the ThreatContext and Threat events that are associated with the given MacAddress.
    """

    putClearThreatsAndVuln = "ers/config/threat/clearThreatsAndVulneribilities"
    getVersion = "ers/config/threat/versioninfo"

class downloadableACL(object):

    """
    Downloadable ACL API allows the client to add, delete, update, search and perform actions on Downloadable ACL. In this documentation, for each available API you will find the request syntax including the required headers and a response example of a successful flow.
    """
    def get_ById(self,id1):
        return "ers/config/downloadableacl/" + id1

    def putUpdate_ById(self,id1):
        return "ers/config/downloadableacl/" + id1

    def delete_ById(self,id1):
        return "ers/config/downloadableacl/" + id1

    postCreate = "ers/config/downloadableacl"
    getAll = "ers/config/downloadableacl"
    getVersion = "ers/config/downloadableacl/versioninfo"

class egressMatrixCell(object):

    """
    Egress Policy Matrix Cell API allows the client to add,update,delete and search EgressMatrixCell(s) among other Operation . In this documentation, for each available API you will find the request syntax including the required headers and a response example of a successful flow.
    """
    def putCloneCell(self,id1,srcSGT,dstSGT):
        return "ers/config/egressmatrixcell/clonecell/" + id1 + "/srcSgt/" + srcSGT + "/dstSgt/" + dstSGT

    def putSetAllCells_ByStatus(self,status):
        return "ers/config/egressmatrixcell/status/" + status

    def get_ById(self,id1):
        return "ers/config/egressmatrixcell/" + id1

    def putUpdate_ById(self,id1):
        return "ers/config/egressmatrixcell/" + id1

    def delete_ById(self,id1):
        return "ers/config/egressmatrixcell/" + id1

    def getMonitorBulkStatus_ById(self,id1):
        return "ers/config/egressmatrixcell/bulk/" + id1

    putClearAllMatrixCells = "ers/config/egressmatrixcell/clearallmatrixcells"
    postCreate = "ers/config/egressmatrixcell"
    getAll = "ers/config/egressmatrixcell"
    getVersion = "ers/config/egressmatrixcell/versioninfo"
    putBulkRequest = "ers/config/egressmatrixcell/bulk/submit"

class endPoint(object):

    """
    Endpoint API allows the client to add, delete, update, search, register and de-register Endpoints. In this documentation, for each available API you will find the request syntax including the required headers and a response example of a successful flow. Please note that each API description shows weather the API is supported in bulk operation. The Bulk section is showing only 'create' bulk operation however, all other operation which are bulk supported can be used in same way.
    """
    def putDeRegister_ById(self,id1):
        return "ers/config/endpoint/" + id1 + "/deregister"

    def putReleaseRejectedEndpoints_ById(self,id1):
        return "ers/config/endpoint/" + id1 + "/releaserejectedendpoint"

    def get_ById(self,id1):
        return "ers/config/endpoint/" + id1

    def putUpdate_ById(self,id1):
        return "ers/config/endpoint/" + id1

    def delete_ById(self,id1):
        return "ers/config/endpoint/" + id1

    def getMonitorBulkStatus_ById(self,id1):
        return "/ers/config/endpoint/bulk/" + id1

    getRejectedEndpoints = "ers/config/endpoint/getrejectedendpoints"
    putRegister = "ers/config/endpoint/register"
    postCreate = "ers/config/endpoint"
    getAll = "ers/config/endpoint"
    getVersion = "ers/config/endpoint/versioninfo"
    putBulkRequest = "ers/config/endpoint/bulk/submit"

class endPointCert(object):

    """
    Certificate Authority API for creating End Point Certificates signed by the ISE Internal CA. This API can take in certificate request details, create an RSA key pair, create a certificate and return the resulting key pair and certificate as a ZIP file. ZIP files are returned as an octet stream.
    """

    putCreateCertificate = "ers/config/endpointcert/certRequest"
    getVersion = "ers/config/endpointcert/versioninfo"

class endPointIdentityGroup(object):

    """
    Endpoint Identity Groups API allows the client to add, delete, update, and search Endpoint Groups. In this documentation, for each available API you will find the request syntax including the required headers and a response example of a successful flow.
    """
    def get_ById(self,id1):
        return "ers/config/endpointgroup/" + id1

    def putUpdate_ById(self,id1):
        return "ers/config/endpointgroup/" + id1

    def delete_ById(self,id1):
        return "ers/config/endpointgroup/" + id1

    postCreate = "ers/config/endpointgroup"
    getAll = "ers/config/endpointgroup"
    getVersion = "ers/config/endpointgroup/versioninfo"

class externalRadiusServer(object):

    """
    External Radius Server API allows the client to add, delete, update, search and perform actions on external radius server. In this documentation, for each available API you will find the request syntax including the required headers and a response example of a successful flow.
    """
    def get_ByName(self,name):
        return "ers/config/externalradiusserver/name/" + name

    def get_ById(self,id1):
        return "ers/config/externalradiusserver/" + id1

    def putUpdate_ById(self,id1):
        return "ers/config/externalradiusserver/" + id1

    def delete_ById(self,id1):
        return "ers/config/externalradiusserver/" + id1

    postCreate = "ers/config/externalradiusserver"
    getAll = "ers/config/externalradiusserver"
    getVersion = "ers/config/externalradiusserver/versioninfo"

class guestLocation(object):

    """
    Guest Location API allows the client to Search the Locations configured from ISE GUI interface. In this documentation, for each available API you will find the request syntax including the required headers and a response example of a successful flow.
    """
    def get_ById(self,id1):
        return "ers/config/guestlocation/" + id1

    getAll = "ers/config/guestlocation/"
    getVersion = "ers/config/guestlocation/versioninfo"

class getSMTPNotification(object):

    """
    Guest SMTP notification settings is a global settings for enabling email notifications within guest application. These apis allow to create / update / retrieve the notification settings. The create API may not be required to be used as of ISE v 2.2 - this is because the single SMTP notification configuration that is the only one used, always gets created during the ISE application initialization period.
    """
    def get_ById(self,id1):
        return "ers/config/guestsmtpnotificationsettings/" + id1

    def putUpdate_ById(self,id1):
        return "ers/config/guestsmtpnotificationsettings/" + id1

    PostCreate = "ers/config/guestsmtpnotificationsettings"
    getAll = "ers/config/guestsmtpnotificationsettings"
    getVersion = "ers/config/guestsmtpnotificationsettings/versioninfo"

class guestSSID(object):

    """
    Guest SSIDs are global objects that are referenced by ISE sponsor portals. Guest SSID API allows the client to add, delete, update and search Guest SSID among other Operation which are available from the all Portal. In this documentation, for each available API you will find the request syntax including the required headers and a response example of a successful flow.
    """
    def get_ById(self,id1):
        return "ers/config/guestssid/" + id1

    def putUpdate_ById(self,id1):
        return "ers/config/guestssid/" + id1

    def delete_ById(self,id1):
        return "ers/config/guestssid/" + id1

    postCreate = "ers/config/guestssid"
    getAll = "ers/config/guestssid"
    getVersion = "ers/config/guestssid/versioninfo"

class guestType(object):

    """
    Guest Type API allows the client to add, delete, update and search Guest Types. In this documentation, for each available API you will find the request syntax including the required headers and a response example of a successful flow.
    """
    def putEmail_ById(self,id1):
        return "ers/config/guesttype/email/" + id1

    def putSMS_byId(self,id1):
        return "ers/config/guesttype/sms/" + id1

    def get_ById(self,id1):
        return "ers/config/guesttype/" + id1

    def putUpdate_ById(self,id1):
        return "ers/config/guesttype/" + id1

    def delete_ById(self,id1):
        return "ers/config/guesttype/" + id1

    postCreate = "ers/config/guesttype"
    getAll = "ers/config/guesttype"
    getVersion = "ers/config/guesttype/versioninfo"

class guestUser(object):

    """
    Guest User API allows the client to add, delete, update and search Guest Users among other Operation which are available from the Sponsor Portal. In this documentation, for each available API you will find the request syntax including the required headers and a response example of a successful flow. Please note that each API description shows weather the API is supported in bulk operation. The Bulk section is showing only 'create' bulk operation however, all other operation which are bulk supported can be used in same way.
    """
    def get_ByName(self,name):
        return "ers/config/guestuser/name/" + name

    def putDeny_ById(self,id1):
        return "ers/config/guestuser/deny/" + id1

    def delete_ByName(self,name):
        return "ers/config/guestuser/name/" + name

    def putReinstate_ById(self,id1):
        return "ers/config/guestuser/reinstate/" + id1

    def putApprove_ById(self,id1):
        return "ers/config/guestuser/approve/" + id1

    def putEmail(self,email,portal):
        return "ers/config/guestuser/email/" + email + "/portalId/" + portal

    def putUpdate_ByName(self,name):
        return "ers/config/guestuser/name/" + name

    def putSMS_ById(self,id1):
        return "ers/config/guestuser/sms/" + id1

    def changeSponsorPassword_ByPortalId(self,portal):
        return "ers/config/guestuser/changeSponsorPassword/" + portal

    def putSuspend_ByName(self,name):
        return "ers/config/guestuser/suspend/name/" + name

    def putReinstate_ByName(self,name):
        return "ers/config/guestuser/reinstate/name/" + name

    def putResetPassword_ById(self,id1):
        return "ers/config/guestuser/resetpassword/" + id1

    def get_ById(self,id1):
        return "ers/config/guestuser/" + id1

    def putUpdates_ById(self,id1):
        return "ers/config/guestuser/" + id1

    def delete_ById(self,id1):
        return "ers/config/guestuser/" + id1

    def putSuspend_ById(self,id1):
        return "ers/config/guestuser/suspend/" + id1

    def getMonitorBulkStatus_ById(self,id1):
        return "ers/config/guestuser/bulk/"+ id1

    postCreate = "ers/config/guestuser"
    getAll = "ers/config/guestuser"
    getVersion = "ers/config/guestuser/versioninfo"
    putBulkRequest = "ers/config/guestuser/bulk/submit"

class hotspotPortal(object):

    """
    HotSpot Guest Portal API provides the ability to Create, Read, Update, Delete and Search HotSpot Guest Portals. In this documentation, for each available API you will find the request syntax including the required headers and a response example of a successful flow.
    """
    def get_ById(self,id1):
        return "ers/config/hotspotportal/" + id1

    def putUpdate_ById(self,id1):
        return "ers/config/hotspotportal/" + id1

    def delete_ById(self,id1):
        return "ers/config/hotspotportal/" + id1

    postCreate = "ers/config/hotspotportal"
    getVersion = "ers/config/hotspotportal/versioninfo"

class ipSgtMapping(object):

    """
    IP To SGT Mapping API allows the client to add, delete, update, search and deploy IP to SGT Mapping. In this documentation, for each available API you will find the request syntax including the required headers and a response example of a successful flow.
    """
    def getDeploy_ById(self,id1):
        return "ers/config/sgmapping/" + id1 + "/deploy"

    def get_ById(self,id1):
        return "ers/config/sgmapping/" + id1

    def putUpdate_ById(self,id1):
        return "ers/config/sgmapping/" + id1

    def delete_ById(self,id1):
        return "ers/config/sgmapping/" + id1

    def getMonitorBulkStatus_ById(self,id1):
        return "ers/config/sgmapping/bulk/" + id1

    postCreate = "ers/config/sgmapping"
    getAll = "ers/config/sgmapping"
    getVersion = "ers/config/sgmapping/versioninfo"
    putBulkRequest = "ers/config/sgmapping/bulk/submit"

class ipSgtMappingGroup(object):

    """
    IP To SGT Mapping Group API allows the client to add, delete, update, search and deploy IP to SGT Mapping Groups. In this documentation, for each available API you will find the request syntax including the required headers and a response example of a successful flow.
    """
    def putDeploy_ById(self,id1):
        return "ers/config/sgmappinggroup/" + id1 + "/deploy"

    def get_ById(self,id1):
        return "ers/config/sgmappinggroup/" + id1

    def putUpdate_ById(self,id1):
        return "ers/config/sgmappinggroup/" + id1

    def delete_ById(self,id1):
        return "ers/config/sgmappinggroup/" + id1

    def getMonitorBulkStatus_ById(self,id1):
        return "ers/config/sgmappinggroup/bulk/" + id1

    putDeployAll = "ers/config/sgmappinggroup/deployall"
    getDeployStatus = "ers/config/sgmappinggroup/deploy/status"
    postCreate = "ers/config/sgmappinggroup"
    getAll = "ers/config/sgmappinggroup"
    getVersion = "ers/config/sgmappinggroup/versioninfo"
    putBulkRequest = "ers/config/sgmappinggroup/bulk/submit"

class iseServiceInfo(object):

    """
    Please update the file: WEB-INF/classes/com/cisco/cpm/ers/sdk-resources.properties with the following key: feature.service.description
    """
    def get_ByName(self,name):
        return "ers/config/service/" + name

    getAll = "ers/config/service"
    getVersion = "ers/config/service/versioninfo"

class identityGroup(object):

    """
    Identity Groups API allows the client to search Identity Groups. In this documentation, for each available API you will find the request syntax including the required headers and a response example of a successful flow.
    """
    def get_ById(self,id1):
        return "ers/config/identitygroup/" + id1

    getAll = "ers/config/identitygroup"
    getVersion = "ers/config/identitygroup/versioninfo"

class identitySequence(object):

    """
    Id Sequence API allows the client to add, delete, update and search Id sequences. In this documentation, for each available API you will find the request syntax including the required headers and a response example of a successful flow.
    """
    def get_ById(self,id1):
        return "ers/config/idstoresequence/" + id1

    def putUpdate_ById(self,id1):
        return "ers/config/idstoresequence/" + id1

    def delete_ById(self,id1):
        return "ers/config/idstoresequence/" + id1

    getAll = "ers/config/idstoresequence"
    getVersion = "ers/config/idstoresequence/versioninfo"

class internalUser(object):

    """
    Internal User API allows the client to add, delete, update and search Internal Users. In this documentation, for each available API you will find the request syntax including the required headers and a response example of a successful flow.
    """
    def get_ById(self,id1):
        return "ers/config/internaluser/" + id1

    def putUpdate_ById(self,id1):
        return "ers/config/internaluser/" + id1

    def delete_ById(self,id1):
        return "ers/config/internaluser/" + id1

    postCreate = "ers/config/internaluser"
    getAll = "ers/config/internaluser"
    getVersion = "ers/config/internaluser/versioninfo"

class myDevicePortal(object):

    """
    My Device Portal API provides the ability to Create, Read, Update, Delete and Search my device portals. In this documentation, for each available API you will find the request syntax including the required headers and a response example of a successful flow.
    """
    def get_ById(self,id1):
        return "ers/config/mydeviceportal/" + id1

    def putUpdate_ById(self,portal):
        return "ers/config/mydeviceportal/" + portal

    def delete_ById(self,portal):
        return "ers/config/mydeviceportal/" + portal

    postCreate = "ers/config/mydeviceportal"
    getAll = "ers/config/mydeviceportal"
    getVersion = "ers/config/mydeviceportal/versioninfo"

class nativeSupplicantProfile(object):

    """
    Native supplicant profile API provides the ability to update, delete and search native supplicant profiles.
    """
    def get_ById(self,id1):
        return "ers/config/nspprofile/" + id1

    def putUpdate_ById(self,id1):
        return "ers/config/nspprofile/" + id1

    def delete_ById(self,id1):
        return "ers/config/nspprofile/" + id1

    getAll = "ers/config/nspprofile/"
    getVersion = "ers/config/nspprofile/versioninfo"

class networkDevice(object):

    """
    Network Device API allows the client to add, delete, update, and search Network Devices. In this documentation, for each available API you will find the request syntax including the required headers and a response example of a successful flow. Please note that each API description shows weather the API is supported in bulk operation. The Bulk section is showing only 'create' bulk operation however, all other operation which are bulk supported can be used in same way.
    """
    def get_ById(self,id1):
        return "ers/config/networkdevice/" + id1

    def putUpdate_ById(self,id1):
        return "ers/config/networkdevice/" + id1

    def delete_ById(self,id1):
        return "ers/config/networkdevice/" + id1

    def getMonitorBulkStatus_ById(self,id1):
        return "ers/config/networkdevice/bulk/" + id1

    postCreate = "ers/config/networkdevice"
    getAll = "ers/config/networkdevice"
    getVersion = "ers/config/networkdevice/versioninfo"
    putBulkRequest = "ers/config/networkdevice/bulk/submit"

class networkDeviceGroup(object):

    """
    Network Device Group API allows the client to search Network Device Groups. In this documentation, for each available API you will find the request syntax including the required headers and a response example of a successful flow.
    """
    def get_ById(self,id1):
        return "ers/config/networkdevicegroup/" + id1

    def putUpdate_ById(self,id1):
        return "ers/config/networkdevicegroup/" + id1

    def delete_ById(self,id1):
        return "ers/config/networkdevicegroup/" + id1

    postCreate = "ers/config/networkdevicegroup"
    getAll = "ers/config/networkdevicegroup"
    getVersion = "ers/config/networkdevicegroup/versioninfo"

class nodeDetails(object):

    """
    Please update the file: WEB-INF/classes/com/cisco/cpm/ers/sdk-resources.properties with the following key: deploy.node.description
    """
    def get_ByName(self,name):
        return "ers/config/node/name/" + name

    def get_ById(self,id1):
        return "ers/config/node/" + id1

    getAll = "ers/config/node"
    getVersion = "ers/config/node/versioninfo"

class psnNodeDetails(object):

    """
    Please update the file: WEB-INF/classes/com/cisco/cpm/ers/sdk-resources.properties with the following key: deploy.sessionservicenode.description
    """
    def get_ByName(self,name):
        return "ers/config/sessionservicenode/name/" + name

    def get_ById(self,id1):
        return "ers/config/sessionservicenode/" + id1

    getAll = "ers/config/sessionservicenode"
    getVersion = "ers/config/sessionservicenode/versioninfo"

class portal(object):

    """
    Portal API allows the client to search Profiles. In this documentation, for each available API you will find the request syntax including the required headers and a response example of a successful flow.
    """
    def get_ById(self,id1):
        return "ers/config/portal/" + id1

    getAll = "ers/config/portal"
    getVersion = "ers/config/portal/versioninfo"

class portalTheme(object):

    """
    Portal Theme API allows the client to add, delete, update and search Portal Theme among other Operation which are available from the all Portal. In this documentation, for each available API you will find the request syntax including the required headers and a response example of a successful flow.
    """
    def get_ById(self,id1):
        return "ers/config/portaltheme/" + id1

    def putUpdate_ById(self,id1):
        return "ers/config/portaltheme/" + id1

    def delete_ById(self,id1):
        return "ers/config/portaltheme/" + id1

    postCreate = "ers/config/portaltheme"
    getAll = "ers/config/portaltheme"
    getVersion = "ers/config/portaltheme/versioninfo"

class profilerProfile(object):

    """
    Profiler Profile API allows the client to search Profiles. In this documentation, for each available API you will find the request syntax including the required headers and a response example of a successful flow.
    """
    def get_ById(self,id1):
        return "ers/config/profilerprofile/" + id1

    getAll = "ers/config/profilerprofile"
    getVersion = "ers/config/profilerprofile"

class radiusServerSequence(object):

    """
    Radius Server Sequence API allows the client to add, delete, update, search and perform actions on radius server sequence. In this documentation, for each available API you will find the request syntax including the required headers and a response example of a successful flow.
    """
    def get_ById(self,id1):
        return "ers/config/radiusserversequence/" + id1

    def putUpdate_ById(self,id1):
        return "ers/config/radiusserversequence/" + id1

    def delete_ById(self,id1):
        return "ers/config/radiusserversequence/" + id1

    postCreate = "ers/config/radiusserversequence"
    getAll = "ers/config/radiusserversequence"
    getVersion = "ers/config/radiusserversequence/versioninfo"

class smsServer(object):

    """
    SMS Provider API allows the client to Search the SMS Providers configured from ISE GUI interface. In this documentation, for each available API you will find the request syntax including the required headers and a response example of a successful flow.
    """
    def get_ById(self,id1):
        return "ers/config/smsprovider/" + id1

    getAll = "ers/config/smsprovider/"
    getVersion = "ers/config/smsprovider/versioninfo"

class sxpConnections(object):

    """
    Please update the file: WEB-INF/classes/com/cisco/cpm/ers/sdk-resources.properties with the following key: sxp.sxpconnections.description
    """
    def get_ById(self,id1):
        return "ers/config/sxpconnections/" + id1

    def putUpdate_ById(self,id1):
        return "ers/config/sxpconnections/" + id1

    def delete_ById(self,id1):
        return "ers/config/sxpconnections/" + id1

    def getMonitorBulkStatus_ById(self,id1):
        return "ers/config/sxpconnections/bulk/" + id1

    postCreate = "ers/config/sxpconnections"
    getAll = "ers/config/sxpconnections"
    getVersion = "ers/config/sxpconnections/versioninfo"
    putBulkRequest = "ers/config/sxpconnections/bulk/submit"

class sxpLocalBindings(object):

    """
    Please update the file: WEB-INF/classes/com/cisco/cpm/ers/sdk-resources.properties with the following key: sxp.sxplocalbindings.description
    """
    def get_ById(self,id1):
        return "ers/config/sxplocalbindings/" + id1

    def putUpdate_ById(self,id1):
        return "ers/config/sxplocalbindings/" + id1

    def delete_ById(self,id1):
        return "ers/config/sxplocalbindings/" + id1

    def getMonitorBulkStatus_ById(self,id1):
        return "ers/config/sxplocalbindings/bulk/" + id1

    postCreate = "ers/config/sxplocalbindings"
    getAll = "ers/config/sxplocalbindings"
    getVersion = "ers/config/sxplocalbindings/versioninfo"
    putBulkRequest = "ers/config/sxplocalbindings/bulk/submit"

class sxpVpns(object):

    """
    Please update the file: WEB-INF/classes/com/cisco/cpm/ers/sdk-resources.properties with the following key: sxp.sxpvpns.description
    """
    def get_ById(self,id1):
        return "ers/config/sxpvpns/" + id1

    def delete_ById(self,id1):
        return "ers/config/sxpvpns/" + id1

    def getMonitorBulkStatus_ById(self,id1):
        return "ers/config/sxpvpns/bulk/" + id1

    postCreate = "ers/config/sxpvpns"
    getAll = "ers/config/sxpvpns"
    getVersion = "ers/config/sxpvpns/versioninfo"
    putBulkRequest = "ers/config/sxpvpns/bulk/submit"

class securityGroups(object):

    """
    Sgt API allows the client to search SGTs. In this documentation, for each available API you will find the request syntax including the required headers and a response example of a successful flow.
    """
    def get_ById(self,id1):
        return "ers/config/sgt/" + id1

    def putUpdate_ById(self,id1):
        return "ers/config/sgt/" + id1

    def delete_ById(self,id1):
        return "ers/config/sgt/" + id1

    def getMonitorBulkStatus_ById(self,id1):
        return "ers/config/sgt/bulk/" + id1

    postCreate = "ers/config/sgt"
    getAll = "ers/config/sgt"
    getVersion = "ers/config/sgt/versioninfo"
    putBulkRequest = "ers/config/sgt/bulk/submit"

class securityGroupAcls(object):

    """
    Please update the file: WEB-INF/classes/com/cisco/cpm/ers/sdk-resources.properties with the following key: trustsec.sgacl.description
    """
    def get_ById(self,id1):
        return "ers/config/sgacl/" + id1

    def putUpdate_ById(self,id1):
        return "ers/config/sgacl/" + id1

    def delete_ById(self,id1):
        return "ers/config/sgacl/" + id1

    def getMonitorBulkStatus_ById(self,id1):
        return "ers/config/sgacl/bulk/" + id1

    postCreate = "ers/config/sgacl"
    getAll = "ers/config/sgacl"
    getVersion = "ers/config/sgacl/versioninfo"
    putBulkRequest = "ers/config/sgacl/bulk/submit"

class securityGroupsVirtualNetworks(object):

    """
    Sgt mapping to virtual networks which are mapped to referenced vlan, these constructs come from out side of ISE and are not CRUDable inside ISE.
    """
    def get_ById(self,id1):
        return "ers/config/sgtvnvlan/" + id1

    def putUpdate_ById(self,id1):
        return "ers/config/sgtvnvlan/" + id1

    def delete_ById(self,id1):
        return "ers/config/sgtvnvlan/" + id1

    def getMonitorBulkStatus_ById(self,id1):
        return "ers/config/sgtvnvlan/bulk/" + id1

    postCreate = "ers/config/sgtvnvlan"
    getAll = "ers/config/sgtvnvlan"
    getVersion = "ers/config/sgtvnvlan/versioninfo"
    putBulkRequest = "ers/config/sgtvnvlan/bulk/submit"

class selfRegisteredPortal(object):

    """
    Self Registered Guest Portal API provides the ability to Create, Read, Update, Delete and Search Self Registered Portals. In this documentation, for each available API you will find the request syntax including the required headers and a response example of a successful flow.
    """
    def get_ById(self,portal):
        return "ers/config/selfregportal/" + portal

    def putUpdate_ById(self,portal):
        return "ers/config/selfregportal/" + portal

    def delete_ById(self,portal):
        return "ers/config/selfregportal/" + portal

    postCreate = "ers/config/selfregportal"
    getAll = "ers/config/selfregportal"
    getVersion = "ers/config/selfregportal/versioninfo"

class sponsorGroup(object):

    """
    Sponsor Group API allows the client to add, delete, update and search Sponsor Groups. In this documentation, for each available API you will find the request syntax including the required headers and a response example of a successful flow.
    """
    def get_ById(self,id1):
        return "ers/config/sponsorgroup/" + id1

    def putUpdate_ById(self,id1):
        return "ers/config/sponsorgroup/" + id1

    def delete_ById(self,id1):
        return "ers/config/sponsorgroup/" + id1

    postCreate = "ers/config/sponsorgroup"
    getAll = "ers/config/sponsorgroup"
    getVersion = "ers/config/sponsorgroup/versioninfo"

class sponsorGroupMember(object):

    """
    Sponsor Group API allows the client to Search the Group Members from different Identity Stores configured in GUI. In this documentation, for each available API you will find the request syntax including the required headers and a response example of a successful flow.
    """
    def get_ById(self,id1):
        return "ers/config/sponsorgroupmember/" + id1

    getAll = "ers/config/sponsorgroupmember"
    getVersion = "ers/config/sponsorgroupmember/versioninfo"

class sponsorPortal(object):

    """
    Sponsor Portal API provides the ability to Create, Read, Update, Delete and Search sponsor portals. In this documentation, for each available API you will find the request syntax including the required headers and a response example of a successful flow.
    """
    def get_ById(self,portal):
        return "ers/config/sponsorportal/" + portal

    def putUpdate_ById(self,portal):
        return "ers/config/sponsorportal/" + portal

    def delete_ById(self,portal):
        return "ers/config/sponsorportal/" + portal

    postCreate = "ers/config/sponsorportal"
    getAll = "ers/config/sponsorportal"
    getVersion = "ers/config/sponsorportal/versioninfo"

class sponsordGuestPortal(object):

    """
    Sponsored Guest Portal API provides the ability to Create, Read, Update, Delete and Search sponsored guest portals. In this documentation, for each available API you will find the request syntax including the required headers and a response example of a successful flow.
    """
    def get_ById(self,portal):
        return "ers/config/sponsoredguestportal/" + portal

    def putUpdate_ById(self,portal):
        return "ers/config/sponsoredguestportal/" + portal

    def delete_ById(self,portal):
        return "ers/config/sponsoredguestportal/" + portal

    postCreate = "ers/config/sponsoredguestportal"
    getAll = "ers/config/sponsoredguestportal"
    getVersion = "ers/config/sponsoredguestportal/versioninfo"

#These are the Regular API calls.

class sessionMgmt(object):

    """
    These are the Session Management APIs as listed at https://www.cisco.com/c/en/us/td/docs/security/ise/2-1/api_ref_guide/api_ref_book/ise_api_ref_ch1.html
    """

    activeCount = "/admin/API/mnt/Session/ActiveCount"
    postureCount = "/admin/API/mnt/Session/PostureCount"
    profilerCount = "/admin/API/mnt/Session/ProfilerCount"
    activeList = "/admin/API/mnt/Session/ActiveList"

    def authList(self,parameterOptions):
            return "/admin/API/mnt/Session/AuthList/" + parameterOptions
    def macAddress(self,macAddr):
            return "/admin/API/mnt/Session/MACAddress/" + macAddr
    def userNameList(self,username):
            return "/admin/API/mnt/Session/UserName/" + username
    def ipAddress(self,ipAddr):
            return "/admin/API/mnt/Session/IPAddress/" + ipAddr
    def endpointIpAddress(self,ipAddr):
            return "/admin/API/mnt/Session/EndPointIPAddress/" + ipAddr
    def auditSession(self,sessionID):
            return "/admin/API/mnt/Session/Active/SessionID/" + sessionID + "/0"

class troubleshootCalls(object):

    """
    These are the Troubleshooting APIs as listed at https://www.cisco.com/c/en/us/td/docs/security/ise/2-1/api_ref_guide/api_ref_book/ise_api_ref_ch1.html
    """

    mntVersion = "/admin/API/mnt/Version"
    failureReasons = "/admin/API/mnt/FailureReasons"

    def authStatus(self,macAddr,noOfSecs,noOfRecords):
            return "/admin/API/mnt/AuthStatus/MACAddress/" + macAddr + "/" + noOfSecs + "/" + noOfRecords + "/All"
    def acctStatus(self,macAddr,noOfSecs):
            return "/admin/API/mnt/AcctStatusTT/MACAddress/" + macAddr + "/" + noOfSecs

class coaCalls(object):

    """
    These are the CoA APIs as listed at https://www.cisco.com/c/en/us/td/docs/security/ise/2-1/api_ref_guide/api_ref_book/ise_api_ref_ch1.html
    """

    def reauth(self,server,macAddr,reauthtype,nasipaddress,destinationipaddress):
        return "/admin/API/mnt/CoA/Reauth/" + server + "/" + macAddr + "/" + reauthtype + "/" + nasipaddress + "/" + destinationipaddress

    def disconnect(self,server,macAddr,reauthtype,nasipaddress,destinationipaddress):
        return "/admin/API/mnt/CoA/Disconnect/" + server + "/" + macAddr + "/" + reauthtype + "/" + nasipaddress + "/" + destinationipaddress
