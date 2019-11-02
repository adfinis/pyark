#--------------------------------------------------------------------------------------------------------
# pyARK - adapted from https://github.com/adfinis-sygroup/pyark
#
# Python module for calling the Cyberark REST API
# Cyberark REST API Version 9.8
#--------------------------------------------------------------------------------------------------------
#

import json
import logging
import requests
import inspect

# Disable the warning messages for turning off SSL cert validation
# Note this does NOT turn off SSL cert validation, just the warning messages if you choose to
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning) 

logger = logging.getLogger(__name__)

class vaultConnector:

    """Handles the authentication against the API and calls the appropriate API
    endpoints.
    """

    def __init__(self, base_url, verify=False):
        """Sends the data to the API endpoint using the appropriate HTTP method.
        self        <object>     Object instances
        base_url    <string>     Base URL for Cyberark REST API Server
        verify      <bool>       Disable SSL Server Certificate Verification
        """
        logger.debug('Initialize vaultConnector')
        self.base_url = base_url
        self.user = None
        self.password = None
        self.session_token = None
        self.verify=verify
        self.cookies=None

    def call(self, http_method, api_endpoint, params={}):
        """Sends the data to the API endpoint using the appropriate HTTP method.
        http_method     <string>     HTTP method to use, e.g. POST
        api_endpoint    <string>     Target API endpoint
        params          <dict>       Payload to send with the request
        """

        headers = {}
        ret = None

        if self.session_token is not None:
            headers = {"Authorization": self.session_token}

        logger.debug('Call params: %s, %s' % (api_endpoint, params))
        try:
            url = "%s/Passwordvault/WebServices/%s" % (self.base_url,
                                                       api_endpoint)
            logger.debug('Request %s URL: %s' % (http_method, url))
            if http_method == "GET":
                ret = requests.get(
                    url     = url,
                    params  = params,
                    timeout = 30,
                    verify  = self.verify,
                    headers = headers,
                    cookies = self.cookies
                )
            elif http_method == "POST":
                ret = requests.post(
                    url     = url,
                    json    = params,
                    timeout = 30,
                    verify  = self.verify,
                    headers = headers,
                    cookies = self.cookies
                )
            elif http_method == "PUT":
                ret = requests.put(
                    url     = url,
                    json    = params,
                    timeout = 30,
                    verify  = self.verify,
                    headers = headers,
                    cookies = self.cookies
                )
            elif http_method == "DELETE":
                ret = requests.delete(
                    url     = url,
                    timeout = 30,
                    verify  = self.verify,
                    headers = headers,
                    cookies = self.cookies
                )
            else:
                logger.error('HTTP method is missing')

            if ret.status_code is not None:
                logger.debug('Returned HTTP status: %s' % (ret.status_code))
            if ret.text is not None:
                logger.debug('Returned HTTP body: %s' % (ret.text))
            if ret.headers is not None:
                logger.debug('Returned HTTP headers: %s' % (ret.headers))
        except Exception as e:
            logger.warning('Error communicating: %s' % (e))
            raise

        return ret

    def login(self, user, password, radius=False):
        """Login into CyberArk and get the session token.
        user        <string>     UserName used for the authentication
        password    <string>     Password used for the authentication
        radius      bool        Enable/disable RADIUS authentication
        """
        logger.debug('Login called, will try to login as %s' % (user))
        params = {
            "username": user,
            "password": password
        }
        if radius:
            logger.debug('Enabling RADIUS authentication for login attempt')
            params["useRadiusAuthentication"] = "true"

        ret = self.call(
            "POST",
            "auth/Cyberark/CyberArkAuthenticationService.svc/Logon",
            params
        )

        if ret is None:
            logger.info('Login failed, API call returned %s' % (ret))
            return False

        if ret.status_code == requests.codes.ok:
            logger.info('login successful')
            payload = json.loads(ret.text)
            logger.debug('Setting session token to %s' % (
                payload['CyberArkLogonResult']))
            self.session_token = payload['CyberArkLogonResult']
            self.cookies = ret.cookies
            return True
        else:
            logger.info('Login failed, please validate your credentials '
                        '(HTTP %s)' % (ret.status_code))
            return False

    def logoff(self):
        """Logoff and destroy the session."""
        logger.debug('Logoff called, will try to logoff token %s' % (self.session_token))
        if self.session_token is None:
            logger.info('Logoff skipped, no session token available')
        else:
            ret = self.call(
                "POST",
                "auth/Cyberark/CyberArkAuthenticationService.svc/Logoff"
            )

        return test_results(inspect.currentframe().f_code.co_name, ret)

def test_results(function_name, ret):
    """Generic routine to process REST results and log messages
    function_name	string  The name of the routine passing the results
    ret             <dict>     Returned request results
    """
    if ret is None:
        logger.error(function_name+'failed, API call returned %s' % (ret))

    # If this is a call to add something then accept 201 as a valid status code
    if ret.status_code == requests.codes.ok or (function_name[0:3] == 'add' and ret.status_code == 201):
        logger.info(function_name+' successful: %s' % (ret.text))
        #return ret.text
    else:
        logger.info(function_name+' failed (HTTP %s)' % (ret.status_code))
        logger.error('API call returned %s' % (ret))
        logger.error(error_codes(ret.status_code))
            
    return ret #False

def error_codes(status_code):
    """Generic HTTP error code explanations.
    status_code int         The return code from the HTTP request
    """
    if status_code == 400:
        return 'The request could not be understood by the server due to incorrect syntax.'
    elif status_code == 401:
        return 'The request requires user authentication.'
    elif status_code == 403:
        return 'The server received and understood the request, but will not fulfill it. Authorization will not help and the request MUST NOT be repeated.'
    elif status_code == 404:
        return 'The server did not find anything that matches the Request-URI.'
    elif status_code == 405:
        return 'Method not allowed. The action requested is incompatible with the target resource selected'
    elif status_code == 409:
        return 'The request could not be completed due to a conflict with the current state of the resource.'
    elif status_code == 500:
        return 'The server encountered an unexpected condition which prevented it from fulfilling the request.'
    else:
        return 'Unknown error encountered.'

def payload(payloadType, param=None):

    if payloadType == 'add_safe' or payloadType == 'update_safe':
        payload = {"safe":{
                    "SafeName":"",
                    "Description":"",
                    "OLACEnabled":False,
                    "ManagingCPM":"PasswordManager",
                    "NumberOfVersionsRetention":30,
                    "NumberOfDaysRetention":7
                    }
        }
    elif payloadType == 'add_safe_member':
        payload = {"member":{
                    "MemberName":"",
                    "SearchIn":"",
                    "MembershipExpirationDate":"",
                    "Permissions":[
                        {"Key":"UseAccounts","Value":False},
                        {"Key":"RetrieveAccounts","Value":False},
                        {"Key":"ListAccounts","Value":False},
                        {"Key":"AddAccounts","Value":False},
                        {"Key":"UpdateAccountContent","Value":False},
                        {"Key":"UpdateAccountProperties","Value":False},
                        {"Key":"InitiateCPMAccountManagementOperations","Value":False},
                        {"Key":"SpecifyNextAccountContent","Value":False},
                        {"Key":"RenameAccounts","Value":False},
                        {"Key":"DeleteAccounts","Value":False},
                        {"Key":"UnlockAccounts","Value":False},
                        {"Key":"ManageSafe","Value":False},
                        {"Key":"ManageSafeMembers","Value":False},
                        {"Key":"BackupSafe","Value":False},
                        {"Key":"ViewAuditLog","Value":False},
                        {"Key":"ViewSafeMembers","Value":False},
                        {"Key":"RequestsAuthorizationLevel","Value":0},
                        {"Key":"AccessWithoutConfirmation","Value":False},
                        {"Key":"CreateFolders","Value":False},
                        {"Key":"DeleteFolders","Value":False},
                        {"Key":"MoveAccountsAndFolders","Value":False}
                    ]
                }
        }
    elif payloadType == 'update_safe_member':
        payload = {"member":{
                    "MembershipExpirationDate":"",
                    "Permissions":[
                        {"Key":"UseAccounts","Value":False},
                        {"Key":"RetrieveAccounts","Value":False},
                        {"Key":"ListAccounts","Value":False},
                        {"Key":"AddAccounts","Value":False},
                        {"Key":"UpdateAccountContent","Value":False},
                        {"Key":"UpdateAccountProperties","Value":False},
                        {"Key":"InitiateCPMAccountManagementOperations","Value":False},
                        {"Key":"SpecifyNextAccountContent","Value":False},
                        {"Key":"RenameAccounts","Value":False},
                        {"Key":"DeleteAccounts","Value":False},
                        {"Key":"UnlockAccounts","Value":False},
                        {"Key":"ManageSafe","Value":False},
                        {"Key":"ManageSafeMembers","Value":False},
                        {"Key":"BackupSafe","Value":False},
                        {"Key":"ViewAuditLog","Value":False},
                        {"Key":"ViewSafeMembers","Value":False},
                        {"Key":"RequestsAuthorizationLevel","Value":0},
                        {"Key":"AccessWithoutConfirmation","Value":False},
                        {"Key":"CreateFolders","Value":False},
                        {"Key":"DeleteFolders","Value":False},
                        {"Key":"MoveAccountsAndFolders","Value":False}
                    ]
                }
        }
    elif payloadType == 'add_account':
        payload = {"account":{
                    "safe":"",
                    "platformID":"",
                    "address":"",
                    "accountName":"",
                    "password":"",
                    "username":"",
                    "disableAutoMgmt":"",
                    "disableAutoMgmtReason":"",
                    "groupName":"",
                    "groupPlatformID":"",
                    "properties":[
                        {"Key":"ExtraPass1Name", "Value":""},
                        {"Key":"ExtraPass1Folder", "Value":""},
                        {"Key":"ExtraPass1Safe","Value":""},
                        {"Key":"ExtraPass3Name","Value":""},
                        {"Key":"ExtraPass3Folder","Value":""},
                        {"Key":"ExtraPass3Safe","Value":""},
                        #{"Key":"Port", "Value":""},
                    ]
                }
        }
    elif payloadType == 'update_account':
        payload = {"account":{
                    "safe":"",
                    "platformID":"",
                    "address":"",
                    "accountName":"",
                    "password":"",
                    "username":"",
                    "disableAutoMgmt":"",
                    "disableAutoMgmtReason":"",
                    "groupName":"",
                    "groupPlatformID":"",
                    "properties":[
                        {"Key":"ExtraPass1Name", "Value":""},
                        {"Key":"ExtraPass1Folder", "Value":""},
                        {"Key":"ExtraPass1Safe","Value":""},
                        {"Key":"ExtraPass3Name","Value":""},
                        {"Key":"ExtraPass3Folder","Value":""},
                        {"Key":"ExtraPass3Safe","Value":""},
                        #{"Key":"Port", "Value":""},
                    ]
                }
        }
    elif payloadType == 'add_pending_account':
        payload = {"pendingAccount":{
                    "UserName":"",
                    "Address":"",
                    "AccountDiscoveryDate":"",
                    "AccountEnabled":"",
                    "AccountOSGroups":"",
                    "AccountType":"",
                    "Domain":"",
                    "PasswordNeverExpires":False,
                    "OSVersion":"",
                    "OU":"",
                    "AccountCategory":"",
                    "UserDisplayName":"",
                    "AccountDescription":"",
                    "GID":"",
                    "UID":"",
                    "OSType":"",
                    "DiscoveryPlatformType":"",
                    "MachineOSFamily":"",
                    "LastLogonDate":"",
                    "LastPasswordSetDate":"",
                    "AccountExpirationDate":"",
                    "AccountCategoryCriteria":""
                }
        }
    elif payloadType == 'update_account_details':
        payload = {"Accounts":{
                    "Folder":"",
                    "AccountName":"",
                    "PlatformID":"",
                    "DeviceType":"",
                    "Address":"",
                    "UserName":"",
                    "GroupName":"",
                    "GroupPlatformID":"",
                    "Properties":[
                    #    {"Key":"","Value":""}
                    ]
                }
        }
    elif payloadType == 'add_user':
        payload = {"UserName":"",
                    "InitialPassword":None,
                    "Email":None,
                    "FirstName":None,
                    "LastName":None,
                    "ChangePasswordOnTheNextLogon":False,
                    "ExpiryDate":None,
                    "UserTypeName":"EPVUser",
                    "Disabled":False,
                    "Location":"\\NAB_Users"
        }
    elif payloadType == 'update_user':
        payload = {"NewPassword":"",
                    "Email":"",
                    "FirstName":"",
                    "LastName":"",
                    "ChangePasswordOnTheNextLogon":False,
                    "ExpiryDate":"",
                    "UserTypeName":"EPVUser",
                    "Disabled":False,
                    "Location":"\\NAB_Users"
        }
    elif payloadType == 'list_applications':
        payload = {"AppID":"",
                    "Location":"\Applications",
                    "IncludeSublocations":False
        }
    elif payloadType == 'add_application':
        payload = {"application":{
                    "AppID":"",
                    "Description":"",
                    "Location":"\Applications",
                    "AccessPermittedFrom":"",
                    "AccessPermittedTo":"",
                    "ExpirationDate":"",
                    "Disabled":False,
                    "BusinessOwnerFName":"",
                    "BusinessOwnerLName":"",
                    "BusinessOwnerEmail":"",
                    "BusinessOwnerPhone":""
                }
        }
    elif payloadType == 'add_application_auth_method':
        if param == "Path":
            payload = {"authentication":{
                        "AuthType":"",
                        "AuthValue":"",
                        "IsFolder":False,
                        "AllowInternalScripts":False
                    }
            }
        elif param == "Hash" or param == "Address" or param == "Certificate":
            payload = {"authentication":{
                        "AuthType":"",
                        "AuthValue":"",
                        "Comment":""
                    }
            }
        elif param == "OS":
            payload = {"authentication":{
                        "AuthType":"",
                        "AuthValue":""
                    }
            }
        else:
            payload = None
    else:
        payload = None

    return payload

#------------------------------------------------------------------------------
# APPLICATIONS
#------------------------------------------------------------------------------

def list_applications(vault, payload):
    
    ret = vault.call("GET", "PIMServices.svc/Applications", payload)
    return test_results(inspect.currentframe().f_code.co_name, ret)

def list_application(vault, AppID):

    ret = vault.call("GET", "PIMServices.svc/Applications/"+AppID)
    return test_results(inspect.currentframe().f_code.co_name, ret)

def list_application_auth_methods(vault, AppID):

    ret = vault.call("GET", "PIMServices.svc/Applications/"+AppID+"/Authentications")
    return test_results(inspect.currentframe().f_code.co_name, ret)

def add_application(vault, payload):

    ret = vault.call("POST", "PIMServices.svc/Applications", payload)
    return test_results(inspect.currentframe().f_code.co_name, ret)

def add_application_auth_method(vault, AppID, payload):

    ret = vault.call("POST", "PIMServices.svc/Applications/"+AppID+"/Authentications", payload)
    return test_results(inspect.currentframe().f_code.co_name, ret)

def delete_application(vault, AppID):

    ret = vault.call("DELETE", "PIMServices.svc/Applications/"+AppID)
    return test_results(inspect.currentframe().f_code.co_name, ret)

def delete_application_auth_method(vault, AppID, AuthID):

    ret = vault.call("DELETE", "PIMServices.svc/Applications/"+AppID+"/Authentications/"+AuthID)
    return test_results(inspect.currentframe().f_code.co_name, ret)

#------------------------------------------------------------------------------
# USER MANAGEMENT
#------------------------------------------------------------------------------

def get_user_details(vault, UserName):
    """Get user details for supplied user.
    vault       <vaultConnector>    Authenticated vault session
    UserName    <string>            User name to retrieve details for
    
    Example - Get details of specified user
    get_user_details(vault, 'TestUser1')
    """
    ret = vault.call("GET", "PIMServices.svc/Users/"+UserName)
    return test_results(inspect.currentframe().f_code.co_name, ret)

def add_user(vault, payload):
    """Add user.
    vault       <vaultConnector>    Authenticated vault session
    payload     <dict>              Refer payload function for structure
    
    Example - Add a new user
    add_user(vault, payload)
    """
    ret = vault.call("POST", "PIMServices.svc/Users", payload)
    return test_results(inspect.currentframe().f_code.co_name, ret)

def add_user_to_group(vault, UserName, GroupName):
    """Add user to a group.
    vault       <vaultConnector>    Authenticated vault session
    UserName    <string>            The name of the user to add
    GroupName   <string>            The name of the group to add to

    Example - Add a user to the specified group
    add_user_to_group(vault,'TestUser1','grp_MySafe_Owner')
    """
    ret = vault.call("POST", "PIMServices.svc/Groups/"+GroupName+"/Users",{"UserName":UserName})
    return test_results(inspect.currentframe().f_code.co_name, ret)

def update_user(vault, UserName, payload):
    """Update user.
    vault       <vaultConnector>    Authenticated vault session
    UserName    <string>            The name of the user to update
    payload     <dict>              Refer payload function for structure

    Example - Update the password for the specified user
    update_user(vault,'TestUser1',payload)
    """
    ret = vault.call("PUT", "PIMServices.svc/Users/"+UserName, payload)
    return test_results(inspect.currentframe().f_code.co_name, ret)

def delete_user(vault, UserName):
    """Delete the specified user.
    vault       <vaultConnector>    Authenticated vault session
    UserName    <string>            The name of the user to delete
    
    Example
    delete_user(vault,'TestUser1')
    """
    ret = vault.call("DELETE", "PIMServices.svc/Users/"+UserName)
    #ret = vault.call("DELETE", "PIMServices.svc/Users",{"UserName":UserName})
    return test_results(inspect.currentframe().f_code.co_name, ret)

def activate_user(vault, UserName):
    """Activate a suspended user.
    vault       <vaultConnector>    Authenticated vault session
    UserName    <string>            The name of the user to activate
    
    Example
    activate_user(vault,'TestUser1')
    """
    ret = vault.call("PUT", "PIMServices.svc/Users/"+UserName, 
        json.dumps({"Suspended":False}))
    return test_results(inspect.currentframe().f_code.co_name, ret)

def get_logged_on_user_details(vault):
    """Retrieve details about the currently logged on User.
    vault       <vaultConnector>    Authenticated vault session
    
    get_logged_on_user_details(vault)
    """
    ret = vault.call("GET", "PIMServices.svc/User")
    return test_results(inspect.currentframe().f_code.co_name, ret)

#------------------------------------------------------------------------------
# SAFE MANAGEMENT
#------------------------------------------------------------------------------

def list_safes(vault, Query=None):
    """List all safes, or if Query supplied, list safes according to the 
       supplied Query string.
    vault       <vaultConnector>    Authenticated vault session
    Query       <string>
    
    Example - Get a list of all safes
    list_safes(vault)
    
    Example - Query for a safe using a filter
    list_safes(vault,'JJ')
    """
    if Query:
        ret = vault.call("GET", "PIMServices.svc/Safes",{"Query":Query})
    else:
        ret = vault.call("GET", "PIMServices.svc/Safes")
    return test_results(inspect.currentframe().f_code.co_name, ret)

def get_safe_details(vault, SafeName):
    """Get safe details for specified safe.
    vault       <vaultConnector>    Authenticated vault session
    SafeName    <string>            The name of the safe
    
    Example - Get details of a named safe
    get_safe_details(vault,'MY_SAFE_01')
    """
    ret = vault.call("GET", "PIMServices.svc/Safes/"+SafeName)
    return test_results(inspect.currentframe().f_code.co_name, ret)

def add_safe(vault, SafeName, payload):
    """Add safe.
    vault       <vaultConnector>    Authenticated vault session
    SafeName    <string>            The name of the safe
    payload     <dict>              Refer payload function for structure
    
    Example - Add a new safe with default settings
    add_safe(vault,'MY_SAFE_01',payload)
    """
    ret = vault.call("POST", "PIMServices.svc/Safes", payload)
    return test_results(inspect.currentframe().f_code.co_name, ret)

def update_safe(vault, SafeName, payload):
    """Update details for the specified safe.
    vault       <vaultConnector>    Authenticated vault session
    SafeName    <string>            Payload to send with the request
    payload     <dict>              Refer payload function for structure
    
    Example - Update the safe description
    update_safe(vault,'MY_SAFE_01',payload)
    """
    ret = vault.call("PUT", "PIMServices.svc/Safes/"+SafeName, payload)
    return test_results(inspect.currentframe().f_code.co_name, ret)

def delete_safe(vault, SafeName):
    """Delete the specified safe.
    vault       <vaultConnector>    Authenticated vault session
    SafeName    <string>            The name of the safe
    
    Example - Get details of a named safe
    delete_safe(vault,'MY_SAFE_03')
    """
    ret = vault.call("DELETE", "PIMServices.svc/Safes/"+SafeName)
    return test_results(inspect.currentframe().f_code.co_name, ret)

def get_safe_account_groups(vault, SafeName):
    """Get safe account groups for specified safe.
    vault       <vaultConnector>    Authenticated vault session
    SafeName    <string>            The name of the safe
    
    Example - Get details of a named safe
    get_safe_account_groups(vault,'MY_SAFE_01')
    """
    ret = vault.call("GET", "PIMServices.svc/Safes/"+SafeName+"/AccountGroups")
    return test_results(inspect.currentframe().f_code.co_name, ret)

#------------------------------------------------------------------------------
# SAFE MEMBERS
#------------------------------------------------------------------------------

def list_safe_members(vault, SafeName):
    """List all safe members for the specified safe.
    vault       <vaultConnector>    Authenticated vault session
    SafeName    <string>            The name of the safe
    """
    ret = vault.call("GET", "PIMServices.svc/Safes/"+SafeName+"/Members")
    return test_results(inspect.currentframe().f_code.co_name, ret)

def add_safe_member(vault, SafeName, payload):
    """Create a new account.
    vault       <vaultConnector>    Authenticated vault session
    SafeName    <string>            The name of the safe
    payload     <dict>              Refer payload function for structure
    
    Example
    add_safe_member(vault,'TestUser1',payload)
    """
    ret = vault.call("POST", "PIMServices.svc/Safes/"+SafeName+"/Members", payload)
    return test_results(inspect.currentframe().f_code.co_name, ret)

def update_safe_member(vault, SafeName, MemberName, payload):
    """Update safe member for the specified safe.
    vault       <vaultConnector>    Authenticated vault session
    SafeName    <string>            The name of the safe
    MemberName  <string>            The name of the member to update
    payload     <dict>              Refer payload function for structure

    Example
    update_safe_member(vault,'MY_SAFE_01',payload)
    """
    ret = vault.call("PUT", "PIMServices.svc/Safes/"+SafeName+"/Members/"+MemberName, payload)
    return test_results(inspect.currentframe().f_code.co_name, ret)

def delete_safe_member(vault, SafeName, MemberName):
    """Delete safe member from the specified safe.
    vault       <vaultConnector>    Authenticated vault session
    SafeName    <string>            The name of the safe
    MemberName  <string>            The name of the member to update
    """
    ret = vault.call("DELETE", "PIMServices.svc/Safes/"+SafeName+"/Members/"+MemberName)
    return test_results(inspect.currentframe().f_code.co_name, ret)

#------------------------------------------------------------------------------
# MANAGING ACCOUNTS
#------------------------------------------------------------------------------

def add_account(vault, payload):
    """Create a new account.
    vault       <vaultConnector>    Authenticated vault session
    payload     <dict>              Refer payload function for structure

    Example
    add_account(vault, payload)
    """
    ret = vault.call("POST", "PIMServices.svc/Account", payload)
    return test_results(inspect.currentframe().f_code.co_name, ret)

def add_pending_account(vault, payload):
    """Create a new account.
    vault       <vaultConnector>    Authenticated vault session
    payload     <dict>              Refer payload function for structure

    Example
    add_pending_account(vault, payload)
    """
    ret = vault.call("POST", "PIMServices.svc/Accounts", payload)
    return test_results(inspect.currentframe().f_code.co_name, ret)

def delete_account(vault, AccountID):
    """Delete an existing account.
    vault       <vaultConnector>    Authenticated vault session
    AccountID   <string>         Account ID to change the credentials for

    Example
    delete_account(vault, '123_1')
    """
    ret = vault.call("DELETE", "PIMServices.svc/Accounts/"+AccountID)
    return test_results(inspect.currentframe().f_code.co_name, ret)

def change_credentials(vault, AccountID, ImmediateChangeByCPM="No", ChangeCredsForGroup="No"):
    """Change the credentials for the specified account.
    vault                   <vaultConnector>    Authenticated vault session
    AccountID               <string>            Account ID to change the credentials for
    ImmediateChangeByCPM    <string>            Whether the password should be changed immediately by the CPM
    ChangeCredsForGroup     <string>            Change all the passwords in an acccount group

    Example
    change_credentials(vault,'123_1',True)
    """
    ret = vault.call("PUT", "PIMServices.svc/Accounts/"+AccountID+"/ChangeCredentials",
        {"ImmediateChangeByCPM":ImmediateChangeByCPM,"ChangeCredsForGroup":ChangeCredsForGroup})
    return test_results(inspect.currentframe().f_code.co_name, ret)

def verify_credentials(vault, AccountID):
    """Create a new account.
    vault       <vaultConnector>    Authenticated vault session
    AccountID   <string>            Account ID to change the credentials for

    Example
    verify_credentials(vault,'123_1')
    """
    ret = vault.call("POST", "PIMServices.svc/Accounts/"+AccountID+"/VerifyCredentials")
    return test_results(inspect.currentframe().f_code.co_name, ret)

def get_account_value(vault, AccountID):
    """Get accounts value based on keywords.
    vault       <vaultConnector>    Authenticated vault session
    AccountID   <string>            Account ID to retrieve the value for
    
    Example
    get_account_value(vault, '123_1')
    """
    ret = vault.call("GET", "PIMServices.svc/Accounts/"+AccountID+"/Credentials")
    return test_results(inspect.currentframe().f_code.co_name, ret)

def get_account_details(vault, Keywords, Safe):
    """Get accounts based on keywords.
    vault       <vaultConnector>    Authenticated vault session
    payload     <dict>              Payload to send with the request
    
    Example
    get_account_details(vault,"TestUser1","MY_SAFE_01")
    """
    ret = vault.call("GET", "PIMServices.svc/Accounts?Keywords="+Keywords+"&Safe="+Safe)
    return test_results(inspect.currentframe().f_code.co_name, ret)

def update_account_details(vault, AccountID, payload):
    """Update specified account based on payload.  Note the payload must contain 
    existing values as well as updated values.  Missing values will be deleted.
    vault       <vaultConnector>    Authenticated vault session
    AccountID   <string>            Account ID to update the details for
    payload     <dict>              Payload to send with the request

    Example
    update_account_details(vault,'123_1',payload)
    """
    ret = vault.call("PUT", "PIMServices.svc/Accounts/"+AccountID, payload)
    return test_results(inspect.currentframe().f_code.co_name, ret)

def list_activity_by_id(vault, AccountID):
    """Get accounts based on keywords.
    vault       <vaultConnector>    Authenticated vault session
    AccountID   <string>            Account ID to retrieve the value for
    
    Example
    list_activity_by_id(vault,'123_1')
    """
    ret = vault.call("GET", "PIMServices.svc/Accounts/"+AccountID+"/Activities")
    return test_results(inspect.currentframe().f_code.co_name, ret)

#------------------------------------------------------------------------------
# ONBOARDING RULES
#------------------------------------------------------------------------------

def add_onboarding_rule(vault):
    pass

def delete_onboarding_rule(vault):
    pass

def get_onboarding_rule(vault):
    pass

#------------------------------------------------------------------------------
# ACCOUNT/ACL
#------------------------------------------------------------------------------

def add_account_acl(vault):
    pass

def delete_account_acl(vault):
    pass

def get_account_acl(vault):
    pass

#------------------------------------------------------------------------------
# POLICY/ACL
#------------------------------------------------------------------------------

def add_policy_acl(vault):
    pass

def delete_policy_acl(vault):
    pass

def get_policy_acl(vault):
    pass

#------------------------------------------------------------------------------
# SERVER WEB SERVICES
#------------------------------------------------------------------------------

def verify(vault):

    ret = vault.call("GET", "PIMServices.svc/Verify")
    return test_results(inspect.currentframe().f_code.co_name, ret)

def server(vault):

    ret = vault.call("GET", "PIMServices.svc/Server")
    return test_results(inspect.currentframe().f_code.co_name, ret)

def logo(vault, ImageType="Square"):
    
    ret = vault.call("GET", "PIMServices.svc/Logo?type="+ImageType)
    return test_results(inspect.currentframe().f_code.co_name, ret)

#
    
def toggle_debug(debug=False):
    
    # Setup logging

    if (logger.hasHandlers()):
        logger.handlers.clear()

    logger.addHandler(logging.StreamHandler())
    if debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
        
#------------------------------------------------------------------------------
# MAIN ROUTINE
#------------------------------------------------------------------------------

def main(debug=False):

    # Setup logging

    if (logger.hasHandlers()):
        logger.handlers.clear()

    logger.addHandler(logging.StreamHandler())
    if debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)



if __name__ == '__main__':
    main()
