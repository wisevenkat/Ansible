#!/usr/bin/python
# Copyright: (c) 2017, Ansible Project
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}


from ansible.module_utils._text import to_text
from ansible.module_utils.basic import AnsibleModule
import json
import requests

def permissions_admin():
    permissions_dict = [
       {"Key":"UseAccounts", "Value":true},
       {"Key":"RetrieveAccounts", "Value":true},
       {"Key":"ListAccounts", "Value":true},
       {"Key":"AddAccounts", "Value":true},
       {"Key":"UpdateAccountContent", "Value":true},
       {"Key":"UpdateAccountProperties", "Value":true},
       {"Key":"InitiateCPMAccountManagementOperations", "Value":true},
       {"Key":"SpecifyNextAccountContent", "Value":true},
       {"Key":"RenameAccounts", "Value":true},
       {"Key":"DeleteAccounts", "Value":true},
       {"Key":"UnlockAccounts", "Value":true},
       {"Key":"ManageSafe", "Value":true},
       {"Key":"ManageSafeMembers", "Value":true},
       {"Key":"BackupSafe", "Value":true},
       {"Key":"ViewAuditLog", "Value":true},
       {"Key":"ViewSafeMembers", "Value":true},
       {"Key":"RequestsAuthorizationLevel", "Value":<0/1/2>},
       {"Key":"AccessWithoutConfirmation", "Value":true},
       {"Key":"CreateFolders", "Value":true},
       {"Key":"DeleteFolders", "Value":true},
       {"Key":"MoveAccountsAndFolders", "Value":true}
    ]
    return permissions_dict
def permissions_user(permissions):
    permissions_dict = []
    if 'UseAccounts' in permissions :
       permissions_dict.append({"Key":"UseAccounts", "Value":true})
    else:
       permissions_dict.append({"Key":"UseAccounts", "Value":false})  
    if 'RetrieveAccounts' in permissions:
       permissions_dict.append({"Key":"RetrieveAccounts", "Value":true})
    else:
       permissions_dict.append({"Key":"RetrieveAccounts", "Value":false}) 

    if 'ListAccounts' in permissions:
       permissions_dict.append({"Key":"ListAccounts", "Value":true})
    else:
       permissions_dict.append({"Key":"ListAccounts", "Value":false}) 

    if 'AddAccounts' in permissions:
       permissions_dict.append({"Key":"AddAccounts", "Value":true})
    else:
       permissions_dict.append({"Key":"AddAccounts", "Value":false}) 

    if 'UpdateAccountContent' in permissions:
       permissions_dict.append({"Key":"UpdateAccountContent", "Value":true})
    else:
       permissions_dict.append({"Key":"UpdateAccountContent", "Value":false}) 

    if 'UpdateAccountProperties' in permissions:
       permissions_dict.append({"Key":"UpdateAccountProperties", "Value":true})
    else:
       permissions_dict.append({"Key":"UpdateAccountProperties", "Value":false}) 

    if 'InitiateCPMAccountManagementOperations' in permissions:
       permissions_dict.append({"Key":"InitiateCPMAccountManagementOperations", "Value":true})
    else:
       permissions_dict.append({"Key":"InitiateCPMAccountManagementOperations", "Value":false}) 
    if 'SpecifyNextAccountContent' in permissions:
       permissions_dict.append({"Key":"SpecifyNextAccountContent", "Value":true})
    else:
       permissions_dict.append({"Key":"SpecifyNextAccountContent", "Value":false}) 
    if 'RenameAccounts' in permissions:
       permissions_dict.append({"Key":"RenameAccounts", "Value":true})
    else:
       permissions_dict.append({"Key":"RenameAccounts", "Value":false})

    if 'DeleteAccounts' in permissions:
       permissions_dict.append({"Key":"DeleteAccounts", "Value":true})
    else:
       permissions_dict.append({"Key":"DeleteAccounts", "Value":false}) 
    if 'UnlockAccounts' in permissions:
       permissions_dict.append({"Key":"UnlockAccounts", "Value":true})
    else:
       permissions_dict.append({"Key":"UnlockAccounts", "Value":false}) 
    if 'ManageSafe' in permissions:
       permissions_dict.append({"Key":"ManageSafe", "Value":true})
    else:
       permissions_dict.append({"Key":"ManageSafe", "Value":false}) 
    if 'ManageSafeMembers' in permissions:
       permissions_dict.append({"Key":"ManageSafeMembers", "Value":true})
    else:
       permissions_dict.append({"Key":"ManageSafeMembers", "Value":false}) 
    if 'BackupSafe' in permissions:
       permissions_dict.append({"Key":"BackupSafe", "Value":true})
    else:
       permissions_dict.append({"Key":"BackupSafe", "Value":false}) 
    if 'ViewAuditLog' in permissions:
       permissions_dict.append({"Key":"ViewAuditLog", "Value":true})
    else:
       permissions_dict.append({"Key":"ViewAuditLog", "Value":false}) 
    if 'ManageSafeMembers' in permissions:
       permissions_dict.append({"Key":"ManageSafeMembers", "Value":true})
    else:
       permissions_dict.append({"Key":"ManageSafeMembers", "Value":false}) 

    if 'ViewSafeMembers' in permissions:
       permissions_dict.append({"Key":"ViewSafeMembers", "Value":true})
    else:
       permissions_dict.append({"Key":"ViewSafeMembers", "Value":false}) 
    #---------------------------------------------------------------------
    if 'RequestsAuthorizationLevel' in permissions:  # level required
       permissions_dict.append({"Key":"RequestsAuthorizationLevel", "Value":true})
    else:
       permissions_dict.append({"Key":"RequestsAuthorizationLevel", "Value":false}) 

    if 'AccessWithoutConfirmation' in permissions:
       permissions_dict.append({"Key":"AccessWithoutConfirmation", "Value":true})
    else:
       permissions_dict.append({"Key":"AccessWithoutConfirmation", "Value":false}) 
    if 'CreateFolders' in permissions:
       permissions_dict.append({"Key":"CreateFolders", "Value":true})
    else:
       permissions_dict.append({"Key":"CreateFolders", "Value":false})
    
    if 'DeleteFolders' in permissions:
       permissions_dict.append({"Key":"DeleteFolders", "Value":true})
    else:
       permissions_dict.append({"Key":"DeleteFolders", "Value":false}) 
    if 'MoveAccountsAndFolders' in permissions:
       permissions_dict.append({"Key":"MoveAccountsAndFolders", "Value":true})
    else:
       permissions_dict.append({"Key":"MoveAccountsAndFolders", "Value":false})
    return permissions_dict
    

def find_safe(module):
    cyberark_session = module.params["cyberark_session"]
    safe_name = module.params["safename"]
    api_base_url = module.params["api_base_url"]
    headers = {
        "content-type": "application/json",
        "Authorization": cyberark_session["token"]
    }
    endpoint = 'https://{0}/PasswordVault/WebServices/PIMServices.svc/Safes?query={1}'.format(api_base_url,safe_name)
    try:
        response = requests.get(url_safe,headers = headers,verify=False)
        response_safe = response.json()
        safe_names = dict(response_safe)
        found = False
        safe_record = None
        if safe_names['SearchSafesResult'] != []:
            for safes in safe_names['SearchSafesResult']:
                if safes['SafeName'] == safe_name:
                        found = True
                        safe_record = safes['SafeName']
                        break
                else:
                        continue
        else:
            found = False
        return (found,safe_record,response.status_code)
    except Exception as e:
        module.fail_json(
                msg=("There was an exception when search safe name, error: %s" % (str(e))),
                status_code= 400
            )
def add_safe_member(module):
    cyberark_session = module.params["cyberark_session"]
    safe_name = module.params["safename"]
    api_base_url = module.params["api_base_url"]
    membername = module.params["membername"]
    searchin = module.params["searchin"]
    membershipexpirationdate = module.params["membershipexpirationdate"]
    permissions = module.params["permissions"]
    admin_account = module.params["admin_account"]
    payload = {"member": {}}
    if membername:
        payload["member"].update({"MemberName": membername})
    if searchin:
        payload["member"].update({"SearchIn": description})
    if membershipexpirationdate:
        payload["member"].update({"MembershipExpirationDate": membershipexpirationdate})
    if admin_account == 'yes':
       permissions_dict = permissions_admin()
    if admin_account == 'no':
       permissions_dict = permissions_user(permissions)
    payload["member"].update({"Permissions": permissions_dict})
    headers = {
        "content-type": "application/json",
        "Authorization": cyberark_session["token"]
    }

    endpoint = 'https://{0}/PasswordVault/WebServices/PIMServices.svc/Safes/{1}/Members'.format(api_base_url,safe_name)
    changed = False
    safe_account_member = None
    try:
        response = requests.post(endpoint,data = json.dumps(payload),headers = headers,verify=False)
        if response.status_code == 201:
             changed = True
             safe_account_member = response.json()
        else:
             changed = False
        return (changed,safe_account_member,response.status_code)
    except Exception as e:
        module.fail_json(
                msg=("There was an exception when adding safe name member, error: %s" % (str(e))),
                status_code= 400
            )

def main():
    fields = {
            "api_base_url": {"type": "str"},
            "safename":  {"type": "str"},
            "cyberark_session": {"required": True, "type": "dict", "no_log": True},
            "admin_account": {"required": True, "type": "str"},
            "membername": {"required": True, "type": "str"},
            "searchin": {"required": True, "type": "str"},
            "membershipexpirationdate": {"required": False, "type": "str", "default": ""},
            "permissions": {"required": True, "type": "dict"}
    }
    module = AnsibleModule(argument_spec=fields, supports_check_mode=True)
    (found, safe_record, status_code) = find_safe(module)
    if found:
        (changed,safe_account_member,status_code) = add_safe_member(module)
        if changed:
            module.exit_json(changed=changed, result=safe_account_member, status_code=status_code, msg= "safe account member added successfully")
        else:
            module.fail_json(changed=changed, status_code=status_code,msg= "safe account member failed to add")
    else:
        changed = False
        results = "Given safe name {0} dose not exist".format(safe_record)
        module.fail_json(changed=changed, result=result, status_code=status_code)

if __name__ == "__main__":
    main()
