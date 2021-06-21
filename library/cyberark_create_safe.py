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
def add_safe(module):
    cyberark_session = module.params["cyberark_session"]
    safe_name = module.params["safename"]
    api_base_url = module.params["api_base_url"]
    description = module.params["description"]
    olacenabled = module.params["olacenabled"]
    managingcpm = module.params["managingcpm"]
    numberOfversionsretention = module.params["numberOfversionsretention"]
    numberOfdaysretention = module.params["numberOfdaysretention"]

    payload = {"safe": {}}
    if safe_name:
        payload["safe"].update({"SafeName": safe_name})
    if description:
        payload["safe"].update({"Description": description})
    # else:
    #     payload["safe"].update({"Description":""})
    if olacenabled:
        payload["safe"].update({"OLACEnabled": olacenabled})
    # else:
    #     payload["safe"].update({"OLACEnabled": False})
    if managingcpm:
        payload["safe"].update({"ManagingCPM": managingcpm})
    if numberOfversionsretention:
        payload["safe"].update({"NumberOfVersionsRetention": numberOfversionsretention})
    if numberOfdaysretention:
        payload["safe"].update({"NumberOfDaysRetention": numberOfdaysretention})
    headers = {
        "content-type": "application/json",
        "Authorization": cyberark_session["token"]
    }
    endpoint = 'https://{0}/PasswordVault/WebServices/PIMServices.svc/Safes'.format(api_base_url)
    changed = False
    safe_account = None
    try:
        response = requests.post(safe_url,data = json.dumps(payload),headers = headers,verify=False)
        if response.status_code == 201:
             changed = True
             safe_account = response.json()
        else:
             changed = False
        return (changed,safe_account,response.status_code)
    except Exception as e:
        module.fail_json(
                msg=("There was an exception when create safe name, error: %s" % (str(e))),
                status_code= 400
            )

def main():
    fields = {
            "api_base_url": {"type": "str"},
            "cyberark_session": {"required": True, "type": "dict", "no_log": True},
            "safename": {"required": True, "type": "str"},
            "description": {"required": False, "type": "str", "default": ""},
            "olacenabled": {"required": False, "type": "str", "default": False"},
            "managingcpm": {"required": True, "type": "str"},
            "numberOfversionsretention": {"required": False, "type": "int","default": 5},
            "numberOfdaysretention": {"required": False, "type": "int","default": 5}
    }
    module = AnsibleModule(argument_spec=fields, supports_check_mode=True)
    (found, safe_record, status_code) = find_safe(module)
    if found:
        changed = False
        results = "Give safe name {0} already exist".format(safe_record)
        module.fail_json(changed=changed, result=result, status_code=status_code)
    else:
       (changed,safe_account,status_code) = add_safe(module)
       if changed:
           module.exit_json(changed=changed, result=safe_account, status_code=status_code, msg= "safe account created successfully")
       else:
           module.fail_json(changed=changed, status_code=status_code,msg= "safe account failed to create")

if __name__ == "__main__":
    main()
