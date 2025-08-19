# 4625, 4627, 4634, 4656, 4658, 4663, 4670, 4672, 4673, 4689, 4690, 4702, 4703, 4799, 4945, 4957, 5024, 5058, 5059, 5061, 5152, 5156, 5157, 5158, 5379, 5447, 5478, 6416, 7036
# 4688
import json


parsed_event = {}


def modifydata(outer):

    inner = json.loads(outer.pop("log"))
    parsed = outer.copy()
    parsed.update(inner)
    data_text = parsed.pop("data", "")

    current_section = None              # e.g., "Subject", "Network Information"
    current_root_list_key = None        # e.g., "Privileges" when first item is inline
    message_lines = []
    
    for raw in data_text.splitlines():
        line = raw.rstrip("\r\n")
        if not line.strip():
            continue
    
        # TOP-LEVEL (no leading tab)
        if not line.startswith("\t"):
            # new top-level context
            current_section = None
            current_root_list_key = None
    
            if line.endswith(":"):
                # True section header: "Subject:", "Network Information:", etc.
                section = line[:-1].strip()
                current_section = section
                parsed[section] = {}
                continue
    
            if ":" in line:
                # Root-level "key: value" (e.g., "Privileges:  SeAssignPrimaryTokenPrivilege")
                key, value = line.split(":", 1)
                key = key.strip()
                value = value.strip()
                parsed[key] = value
                # prepare to collect subsequent indented list items (if any)
                current_root_list_key = key
                continue
    
            # Otherwise: message text before any section
            message_lines.append(line.strip())
            continue
    
        # INDENTED LINE
        stripped = line.strip()
    
        if current_section is not None:
            if ":" in stripped:
                k, v = stripped.split(":", 1)
                parsed[current_section][k.strip()] = v.strip()
            else:
                # Section contains list items; store section as list
                if isinstance(parsed[current_section], dict):
                    if parsed[current_section]:
                        # Mixed content (rare): keep list under "items" so we don't drop existing KV
                        items = parsed[current_section].get("items")
                        if items is None:
                            parsed[current_section]["items"] = []
                        parsed[current_section]["items"].append(stripped)
                    else:
                        parsed[current_section] = [stripped]
                else:
                    # already a list
                    parsed[current_section].append(stripped)
            continue
    
        # No active section → continuation of a root-level list (e.g., Privileges)
        if current_root_list_key:
            if isinstance(parsed[current_root_list_key], list):
                parsed[current_root_list_key].append(stripped)
            else:
                first = parsed[current_root_list_key]
                parsed[current_root_list_key] = [first, stripped]
            continue
    
        # Fallback: treat as message
        message_lines.append(stripped)
    
    if message_lines:
          parsed["Message"] = " ".join(message_lines)
    
    return parsed

# this to return True/False based on which this message will qualify to be used for datamodel
def criteria(metainfo):
    return metainfo['provider'] == 'Microsoft' and metainfo['group'] == 'Windows Events' \
        and metainfo['type'] == 'Audit'

def timestamp(event):
    global parsed_event
    if not parsed_event :
      parsed_event = modifydata(event)
    eventtime = parsed_event.get("date")
    if eventtime is not None :
      return int(eventtime*1000)
  
# this to return user readable text as message extracted from event
def message(event):
    global parsed_event
    if not parsed_event :
      parsed_event = modifydata(event)
    return parsed_event.get('Message')



# Dictonary
def dictionary(event_data):

    global parsed_event
    if not parsed_event :
      parsed_event = modifydata(event_data)
    subject = parsed_event.get('Subject', {})
    creator_subject = parsed_event.get('Creator Subject', {})
    target_subject = parsed_event.get('Target Subject', {})
    object = parsed_event.get('Object', {})
    logon_info = parsed_event.get('Logon Information', {})
    new_logon = parsed_event.get('New Logon', {})
    failure_info = parsed_event.get('Failure Information', {})
    filter_info = parsed_event.get('Filter Information', {})
    process_info = parsed_event.get('Process Information', {})
    network_info = parsed_event.get('Network Information', {})
    application_info = parsed_event.get('Application Information', {})
    detailed_auth_info = parsed_event.get('Detailed Authentication Information', {})
    account_for_which_logon_failed = parsed_event.get('Account For Which Logon Failed', {})
    access_request_info = parsed_event.get('Access Request Information', {})
    event = {
        # Always present
        "event_id": parsed_event.get('event_id'),
        "event_category":parsed_event.get("channel"),
        "source_host":parsed_event.get("agent_name"),
        "source_ip": network_info.get('Source Network Address') or network_info.get('Source Address') or parsed_event.get('source'),

        # Subject (who triggered event)
        "source_security_id": new_logon.get('Security ID') or subject.get('Security ID') or creator_subject.get('Security ID'),
        "source_account_name": new_logon.get('Account Name') or subject.get('Account Name') or creator_subject.get('Account Name'),
        "source_account_domain": new_logon.get('Account Domain') or subject.get('Account Domain') or creator_subject.get('Account Domain'),
        "source_logon_id": new_logon.get('Logon ID') or subject.get('Logon ID') or creator_subject.get('Logon ID'),
        "source_logon_guid": new_logon.get('Logon GUID') or subject.get('Logon GUID') or creator_subject.get('Logon GUID'),

        "destination_security_id": account_for_which_logon_failed.get('Security ID'),
        "destination_account_name": account_for_which_logon_failed.get('Account Name'),
        "destination_account_domain": account_for_which_logon_failed.get('Account Domain'),

        # New Logon
        
        "new_logon_linked_logon_id": new_logon.get('Linked Logon ID'),
        "new_logon_network_account_name": new_logon.get('Network Account Name'),
        "new_logon_network_account_domain": new_logon.get('Network Account Domain'),

        # Logon details
        "logon_process_name": parsed_event.get('Logon Process Name'),
        "logon_type": logon_info.get('Logon Type'),
        "restricted_admin_mode": logon_info.get('Restricted Admin Mode'),
        "virtual_account": logon_info.get('Virtual Account'),
        "elevated_token": logon_info.get('Elevated Token'),

        "logon_process": detailed_auth_info.get('Logon Process'),
        "authentication_package": detailed_auth_info.get('Authentication Package'),
        "transited_services": detailed_auth_info.get('Transited Services'),
        "package_name": detailed_auth_info.get('Package Name (NTLM only)'),
        "key_length": detailed_auth_info.get('Key Length'),

        # Failure details (4625 etc.)
        "error_message": failure_info.get('Failure Reason'),
        "failure_status": failure_info.get('Status'),
        "failure_sub_status": failure_info.get('Sub Status'),

        "process_id": process_info.get('Process ID') or process_info.get('New Process ID') or application_info.get('Process ID') or process_info.get('Caller Process ID'),
        "process_name": process_info.get('Process Name') or process_info.get('New Process Name') or process_info.get('Caller Process Name'),
        "process_command_line": process_info.get('Process Command Line'),
        "creator_process_id": process_info.get('Creator Process ID'),
        "creator_process_name": process_info.get('Creator Process Name'),

        # Object Access (4656, 4663, etc.)
        "server": object.get('Object Server'),
        "service_type": object.get('Object Type'),
        "handle_id": object.get('Handle ID'),
        "resource_attributes": object.get('Resource Attributes'),

        "applicationname": application_info.get('Application Name'),

        "server_workstation": network_info.get('Workstation Name'),
        "direction": network_info.get('Direction'),\
        "source_port": network_info.get('Source Port'),
        "destination_ip": network_info.get('Destination Address') or network_info.get('Client Address'),
        "destination_port": network_info.get('Destination Port') or network_info.get('Client Port'),
        
        "network_protocol": network_info.get('Protocol'),

        "filter_run_time_id": filter_info.get('Filter Run-Time ID'),
        "layer_name": filter_info.get('Layer Name'),
        "layer_run_time_id": filter_info.get('Layer Run-Time ID'),
        "accesses": access_request_info.get('Accesses'),
        "file_permission":access_request_info.get("items"),
        "access_mask": access_request_info.get("Access Mask") or parsed_event.get('Access Mask'),
        "privileges":access_request_info.get("Privileges Used for Access Check") or  parsed_event.get('Privileges') ,
        "permissions": parsed_event.get('Permissions'),

        # Process Information (4688, 4689, etc.)
        

        "parent_process_id": parsed_event.get('Parent Process ID'),
        "parent_process_name": parsed_event.get('Parent Process Name'),
        "token_elevation_type": parsed_event.get('Token Elevation Type'),

        # Service events (7036, 5024, etc.)
        "service_name": object.get('Object Name') or parsed_event.get('Service Name'),
        "service_file_name": parsed_event.get('Service File Name'),
        "service_state": parsed_event.get('Service State'),
        "service_type": parsed_event.get('Service Type'),
        "start_type": parsed_event.get('Start Type'),

        # Task Scheduler (4702, 4703)
        "task_name": parsed_event.get('Task Name'),
        "task_content": parsed_event.get('Task Content'),

        # Firewall / Filtering Platform (5152, 5156, etc.)
        

        # Credential events (5379)
        "target_name": parsed_event.get('Target Name'),
        "credential_type": parsed_event.get('Credential Type'),

        # Policy changes (5447, 5478, 6416)
        "policy_change": parsed_event.get('Policy Change'),
        "policy_id": parsed_event.get('Policy ID'),

        # Group membership (4627, 4799)
        "member_name": parsed_event.get('Member Name'),
        "member_sid": parsed_event.get('Member SID'),
        "group_name": parsed_event.get('Group Name'),

        # Cryptographic (5058, 5059, 5061)
        "cryptographic_provider": parsed_event.get('Provider Name'),
        "algorithm": parsed_event.get('Algorithm Name'),
        "key_name": parsed_event.get('Key Name'),

        # Misc common fields
        

        "session_id": parsed_event.get('Session ID'),
        "reason": parsed_event.get('Reason')
    }

    return event
