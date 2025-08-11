import time
from datetime import datetime

# This function determines if the log qualifies for data processing.
def criteria(metainfo):
    return metainfo.get('provider') == 'Linux' and metainfo.get('group') == 'OS Events' \
        and metainfo.get('type') == 'Security'

def timestamp(event):
    datestring = event["EventTime"]
    dt = datetime.strptime(datestring, "%Y-%m-%d %H:%M:%S")  # Parse the string to datetime
    epoch_time = time.mktime(dt.timetuple())  # Convert to seconds since epoch
    milliseconds = int(epoch_time * 1000)  # Convert to milliseconds
    return milliseconds

# Extracts user-readable message from event
def message(event):
    return event.get('Message') # Extract the event message

# Dictionary function for structured event data
def dictionary(event):
    event_dict = {
        "event_time": event.get("EventReceivedTime"),
        "event_severity_value": event.get("SyslogSeverityValue"),
        "event_severity_type": event.get("SyslogSeverity"),
        "event_category": event.get("SourceModuleName"),
        "source_file": event.get("SourceModuleType"),
        "source_type": event.get("SyslogFacility"),
        "source_type_value": event.get("SyslogFacilityValue"),
        "host": event.get("Hostname"),
        "action": event.get("SourceName"),
        "process_id": event.get("ProcessID"),
        "event_message": event.get("Message"),
        "user_ip": event.get("MessageSourceAddress"),
    }

    return event_dict





  