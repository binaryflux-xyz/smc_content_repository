
# Sample name -> streams/Linux_Security/script.py

def configuration():
    return {
    "dictionary": "smc/default/dictionaries/linux_dictionary/",
    "detections": [
        "smc/default/detections/multiple_sudo_session_opened/",
        "smc/default/detections/sudo_command_from_root_directory/",
        "smc/default/detections/multiple_use_of_su_command_to_switch_to_root/"
    ]
}

def use():
    return 'http://integration-Linux-Security/execute?groups=OS'
