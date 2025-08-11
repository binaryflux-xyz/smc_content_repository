
# Sample name -> streams/Linux_Security/script.py

def configuration():
    return {
    "dictionary": "smc/smc/dictionaries/linux_dictionary/",
    "detections": [
        "smc/smc/detections/multiple_sudo_session_opened/",
        "smc/smc/detections/sudo_command_from_root_directory/",
        "smc/smc/detections/multiple_use_of_su_command_to_switch_to_root/"
    ]
}

def use():
    return 'http://integration-Linux-Security/execute?groups=OS'
