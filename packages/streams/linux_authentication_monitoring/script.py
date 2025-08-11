
# Sample name -> streams/Linux_Security/script.py

def configuration():
    return {
    "dictionary": "smc/default/dictionaries/linux_dictionary/",
    "detections": [
        "smc/default/detections/multiple_failed_login_attempts_for_linux/",
        "smc/default/detections/successful_root_login_via_ssh/",
        "smc/default/detections/ssh_key_based_login_success/"
    ]
}

def use():
    return 'http://integration-Linux-Security/execute?groups=OS'
