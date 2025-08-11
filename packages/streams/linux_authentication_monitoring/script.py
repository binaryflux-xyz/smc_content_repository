
# Sample name -> streams/Linux_Security/script.py

def configuration():
    return {
    "dictionary": "smc/smc/dictionaries/linux_dictionary/",
    "detections": [
        "smc/smc/detections/multiple_failed_login_attempts_for_linux/",
        "smc/smc/detections/successful_root_login_via_ssh/",
        "smc/smc/detections/ssh_key_based_login_success/"
    ]
}

def use():
    return 'http://integration-Linux-Security/execute?groups=OS'
