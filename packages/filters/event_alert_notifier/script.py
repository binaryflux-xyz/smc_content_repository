def condition(event):
    if event.get('log_type') == "event" and event.get('event_level') == "alert" :
        return True
    else:
        return False