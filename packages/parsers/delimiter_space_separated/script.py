import re
 

KEY_VALUE_PATTERN = re.compile(r'(\w+)=([^=]+?)(?=\s+\w+=|$)')
def parse(log_line):
    try:
        matches = KEY_VALUE_PATTERN.findall(log_line.strip())
        result = {}
        for key,value in matches:
          result[key]=value.strip().strip('"\'')
        return {"values":result}
    except Exception as  e:
        return {"error": "Parsing failed: %s" % str(e)} 

# def parse(log_line):
#     try:
#         values = log_line.strip().split(" ")
#         return {"values": values}
#     except Exception as  e:
#         return {"error": "Parsing failed: %s" % str(e)} 



  