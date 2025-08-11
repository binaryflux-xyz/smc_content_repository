# sample name -> widgets/accounts_compromised/script.py
import time

# this to return default widget config
def configure():
    return {
        "searchable": True,
        "datepicker": True,
        "properties": {"type": "table"},
        "dimension": {"x":4,"y":1,"width": 4, "height": 7}
    }

# this to return query to be used for rendering widget and its parameters
def query():

    return {
        "query": "SELECT * from fn_topoutliers",
        "parameters": {'n' : 0},
    }

# this to return filter queries based on filters selected by user and its parameters
def filters(filter):
    filterqueries = []
    parameters = {}
    if filter:
        if filter.get("detectioncriticality"):
            parameters["criticality"] = filter.get("detectioncriticality")
        if filter.get("detectiontactic"):
            parameters["tactic"] = filter.get("detectiontactic")
        if filter.get("detectiontechnique"):
            parameters["technique"] = filter.get("detectiontechnique")
        if filter.get("streamname"):
            parameters["streamname"] = filter.get("streamname")
    return {"filterqueries": filterqueries, "parameters": parameters}


# this to return free text search query and its parameters
def search(freetext):
    searchquery = ' "entity" ilike :_entity '
    return {
        "searchquery": searchquery,
        "parameters": {"_entity": "%" + freetext + "%"},
    }



# this to return sort query
def sort(sorcol, sortorder):
    sort += " order by " + sorcol + " " + sortorder


# this to return return formated results to render a widget
def render(results):
    if not results or len(results) == 0:
        raise Exception("no results found")
    
    for result in results:
        result['description']=None
        # result['description']=graph.getMeta(result['entity'],result['entitytype'])
    
    columns = ['entity' , 'score']

    return  {"result":{"columns": columns, "rows": results}}