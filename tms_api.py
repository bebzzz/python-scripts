import urllib3
import requests
import json
import time
import sys
import re

# to call:  get_process_state("sg1-chicago4.test", mm_uri, mm_user, mm_pass, "app_server")
# returns a dictionary like: {'expectedStatus': u'running', 'state': u'started'}
def get_process_state(instanceID, mm_uri, mm_user, mm_pass, procName):
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    headers = {'content-type': 'application/json'}
    url = mm_uri + "/v1/instances/" + instanceID + "/processes/" + procName
    response = requests.get(url, auth=(mm_user, mm_pass), headers=headers, verify=False)
    if response.status_code == 200:
        state = {
            "state": response.json()['state'],
            "expectedStatus": response.json()['expectedStatus']
            }
    elif response.status_code == 401:
        print("Response [" + str(response.status_code) + "] user is not authorized")
        return
    elif response.status_code == 404:
        print("Response [" + str(response.status_code) + "] InstanceID or ProcessName NOT FOUND")
        return
    elif response.status_code == 500:
        print("Response [" + str(response.status_code) + "] there is some error on the server side")
        return
    else:
        print("Unknown ERROR Response [" + str(response.status_code) + "]")
        return
    return state




def response_code(code):
    if code == 204:
        #print("Response [" + str(code) + "] request has been successfully processed")
        return
    elif code == 202:
        return
    elif code == 401:
        print("Response [" + str(code) + "] user is not authorized")
    elif code == 404:
        print("Response [" + str(code) + "] requested instance has not been found")
    elif code == 500:
        print("Response [" + str(code) + "] there is some error on the server side")
    else:
        print("Unknown ERROR Response [" + str(response.status_code) + "]")
    return


#to call:  get_process_state("sg1-chicago4.test", mm_uri, mm_user, mm_pass, "app_server", "started")
def waiting_tms(instanceID, mm_uri, mm_user, mm_pass, procName, expectation):
    if expectation == 'stopped':
        status_timeout = 0
        while status_timeout < 30:
            state = get_process_state(instanceID, mm_uri, mm_user, mm_pass, procName)
            if state['state'] == 'stopped' and state['expectedStatus'] == 'stopped':
                print("\n" + procName + " has been STOPPED for " + instanceID)
                break
            else:
                sys.stdout.write(str(30 - status_timeout) + " seconds remaining for " + procName + " to STOP")
                sys.stdout.flush()
                time.sleep(1)
                status_timeout += 1
    if expectation == 'started':
        status_timeout = 0
        while status_timeout < 30:
            state = get_process_state(instanceID, mm_uri, mm_user, mm_pass, procName)
            if state['state'] == 'started' and state['expectedStatus'] == 'running':
                print("\n" + procName + " has been STARTED for " + instanceID)
                break
            else:
                sys.stdout.write("\r")
                sys.stdout.write(str(30 - status_timeout) + " seconds remaining for " + procName + " to START")
                sys.stdout.flush()
                time.sleep(1)
                status_timeout += 1
    return




# to call
# change_process_state("sg1-chicago4.test", mm_uri, mm_user, mm_pass, "app_server", "stop")
def change_process_state(instanceID, mm_uri, mm_user, mm_pass, procName, action):
    state = get_process_state(instanceID, mm_uri, mm_user, mm_pass, procName)
    if state['state'] == None:
        print("Impossible to determine the state of '" + procName + "' for " + instanceID)
        return
    if action == "stop":
        if state['state'] == 'started':
            headers = {'content-type': 'application/json'}
            url = mm_uri + "/v1/instances/" + instanceID + "/processes/" + procName + "/actions/" + action
            response = requests.patch(url, auth=(mm_user, mm_pass), headers=headers, verify=False)
            response_code(response.status_code)
            print("STOP has been sent for " + procName)
            waiting_tms(instanceID, mm_uri, mm_user, mm_pass, procName, "stopped")
            #clear_last_line()
        elif state['state'] == 'stopped':
            print(procName + " is already stopped")
            #clear_last_line()
        else:
            print(procName + " is in unknown status")
            #clear_last_line()
    elif action == "start":
        if state['state'] == 'started':
            print(procName + " is already started")
            #clear_last_line()
        elif state['state'] == 'stopped':
            headers = {'content-type': 'application/json'}
            url = mm_uri + "/v1/instances/" + instanceID + "/processes/" + procName + "/actions/" + action
            response = requests.patch(url, auth=(mm_user, mm_pass), headers=headers, verify=False)
            response_code(response.status_code)
            print("START has been sent for " + procName)
            waiting_tms(instanceID, mm_uri, mm_user, mm_pass, procName, "started")
            #clear_last_line()
        else:
            print(procName + " is in unknown status")
            #clear_last_line()
    else:
        print("Action '" + action + "' is not supported")
    return




# to call:
# change_sr_job_state("test1331", mma_uri, mma_user, mma_pass, "services", "street_routing", "disable")
# change_sr_job_state("test1331", mma_uri, mma_user, mma_pass, "batch", "forecast", "enable")
# to enable/disable ALL:  change_sr_job_state("test1331", mma_uri, mma_user, mma_pass, "", "", "disable"))
def change_sr_job_state(sysuser, mma_uri, mma_user, mma_pass, mode, module, action):
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    headers = {'content-type': 'application/json'}
    data = {
            "action": action,
            "module": module,
            "mode": mode
        }
    url = mma_uri + "/v1/instances/" + sysuser + "/be/script_runner"
    response = requests.patch(url, data=json.dumps(data), auth=(mma_user, mma_pass), headers=headers, verify=False)
    if response.status_code == 200:
        #print("Response [" + str(response.status_code) + "] the status of the tasks has been successfully received")
        if module == "":
            print("Request " + action + " has been sent for ALL SR jobs")
        else:
            print("Request " + action + " has been sent for " + module + " SR job")
        return response
    elif response.status_code == 400:
        print("Response [" + str(response.status_code) + "] bad request")
        return response
    elif response.status_code == 401:
        print("Response [" + str(response.status_code) + "] user is not authorized")
        return response
    elif response.status_code == 500:
        print("Response [" + str(response.status_code) + "] there is some error on the server side")
        return response
    else:
        print("Unknown ERROR Response [" + str(response.status_code) + "]")
        return response




# to call:
# create_admin_user("test1331", mma_uri, mma_user, mma_pass, "admin2")
# returns: Response [201] user has been successfully created
def create_admin_user(sysuser, mma_uri, mma_user, mma_pass, login_name):
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    headers = {'content-type': 'application/json'}
    data = {
            "instanceName": sysuser,
            "loginName": login_name
        }
    url = mma_uri + "/v1/user"
    response = requests.post(url, data=json.dumps(data), auth=(mma_user, mma_pass), headers=headers, verify=False)
    if response.status_code == 201:
        print("Response [" + str(response.status_code) + "] user has been successfully created")
    elif response.status_code == 401:
        print("Response [" + str(response.status_code) + "] user is not authorized")
    elif response.status_code == 404:
        print("Response [" + str(response.status_code) + "] requested instance has not been found")
    elif response.status_code == 409:
        print("Response [" + str(response.status_code) + "] requested user already exists")
    elif response.status_code == 422:
        print("Response [" + str(response.status_code) + "] requested instance not available")
    elif response.status_code == 500:
        print("Response [" + str(response.status_code) + "] there is some error on the server side")
    else:
        print("Unknown ERROR Response [" + str(response.status_code) + "]")
    return response



# to call:
# reset_admin_password("test1331", mma_uri, mma_user, mma_pass, "admin2")
# returns: Response [200] administrator password has been successfully reset. {"name":"admin2","password":"StrongPasWd"}
def reset_admin_password(sysuser, mma_uri, mma_user, mma_pass, login_name):
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    headers = {'content-type': 'application/json'}
    data = {
            "instanceName": sysuser,
            "loginName": login_name
        }
    url = mma_uri + "/v1/user"
    response = requests.patch(url, data=json.dumps(data), auth=(mma_user, mma_pass), headers=headers, verify=False)
    if response.status_code == 200:
        print("Response [" + str(response.status_code) + "] administrator password has been successfully reset. " + response.text)
    elif response.status_code == 401:
        print("Response [" + str(response.status_code) + "] user is not authorized")
    elif response.status_code == 404:
        print("Response [" + str(response.status_code) + "] requested instance or user has not been found")
    elif response.status_code == 422:
        print("Response [" + str(response.status_code) + "] requested instance not available")
    elif response.status_code == 500:
        print("Response [" + str(response.status_code) + "] there is some error on the server side")
    else:
        print("Unknown ERROR Response [" + str(response.status_code) + "]")
    return response



# to call:  get_hosts_on_corepod(mma_uri, mma_user, mma_pass)
# returns a list of ALL HOSTS in COREPOD like this:
# [
# 	{
# 	"id":"1",
# 	"address":"beapp-1",
# 	"type_id":"1",
# 	"group_id":"1",
# 	"type":"be",
# 	"group":"BE-APP-TEST-DC2-1",
# 	"used_in_slot_group":true
# 	},
# 	............................
# ]
def get_hosts_on_corepod(mma_uri, mma_user, mma_pass):
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    headers = {'content-type': 'application/json'}
    url = mma_uri+"/gui_api/pod/host"
    response = requests.get(url, auth=(mma_user, mma_pass), headers=headers, verify=False)
    if response.status_code == 200:
        #print("Response [" + str(response.status_code) + "] OK")
        hosts_on_corepod = response.json()
        return hosts_on_corepod
    elif response.status_code == 404:
        print("Response [" + str(response.status_code) + "] Not found")
        return response
    elif response.status_code == 401:
        print("Response [" + str(response.status_code) + "] Unauthorized")
        return response
    elif response.status_code == 500:
        print("Response [" + str(response.status_code) + "] there is some error on the server side")
        return response
    else:
        print("Unknown ERROR Response [" + str(response.status_code) + "]")
        return response




# to call:  get_instance_parameters("sg1-chicago4.test", mma_uri, mma_user, mma_pass)
# returns a dictionary with all instance parameters
# example of call for getting one parameter: get_instance_parameters("sg1-chicago4.test", mma_uri, mma_user, mma_pass)['sg1-chicago4.test']['instanceParameters']['search_agent.http_max_threads']
def get_instance_parameters(instance_name, mma_uri, mma_user, mma_pass):
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    headers = {'content-type': 'application/json'}
    url = mma_uri+"/v1/parameters?instances=" + instance_name
    response = requests.get(url, auth=(mma_user, mma_pass), headers=headers, verify=False)
    if response.status_code == 202:
        #print("Response [" + str(response.status_code) + "] OK")
        instance_parameters = response.json()
        return instance_parameters
    elif response.status_code == 404:
        print("Response [" + str(response.status_code) + "] Not found")
        return response
    elif response.status_code == 401:
        print("Response [" + str(response.status_code) + "] Unauthorized")
        return response
    elif response.status_code == 500:
        print("Response [" + str(response.status_code) + "] there is some error on the server side")
        return response
    else:
        print("Unknown ERROR Response [" + str(response.status_code) + "]")
        return response





# to call:  get_sr_job_info("test1331", mma_uri, mma_user, mma_pass, "stats_agent")
# List of allowed sr_tasks:
# 'stats_agent'
# 'report_scheduler'
# 'db_optimizer'
# 'forecast'
# 'resource_cut'
# 'dnrm_extract'
# 'property_file_reaper'

# 'dwh_writer'
# 'travel_complaint'
# 'dwh_reader'
# 'mdb_writer'
# 'routing_results'
# 'collaboration_sync'
# 'geo_request'
# 'soap_auth'
# 'live_updates'
# 'street_routing'd',
# 'mdb_reader'

# returns a list like:
# {
#     u'status': u'enabled',
#     u'name': u'stats_agent',
#     u'started': u'2018-08-02 00:07:09',
#     u'host': u'test-srapp-1',
#     u'finished': u'2018-08-02 00:07:10',
#     u'config': u'disabled'
# }
# to call:  get_sr_job_info("test1331", mma_uri, mma_user, mma_pass, "stats_agent")['finished']
# returns unicode:  "2018-08-02 00:07:10"
def get_sr_job_info(sysuser, mma_uri, mma_user, mma_pass, sr_task):
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    headers = {'content-type': 'application/json'}
    url = mma_uri + "/v1/instances/" + sysuser + "/be/script_runner/info/module/" + sr_task
    response = requests.get(url, auth=(mma_user, mma_pass), headers=headers, verify=False)
    if response.status_code == 200:
        #print("Response [" + str(response.status_code) + "] the status of the tasks has been successfully received")
        state = response.json()
    elif response.status_code == 400:
        print("Response [" + str(response.status_code) + "] bad request")
        return response
    elif response.status_code == 401:
        print("Response [" + str(response.status_code) + "] user is not authorized")
        return response
    elif response.status_code == 500:
        print("Response [" + str(response.status_code) + "] there is some error on the server side")
        return response
    else:
        print("Unknown ERROR Response [" + str(response.status_code) + "]")
        return response
    return state




# to call:  get_sr_jobs_state("test1331", mma_uri, mma_user, mma_pass, "batch|services|all")
# List of allowed modes: batch, services, scheduler(does't actually work), all.
# mode "batch" returns a dictionary like:
#   {
#       u'appt_cut': u'enabled',
#       u'stats_agent': u'disabled',
#       u'report_scheduler': u'enabled',
#       u'db_optimizer': u'enabled',
#       u'forecast': u'enabled',
#       u'resource_cut': u'enabled',
#       u'dnrm_extract': u'enabled',
#       u'property_file_reaper': u'enabled'
#   }

# mode "services" returns:
#   {
#       u'dwh_writer': u'running',
#       u'travel_complaint': u'running',
#       u'dwh_reader': u'running',
#       u'mdb_writer': u'running',
#       u'routing_results': u'running',
#       u'collaboration_sync': u'running',
#       u'geo_request': u'running',
#       u'soap_auth': u'running',
#       u'live_updates': u'running',
#       u'street_routing': u'enabled',
#       u'mdb_reader': u'running'
#   }
# to call:  get_sr_jobs_state("test1331", mma_uri, mma_user, mma_pass, "batch")['resource_cut']
# returns unicode:  "enabled"
def get_sr_jobs_state(sysuser, mma_uri, mma_user, mma_pass, mode):
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    headers = {'content-type': 'application/json'}
    url = mma_uri + "/v1/instances/" + sysuser + "/be/script_runner/mode/" + mode
    response = requests.get(url, auth=(mma_user, mma_pass), headers=headers, verify=False)
    if response.status_code == 200:
        #print("Response [" + str(response.status_code) + "] the status of the tasks has been successfully received")
        state = response.json()
    elif response.status_code == 400:
        print("Response [" + str(response.status_code) + "] bad request")
        return response
    elif response.status_code == 401:
        print("Response [" + str(response.status_code) + "] user is not authorized")
        return response
    elif response.status_code == 500:
        print("Response [" + str(response.status_code) + "] there is some error on the server side")
        return response
    else:
        print("Unknown ERROR Response [" + str(response.status_code) + "]")
        return response
    return state


# to call: get_sysuser("sg1-chicago4.test", mma_uri, mma_user, mma_pass)
# returns a string like "test1331"
def get_sysuser(instance_name, mma_uri, mma_user, mma_pass):
    instance_parameters = get_instance_parameters(instance_name, mma_uri, mma_user, mma_pass)
    sysuser = (instance_parameters[instance_name]["instanceParameters"]["system_username"])
    return sysuser


# to call:  get_version("sg1-chicago4.test", mma_uri, mma_user, mma_pass)
# returns a string like "18.8.2.0.4"
def get_version(instance_name, mma_uri, mma_user, mma_pass):
    instance_parameters = get_instance_parameters(instance_name, mma_uri, mma_user, mma_pass)
    version = (instance_parameters[instance_name]["instanceParameters"]["instance_version"])
    return version

# to call: get_availabel_corepods(mm_uri, mm_user, mm_pass)
# returns json
# example of call: get_availabel_corepods(mm_uri, mm_user, mm_pass)['items'][2]['label']
# returns: "DC6"
def get_available_corepods(mm_uri, mm_user, mm_pass):
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    headers = {'content-type': 'application/json'}
    url = mm_uri + "/v1/corePods"
    response = requests.get(url, auth=(mm_user, mm_pass), headers=headers, verify=False)
    if response.status_code == 200:
        #print("Response [" + str(response.status_code) + "] OK")
        corepods = response.json()
        return corepods
    elif response.status_code == 404:
        print("Response [" + str(response.status_code) + "] Not found")
        return response
    elif response.status_code == 401:
        print("Response [" + str(response.status_code) + "] Unauthorized")
        return response
    elif response.status_code == 500:
        print("Response [" + str(response.status_code) + "] there is some error on the server side")
        return response
    else:
        print("Unknown ERROR Response [" + str(response.status_code) + "]")
        return response



# to call: get_corepods_labels(mm_uri, mm_user, mm_pass)
# returns a list like this: [u'DC2TST', u'DC2', u'DC6', u'DC6TRN']
def get_corepods_labels(mm_uri, mm_user, mm_pass):
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    available_corepods = get_available_corepods(mm_uri, mm_user, mm_pass)
    labels = []
    for pod in range (0, len(available_corepods['items'])):
        labels.append(available_corepods['items'][pod]['label'])
    return labels



# to call: get_BEnodes_on_corepod(mm_uri, mm_user, mm_pass, 'DC2')
def get_BEnodes_on_corepod(mm_uri, mm_user, mm_pass, corePodLabel):
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    headers = {'content-type': 'application/json'}
    url = mm_uri + "/v1/corePods/" + corePodLabel + "/beNodes"
    response = requests.get(url, auth=(mm_user, mm_pass), headers=headers, verify=False)
    if response.status_code == 200:
        #print("Response [" + str(response.status_code) + "] OK")
        be_on_corepod = response.json()
        return be_on_corepod
    elif response.status_code == 404:
        print("Response [" + str(response.status_code) + "] Not found")
        return response
    elif response.status_code == 401:
        print("Response [" + str(response.status_code) + "] Unauthorized")
        return response
    elif response.status_code == 500:
        print("Response [" + str(response.status_code) + "] there is some error on the server side")
        return response
    else:
        print("Unknown ERROR Response [" + str(response.status_code) + "]")
        return response


# get_BEnodes_list(mm_uri, mm_user, mm_pass, "DC2")
# returns a dictionary of all beapp hosts of corepod with their labels
def get_BEnodes_list(mm_uri, mm_user, mm_pass, corePodLabel):
    be_nodes = get_BEnodes_on_corepod(mm_uri, mm_user, mm_pass, corePodLabel)
    nodes = {}
    for node in range (0, len(be_nodes['items'])):
        nodes.update({be_nodes['items'][node]['hostName']:be_nodes['items'][node]['label']})
    return nodes


# to call: get_processes_on_be(mm_uri, mm_user, mm_pass, "DC2", "beapp-10")
# returns a dictionary like: {u'pldt': u'configuration_server', u'dmxmusic': u'configuration_server', u'geico': u'configuration_server'}
def get_processes_on_be(mm_uri, mm_user, mm_pass, corePodLabel, node):
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    processes = {}
    label = get_BEnodes_list(mm_uri, mm_user, mm_pass, corePodLabel)[node]
    headers = {'content-type': 'application/json'}
    url = mm_uri + "/v1/beNodes/" + label + "/processes"
    response = requests.get(url, auth=(mm_user, mm_pass), headers=headers, verify=False)
    if response.status_code == 200:
        #print("Response [" + str(response.status_code) + "] OK")
        proc_on_be = response.json()
        for process in range (0, len(proc_on_be['items'])):
            processes.update({proc_on_be['items'][process]['instanceName']:proc_on_be['items'][process]['name']})
        return processes
    elif response.status_code == 404:
        print("Response [" + str(response.status_code) + "] Not found")
        return response
    elif response.status_code == 401:
        print("Response [" + str(response.status_code) + "] Unauthorized")
        return response
    elif response.status_code == 500:
        print("Response [" + str(response.status_code) + "] there is some error on the server side")
        return response
    else:
        print("Unknown ERROR Response [" + str(response.status_code) + "]")
        return response
