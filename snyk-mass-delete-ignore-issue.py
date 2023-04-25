#!/usr/bin/python3

import urllib.request, urllib.parse
import json
import sys
import getopt
import datetime

def print_error(cause):
    print(cause)
    print('Usage: snyk-mass-delete-ignore-issue.py -a <api-key> -o <org-id> -i <issue-id> [-c]')
    print('Use -h or --help for better help.')
    sys.exit(2)

def get_projects_affected_by_issue(api_key, org_id, issue_id):
    values = { "filters": { "orgs" : [org_id], "issues" : [issue_id] } }
    data = json.dumps(values)
    data = data.encode('utf-8')
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'token ' + api_key
    }
    toDate = datetime.datetime.today()
    fromDate = toDate - datetime.timedelta(days=5)
    params = {
        'from': str(fromDate.year) + "-" + str(fromDate.month) + "-" + str(fromDate.day),
        'to': str(toDate.year) + "-" + str(toDate.month) + "-" + str(toDate.day),
        'groupBy': 'issue'
    }
    p = urllib.parse.urlencode(params)
    request = urllib.request.Request('https://api.snyk.io/api/v1/reporting/issues/?' + p, data=data, headers=headers)
    response_body = urllib.request.urlopen(request)
    response = json.load(response_body)
    project_ids = [i['id'] for i in response['results'][0]['projects']]
    project_names = [i['name'] for i in response['results'][0]['projects']]
    for i in project_names:
        print(i)
    print('Total amount of affected projects:', len(project_names))
    return project_ids

def delete_mass_ignore(api_key, org_id, issue_id, reason, reason_type, expires):
    project_ids = get_projects_affected_by_issue(api_key, org_id, issue_id)
    print('¿Do you wish to continue? (Y/n)')
    if input() in ('y', ''):
        print('Deleting ignores...')
    else:
        sys.exit(1)
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'token ' + api_key
    }
    for project_id in project_ids:
        url = 'https://api.snyk.io/api/v1/org/' + org_id + '/project/' + project_id + '/ignore/' + issue_id
        request = urllib.request.Request(url, headers=headers, method="DELETE")
        response_body = urllib.request.urlopen(request)
        response = json.load(response_body)
        print(response)

def check_projects(api_key, org_id, issue_id):
    if issue_id ==  '':
        print('An issue ID is required to run the query.')
        sys.exit(2)
    get_projects_affected_by_issue(api_key, org_id,issue_id)
    sys.exit(0)

def main(argv):
    api_key, org_id, issue_id = '', '', ''
    check_only = False
    try:
        opts, args = getopt.getopt(argv, 'ha:o:i:c', ['help', 'api-key=', 'org-id=', 'issue-id=', 'query'])
    except getopt.GetoptError:
        print('Usage: snyk-mass-delete-ignore-issue.py -a <api-key> -o <org-id> -i <issue-id> [-q]')
        print('Use -h or --help for better help.')
        sys.exit(2)
    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print('''
    Usage: snyk-mass-delete-ignore-issue.py -a <api-key> -o <org-id> -i <issue-id> [-c]
    Removes any ignore created for an issue identified with an issue ID in all projects affected (dependency or license issue).

    -a / --api-key : Snyk's service account API key. Required.
    -o / --org-id : Org's ID on Snyk. Required.
    -i / --issue-id : The issue ID to delete the ignore. Required.
    -q / --query : Doesn\'t ignore vulnerabilities, just queries the affected projects. Optional.
            ''')
            sys.exit(0)
        elif opt in ('-a', '--api-key'):
            api_key = arg
        elif opt in ('-o', '--org-id'):
            org_id = arg
        elif opt in ('-i', '--issue-id'):
            issue_id = arg
        elif opt in ('-q', '--query'):
            check_only = True
    if api_key == '':
        print_error('A valid API key is required to continue...')
    if org_id == '':
        print_error('An org ID is required to continue...')
    if issue_id ==  '':
        print_error('An issue ID is required to continue...')
    if check_only:
        check_projects(api_key, org_id, issue_id)
    else:
        delete_mass_ignore(api_key, org_id, issue_id)

main(sys.argv[1:])