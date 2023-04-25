#!/usr/bin/python3

import re
import urllib.request, urllib.parse
import json
import sys
import getopt
import datetime

def print_error(cause):
    print(cause)
    print('Usage: snyk-mass-ignore-issue.py -a <api-key> -o <org-id> -i <issue-id> [-r <reason>] [-t <reasonType>] [-e <expiration-date>] [-c]')
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
        'from': fromDate.strftime("%Y-%m-%d"),
        'to': toDate.strftime("%Y-%m-%d"),
        'groupBy': 'issue'
    }
    p = urllib.parse.urlencode(params)
    request = urllib.request.Request('https://api.snyk.io/api/v1/reporting/issues/?' + p, data=data, headers=headers, method="POST")
    response_body = urllib.request.urlopen(request)
    response = json.load(response_body)
    project_ids = [i['id'] for i in response['results'][0]['projects']]
    project_names = [i['name'] for i in response['results'][0]['projects']]
    for i in project_names:
        print(i)
    print('Total amount of projects to be changed:', len(project_names))
    return project_ids

def send_mass_ignore(api_key, org_id, issue_id, reason, reason_type, expires):
    project_ids = get_projects_affected_by_issue(api_key, org_id, issue_id)
    print('¿Do you wish to continue? (Y/n)')
    if input() in ('y', ''):
        print('Ignoring issues...')
    else:
        sys.exit(1)
    values = { 'reason': reason, 'reasonType': reason_type, 'disregardIfFixable': False, 'expires': expires }
    data = json.dumps(values)
    data = data.encode('utf-8')
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'token ' + api_key
    }
    for i in project_ids:
        url = 'https://api.snyk.io/api/v1/org/' + org_id + '/project/' + i + '/ignore/' + issue_id
        request = urllib.request.Request(url, data=data, headers=headers, method="POST")
        response_body = urllib.request.urlopen(request)
        response = json.load(response_body)
        print(response)

def check_projects(api_key, org_id, issue_id):
    if issue_id ==  '':
        print_error('An issue ID is required to run the check.')
    get_projects_affected_by_issue(api_key, org_id,issue_id)
    sys.exit(0)

def main(argv):
    api_key, org_id, issue_id, reason, reason_type, expires = '', '', '', '', '', ''
    check_only = False
    try:
        opts, args = getopt.getopt(argv, 'ha:o:i:r:t:e:q', ['help', 'api-key=', 'org-id=', 'issue-id=', 'reason=', 'reason-type=', 'expires=', 'query'])
    except getopt.GetoptError:
        print('Usage: snyk-mass-ignore-issue.py -a <api-key> -o <org-id> -i <issue-id> [-r <reason>] [-t <reasonType>] [-e <expiration-date>] [-q]')
        print('Use -h or --help for better help.')
        sys.exit(2)
    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print('''
    Usage: snyk-mass-ignore-issue.py -a <api-key> -o <org-id> -i <issue-id> [-r <reason>] [-t <reasonType>] [-e <expiration-date>] [-c]
    Ignores issues identified by an issue ID in mass for all projects affected (dependency or license issue).

    -a / --api-key : Snyk's service account API key. Required.
    -o / --org-id : Org's ID on Snyk. Required.
    -i / --issue-id : The issue ID to ignore. Required.
    -r / --reason : The reason to ingore the issue. Required to send ignores, not for queries.
    -t / --reason-type : The reason type to ignore the issue. Only three possible values are admitted: not-vulnerable, wont-fix, temporary-ignore. Required to send ingores, not for queries.
    -e / --expires : Date ,  "yyyy-mm-dd hh:mm". Required if the reason type is "temporary-ignore".
    -q / --query : Doesn\'t ignore vulnerabilities, just queries the affected projects. Optional.
            ''')
            sys.exit(0)
        elif opt in ('-a', '--api-key'):
            api_key = arg
        elif opt in ('-o', '--org-id'):
            org_id = arg
        elif opt in ('-i', '--issue-id'):
            issue_id = arg
        elif opt in ('-r', '--reason'):
            reason = arg
        elif opt in ('-t', '--reason-type'):
            if arg not in ('not-vulnerable', 'wont-fix', 'temporary-ignore'):
                print('There\'s only three valid reason type values: not-vulnerable, wont-fix, temporary-ignore.')
                sys.exit(2)
            else:
                reason_type = arg
        elif opt in ('-e', '--expires'):
            # expires = arg
            expires = arg + " 08:00:00"
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
        if reason ==  '':
            print_error('A valid reason is required to continue...')
        if reason_type ==  '':
            print_error('A reason type is required to continue...')
        send_mass_ignore(api_key, org_id, issue_id, reason, reason_type, expires)

main(sys.argv[1:])