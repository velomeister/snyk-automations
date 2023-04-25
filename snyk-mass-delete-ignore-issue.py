#!/usr/bin/python3

import urllib.request, urllib.parse
import json
import sys
import getopt
import datetime

def print_error(cause):
    print(cause)
    print('uso: snyk-mass-delete-ignore-issue.py -a <api-key> -o <org-id> -i <issue-id> [-c]')
    print('Para más ayuda usa el comando -h o --help')
    sys.exit(2)

def get_projects_affected_by_issue(api_key, org_id, issue_id):
    # Obtiene todos proyectos en los cuales un issue está presente.
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
    print('Total de proyectos a cambiar:', len(project_names))
    return project_ids

def delete_mass_ignore(api_key, org_id, issue_id, reason, reason_type, expires):
    # Itera sobre la lista de proyectos y genera una excepción temporal sobre el issue.
    project_ids = get_projects_affected_by_issue(api_key, org_id, issue_id)
    print('¿Desea continuar con la eliminación de las excepciones? (Y/n)')
    if input() in ('y', ''):
        print('Eliminando excepciones...')
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
        print('Un ID de issue es requerido para realizar la verificación.')
        sys.exit(2)
    get_projects_affected_by_issue(api_key, org_id,issue_id)
    sys.exit(0)

def main(argv):
    # Esta automatización tiene como flujo de trabajo:
    # - Busca un issue en todos los proyectos de la empresa y genera la lista
    # de proyectos afectados por un issue.
    # - Elimina la excepción emitida para todos los proyectos encontrados (si la hay).
    api_key, org_id, issue_id = '', '', ''
    check_only = False
    try:
        opts, args = getopt.getopt(argv, 'ha:o:i:c', ['help', 'api-key=', 'org-id=', 'issue-id=', 'check-project-list'])
    except getopt.GetoptError:
        print('uso: snyk-mass-delete-ignore-issue.py -a <api-key> -o <org-id> -i <issue-id> [-c]')
        print('Para más ayuda usa el comando -h o --help')
        sys.exit(2)
    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print('''
    uso: snyk-mass-delete-ignore-issue.py -a <api-key> -o <org-id> -i <issue-id> [-c]
    Genera excepciones en masa de un issue para todos los proyectos afectados según el ID del issue (vulnerabilidad o problema de licencia).

    -a / --api-key : API Key de la cuenta de servicio de Snyk. Requerido.
    -o / --org-id : El ID de la organización en Snyk. Requerido.
    -i / --issue-id : El ID del issue al que se le va a generar la excepción. Requerido.
    -c / --check-project-list : No aplica excepciones, solo lista los proyectos que van a ser afectados.
            ''')
            sys.exit(0)
        elif opt in ('-a', '--api-key'):
            api_key = arg
        elif opt in ('-o', '--org-id'):
            org_id = arg
        elif opt in ('-i', '--issue-id'):
            issue_id = arg
        elif opt in ('-c', '--check'):
            check_only = True
    if api_key == '':
        print_error('Se requiere un API Key de Snyk para continuar...')
    if org_id == '':
        print_error('Se requiere el ID de la organización en Snyk para continuar...')
    if issue_id ==  '':
        print_error('Un ID de issue es requerido para continuar...')
    if check_only:
        check_projects(api_key, org_id, issue_id)
    else:
        delete_mass_ignore(api_key, org_id, issue_id)

main(sys.argv[1:])