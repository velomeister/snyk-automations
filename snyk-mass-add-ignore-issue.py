#!/usr/bin/python3

import re
import urllib.request, urllib.parse
import json
import sys
import getopt
import datetime

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
    print('Total de proyectos a cambiar:', len(project_names))
    return project_ids

def send_mass_ignore(api_key, org_id, issue_id, reason, reason_type, expires):
    # Itera sobre la lista de proyectos y genera una excepción temporal sobre el issue.
    project_ids = get_projects_affected_by_issue(api_key, org_id, issue_id)
    print('¿Desea continuar con la ejecución de las excepciones? (Y/n)')
    if input() in ('y', ''):
        print('Ejecutando excepciones...')
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
        print('Un ID de issue es requerido para realizar la verificación.')
        sys.exit(2)
    get_projects_affected_by_issue(api_key, org_id,issue_id)
    sys.exit(0)

def main(argv):
    # Esta automatización tiene como flujo de trabajo:
    # - Busca un issue en todos los proyectos de la empresa y genera la lista
    # de proyectos afectados.
    # - Emite una excepción global (temporal) para todos los proyectos encontrados.
    api_key, org_id, issue_id, reason, reason_type, expires = '', '', '', '', '', ''
    check_only = False
    try:
        opts, args = getopt.getopt(argv, 'ha:o:i:r:t:e:c', ['help', 'api-key=', 'org-id=', 'issue-id=', 'reason=', 'reason-type=', 'expires=', 'check-project-list'])
    except getopt.GetoptError:
        print('uso: snyk-mass-ignore-issue.py -a <api-key> -o <org-id> -i <issue-id> -r <reason> -t <reasonType> [-e <expiration-date>] [-c]')
        print('Para más ayuda usa el comando -h o --help')
        sys.exit(2)
    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print('''
    uso: snyk-mass-ignore-issue.py -a <api-key> -o <org-id> -i <issue-id> -r <reason> -t <reasonType> [-e <expiration-date>] [-c]
    Genera excepciones en masa de un issue para todos los proyectos afectados según el ID del issue (vulnerabilidad o problema de licencia).

    -a / --api-key : API Key de la cuenta de servicio de Snyk. Requerido.
    -o / --org-id : El ID de la organización en Snyk. Requerido.
    -i / --issue-id : El ID del issue al que se le va a generar la excepción. Requerido.
    -r / --reason : La razón por la que se va a generar la excepción. Requerido para aplicar las excepciones, no para consultar.
    -t / --reason-type : El tipo de razón. Solo hay tres valores admitidos: not-vulnerable, wont-fix, temporary-ignore. Requerido para aplicar las excepciones, no para consultar.
    -e / --expires : Fecha de expiración de la excepción en formato "yyyy-mm-dd hh:mm". Opcional.
    -c / --check-project-list : No aplica excepciones, solo lista los proyectos que van a ser afectados. Opcional.
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
                print('Solo hay tres valores admitidos para el tipo de razón: not-vulnerable, wont-fix, temporary-ignore.')
                sys.exit(2)
            else:
                reason_type = arg
        elif opt in ('-e', '--expires'):
            # expires = arg
            expires = arg + " 08:00:00"
        elif opt in ('-c', '--check'):
            check_only = True
    if api_key == '':
        print('Se requiere un API Key de Snyk para continuar...')
        print('uso: snyk-mass-add-ignore-issue.py -a <api-key> -o <org-id> -i <issue-id> -r <reason> -t <reasonType> [-e <expiration-date>] [-c]')
        print('Para más ayuda usa el comando -h o --help')
        sys.exit(2)
    if org_id == '':
        print('Se requiere el ID de la organización en Snyk para continuar...')
        print('uso: snyk-mass-add-ignore-issue.py -a <api-key> -o <org-id> -i <issue-id> -r <reason> -t <reasonType> [-e <expiration-date>] [-c]')
        print('Para más ayuda usa el comando -h o --help')
        sys.exit(2)
    if issue_id ==  '':
        print('Un ID de issue es requerido para continuar...')
        print('uso: snyk-mass-add-ignore-issue.py -a <api-key> -o <org-id> -i <issue-id> -r <reason> -t <reasonType> [-e <expiration-date>] [-c]')
        print('Para más ayuda usa el comando -h o --help')
        sys.exit(2)
    if check_only:
        check_projects(api_key, org_id, issue_id)
    else:
        if reason ==  '':
            print('Una razón es requerida para aplicar las excepciones...')
            print('uso: snyk-mass-add-ignore-issue.py -a <api-key> -o <org-id> -i <issue-id> -r <reason> -t <reasonType> [-e <expiration-date>] [-c]')
            print('Para más ayuda usa el comando -h o --help')
            sys.exit(2)
        if reason_type ==  '':
            print('Un tipo de razón es requerida para aplicar las excepciones...')
            print('uso: snyk-mass-add-ignore-issue.py -a <api-key> -o <org-id> -i <issue-id> -r <reason> -t <reasonType> [-e <expiration-date>] [-c]')
            print('Para más ayuda usa el comando -h o --help')
            sys.exit(2)
        send_mass_ignore(api_key, org_id, issue_id, reason, reason_type, expires)

main(sys.argv[1:])