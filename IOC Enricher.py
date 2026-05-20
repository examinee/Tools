import requests
import json
from datetime import datetime
import argparse
import time
import csv
import os
import re

DOMAIN_PATTERN = re.compile(
    r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$'
)
MAX_DOMAIN_LENGTH = 253
def get_api_key():
    key= os.getenv('VT_API_KEY')
    if not key:
        print("[ERROR] 환경 변수 'VT_API_KEY'가 설정되지 않았습니다.")
        exit(1)
    return key
key = get_api_key()

def domain_extraction(file_path):
    domains = []
    invalid_domains = []
    try:
        with open(file_path, 'r') as f:
            domain_data = f.read()
    except FileNotFoundError:
        print(f"[ERROR] 파일을 찾을 수 없습니다: {file_path}")
    except PermissionError:
        print(f"[ERROR] 파일 읽기 권한이 없습니다: {file_path}")
    else:
        for d in domain_data.split(','):
            d = d.strip()
            if not d:
                continue
            if DOMAIN_PATTERN.match(d) and len(d) <= MAX_DOMAIN_LENGTH:
                domains.append(d)
            else:
                invalid_domains.append(d)
        if invalid_domains:
            print(f"[WARNING] 유효하지 않은 도메인: {', '.join(invalid_domains)}")
    return domains


def request_domain(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": key}
    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        return response
    except requests.exceptions.Timeout:
        print(f"[ERROR] {domain}: 요청 타임아웃")
        return None
    except requests.exceptions.HTTPError as e:
        print(f"[ERROR] {domain}: HTTP {e.response.status_code}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] {domain}: {e}")
        return None



def data_analysis(data):
    ip_list = []
    for r in data['data']['attributes'].get('last_dns_records', []):
        if r['type'] == 'A':
            ip_list.append(r['value'])
    result = {
    'domain': data['data']['id'],
    'malicious': data['data']['attributes']['last_analysis_stats']['malicious'],
    'total': data['data']['attributes']['last_analysis_stats']['malicious'] + data['data']['attributes']['last_analysis_stats']['harmless'] + data['data']['attributes']['last_analysis_stats']['suspicious'] + data['data']['attributes']['last_analysis_stats']['undetected'],
    'creation_date': datetime.fromtimestamp(data['data']['attributes'].get('creation_date', 0)).strftime('%Y-%m-%d'),
    'ip': ip_list,
    'tld': data['data']['attributes']['tld'],
}
    return result
def save_json(data, output_path):
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=4)
        
def save_csv(data, output_path):
    if not data:
        return
    rows = []
    for r in data:
        row = r.copy()
        row['ip'] = ';'.join(r['ip'])
        rows.append(row)
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

if __name__ == "__main__":
    result = []
    parser = argparse.ArgumentParser()
    parser.add_argument('files')
    parser.add_argument('--csv', action='store_true')
    args = parser.parse_args()
    for domain in domain_extraction(args.files):
        print(f"Checking domain: {domain}")
        response = request_domain(domain)
        if response:
            result.append(data_analysis(response.json()))
        time.sleep(15)
    if result:
        save_json(result, 'c2_output_file.json')
    else:
        print("[WARNING] 저장할 결과가 없습니다.")
    if args.csv:
        if result:
            save_csv(result, 'c2_output_file.csv')
        else:
            print("[WARNING] 저장할 결과가 없습니다.")