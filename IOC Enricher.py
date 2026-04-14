import requests
import json
from datetime import datetime
import argparse
import time
import csv
API_KEY = "your_api_key_here"

def domain_extraction(file_path):
    domains = []
    with open(file_path, 'r') as f:
        domain_data = f.read()
        for d in domain_data.split(','):
            d = d.strip()
            if d:
                domains.append(d)
    return domains


def request_domain(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": API_KEY}
    response = requests.get(url, headers=headers)
    return response
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
        if response.status_code == 200:
            result.append(data_analysis(response.json()))
            print(f" {domain} [DONE]")
        else:
            print(f"[ERROR] {domain}: HTTP {response.status_code}")
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