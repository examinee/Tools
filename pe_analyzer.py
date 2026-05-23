import pefile
import os
import hashlib
from datetime import datetime
import math
import argparse
import json


black_imps = ['CreateRemoteThread', 'NtUnmapViewOfSection', 'VirtualAlloc', 'CreateProcess', 'WriteProcessMemory', 'NtResumeThread','VirtualProtect','NtWriteVirtualMemory','CreateToolhelp32Snapshot','Process32First', 'Process32Next','OpenProcess']
injection_patterns = {
    'Process Hollowing': ['CreateProcess', 'NtUnmapViewOfSection', 
                          'VirtualAlloc', 'WriteProcessMemory'],
    'DLL Injection': ['OpenProcess', 'VirtualAlloc', 
                      'WriteProcessMemory', 'CreateRemoteThread'],
    'Process Enumeration': ['CreateToolhelp32Snapshot', 
                            'Process32First', 'Process32Next']
}

def calc_entropy(data):
    if not data:
        return 0
    entropy = 0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    for count in counts:
        if count > 0:
            p_x = count / len(data)
            entropy += - p_x * math.log(p_x, 2)
    return entropy


def get_file_info(file_path):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
    except FileNotFoundError:
        print(f"[ERROR] 파일을 찾을 수 없습니다: {file_path}")
        exit(1)
    except PermissionError:
        print(f"[ERROR] 파일 읽기 권한이 없습니다: {file_path}")
        exit(1)
    else:
        try:
            pe = pefile.PE(file_path)
        except pefile.PEFormatError:
            print(f"[ERROR] 유효한 PE 파일이 아닙니다: {file_path}")
            exit(1)
    md5 = hashlib.md5(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    timestamp = pe.FILE_HEADER.TimeDateStamp
    compile_time = datetime.fromtimestamp(timestamp)
    dangerous_imports =set()
    check_imports = []
    resource_entropy_flag = False
    resource_pe_flag = False
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            for resource_id in resource_type.directory.entries:
                for resource_lang in resource_id.directory.entries:
                    rva = resource_lang.data.struct.OffsetToData
                    size = resource_lang.data.struct.Size
                    resource_data  = pe.get_data(rva, size)
                    if calc_entropy(resource_data) > 7.0:
                        resource_entropy_flag = True
                    if len(resource_data) >= 2 and resource_data[0] == 0x4D and resource_data[1] == 0x5A:
                        resource_pe_flag = True

    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for dlls in pe.DIRECTORY_ENTRY_IMPORT:
            for imps in dlls.imports:
                if imps.name:
                    func_name = imps.name.decode()
                    for black_api in black_imps:
                        if black_api in func_name:
                            dangerous_imports.add(func_name)
                else:
                    check_imports.append(f"Ordinal({imps.ordinal})")
    sections = []
    for section in pe.sections:
        sections.append({
            'name': section.Name.decode().strip('\x00'),
            'virtual_size': section.Misc_VirtualSize,
            'raw_size' : section.SizeOfRawData,
            'entropy' : calc_entropy(section.get_data())
        })      
        
    result ={
        'filename' : os.path.basename(file_path),
        'size' : os.path.getsize(file_path),
        'md5' : md5,
        'sha256' : sha256,
        'sha1' : sha1,
        'compile_time' : compile_time.strftime('%Y-%m-%d %H:%M:%S'),
        'sections' : sections,
        'dangerous_imports' : dangerous_imports,
        'check_imports' : check_imports,
        'resources': {
            'high_entropy': resource_entropy_flag,
            'hidden_pe': resource_pe_flag
        }
    }
    return result

def injection_detection(info):
    match_tech = []
    for tech, require_api in injection_patterns.items():
        match = 0
        for imp in info['dangerous_imports']:
            for api in require_api:
                if imp.startswith(api):
                    match += 1
        if match >= 3:
            match_tech.append(tech)
    return match_tech


def result_print(info):   
    print(f"Filename: {info['filename']}")
    print(f"Size: {info['size']} bytes")
    print(f"MD5: {info['md5']}")
    print(f"SHA256: {info['sha256']}")
    print(f"SHA1: {info['sha1']}")
    print(f"Compile Time: {info['compile_time']}")
    for section in info['sections']:
        if section['virtual_size'] > section['raw_size'] * 10 and section['raw_size'] > 0:
            print(f"Abnormal Size Gap Detected! : {section['name']}")
        if section['entropy'] > 7.0:
            print(f"high entropy detected! : {section['name']}")
    if info['resources']['high_entropy'] == True:
        print(f"high resource entropy detected! : {info['resources']}")
    if info['resources']['hidden_pe'] == True:
        print(f"PE file in resource detected! : {info['resources']}")
    injection_techs = injection_detection(info)
    if injection_techs:
        print(f"Injection technique detected! : {', '.join(injection_techs)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('files', nargs='+')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args()
    for file_path in args.files:
        info = get_file_info(file_path)
        result_print(info)
        if args.json:
           output = info.copy()
           output['dangerous_imports'] = list(info['dangerous_imports'])
           print(json.dumps(output, indent=2))
             