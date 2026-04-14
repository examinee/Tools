# PE Analyzer

## Description
PE 파일을 파싱하여 악성 의심 행위를 검사하는 정적 분석 툴.

### Features
- PE 섹션 abnormal size gap 탐지 (virtual_size vs raw_size)
- PE 섹션 엔트로피 기반 패킹 탐지
- IAT 파싱 및 의심 API 추출
- 인젝션 기법 탐지 (Process Hollowing, DLL Injection, Process Enumeration)
- 리소스 섹션 고엔트로피 및 숨겨진 PE (MZ 시그니처) 탐지
- JSON 형식 출력 지원
## Installation
- python 3.x
- pip install pefile

## Usage
```
python pe_analyzer.py file1.exe
python pe_analyzer.py file1.exe file2.exe file3.exe --json
```