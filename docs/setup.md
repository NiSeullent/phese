# CLI 설치와 자동 설정

설치 과정은 로컬에서 확보하고 검토한 소스로 실행한다. 설치 도구는 OS 패키지·PHP 바이너리를 내려받거나 PHP 코드를 고치지 않으며, 운영 FPM/Apache에 확장을 자동 로드하거나 서비스를 재시작하지 않는다.

```bash
# 같은 PHP 설치의 실행 파일과 개발 도구로 계획 검사
./tools/bootstrap.sh --php /path/to/php --php-config /path/to/php-config

# 계획이 통과한 설정으로 CLI와 네이티브 확장 설치
sudo ./tools/bootstrap.sh --php /path/to/php --php-config /path/to/php-config --apply

# 설치된 CLI 또는 wheel에서 네이티브 확장을 설치할 때
phese install --source /path/to/phese-source \
  --php /path/to/php --php-config /path/to/php-config
sudo phese install --source /path/to/phese-source \
  --php /path/to/php --php-config /path/to/php-config --apply

# 앱별 권한·런타임·보호 확장·Codex/Claude 설정 계획
python3 -m phese.setup --app /path/to/app

# 앱 소유자로 실행: 필요한 데이터 쓰기 경로만 명시해 적용
python3 -m phese.setup --app /path/to/app --write /path/to/app/storage --apply

# 생성된 설정으로 실행. 앱 디렉터리에서는 --config 생략 가능
python3 -m phese.setup run --config /path/to/app/.phese/config.json index.php
```

설치된 CLI에서는 `phese setup ...` 및 `phese start --config ... index.php`로 같은 기능을 사용할 수 있다. 위 모듈 명령은 소스 배포본에서도 사용할 수 있다.

Python wheel에는 네이티브 C 확장의 빌드 SDK와 소스 설치 도구가 포함되지 않는다. wheel의 `doctor`, `page`, `setup`, `start`는 별도로 준비한 런타임·모듈과 사용할 수 있지만, `install`에는 검토한 전체 소스 배포본이 필요하다. `--source`로 소스 경로를 명시할 수 있다. 생략하면 현재 실행 중인 모듈의 상위 디렉터리에 SDK가 있는지 확인하고, 없으면 현재 작업 디렉터리가 완전한 소스 배포본인지 확인한다. 둘 다 아니면 설치를 중단하고 `--source` 사용을 안내한다. 현재 디렉터리의 이름이나 Python 패키지 존재만으로 빌드 소스로 신뢰하지 않는다. 계획 검사부터 빌드 파일의 존재·소유권·쓰기 권한을 검사하며, 소스나 의존성을 자동 다운로드하지 않는다.

Bootstrap은 PHP와 `php-config --version`의 버전 일치, `phpize --version`의 PHP·Zend 모듈 API 번호, `php-config --extension-dir`의 ABI·ZTS 표기를 서로 확인한다. C 컴파일러, make, autoconf 및 bubblewrap 0.10 이상도 필요하다. ABI 표기가 없는 SDK 디렉터리 배치는 자동 승인하지 않으며 별도 검증이 필요하다. 실행 중인 PHP와 맞는 확장을 빌드한 뒤 실제 `phese_status()`를 검사한다. 버전·ABI·필수 보호를 확인하지 못하면 설치를 중단한다. root 소유이며 공유 쓰기 권한이 없는 소스와 실행 도구만 시스템 설치에 사용한다. 기존 모듈의 설치 기록과 SHA-256이 다르면 덮어쓰지 않는다. 설치 성공은 기존 웹서비스가 보호됐다는 뜻이 아니다.

앱 설정은 명시하지 않으면 설치된 수정 PHP 및 일치하는 네이티브 모듈을 검사해 선택한다. `--php`, `--extension`으로 정확한 경로를 선택할 수 있다. 자동 선택은 안전성 증거를 확인하는 과정이며, PHP나 모듈을 인터넷에서 자동으로 가져오는 기능은 아니다. 숫자상 미패치 PHP, 지원하지 않은 브랜치, 로드되지 않은 모듈과 불충분한 bubblewrap은 거부한다.

자동 설정의 기본값은 네트워크 차단, 60초 실행 제한, 앱 읽기 전용이다. 발견한 `storage`, `cache`, `tmp`는 쓰기 후보로 표시하고 자동 승인하지 않는다. `--write`로 지정한 앱 내부 디렉터리만 설정에 추가하며 소유권·권한은 변경하지 않는다. root 실행의 실제 sandbox 호스트 UID/GID 65534가 읽기·쓰기에 필요한 Unix 권한도 충족해야 한다. 현재 워크로드를 측정하지 않고 성능이 최적이라고 주장하거나 자원 제한을 임의 확대하지 않는다.

`--apply`는 다음 파일만 기록한다.

- 앱의 `.phese/config.json`: 해당 사용자 전용 설정
- 별도 상태 디렉터리의 `config.json`, `requests.json`, `manifest.json`: 기본 root 경로는 `/var/lib/asylumenforce/apps/<앱 경로 해시>`이며 일반 사용자는 `~/.local/state/phese/apps/<해시>`를 사용한다. `--state-dir`로 앱과 겹치지 않는 경로를 지정할 수 있다.
- 선택한 도우미의 `AGENTS.md`, `CLAUDE.md` 관리 구역

앱과 수정할 파일은 실행 사용자가 소유하고, 다른 사용자가 쓸 수 없는 경로여야 한다. root가 서비스 사용자 소유의 앱 지침을 무조건 바꾸지 않는다. 해당 앱 소유자로 설정하거나, 관리자가 배포 트리의 권한을 별도로 검토한다. 심볼릭 링크, 손상된 관리 표식, 다른 도구의 `.phese/config.json`은 거부한다. 기존 프로젝트 지침은 관리 구역 밖에서 그대로 보존하며 적용 중 파일이 바뀌면 중단한다. 파일 적용 실패 시 이미 변경한 설정은 원래 내용으로 복구하고, 복구를 확인할 수 없으면 성공을 반환하지 않는다.

## Codex와 Claude Code 연동 범위

기본 `--assistants codex,claude`는 Codex의 `AGENTS.md`, Claude Code의 `CLAUDE.md`에 같은 프로젝트 범위 지침을 넣는다. 하나만 원하면 `--assistants codex` 또는 `--assistants claude`, 지침 생성을 제외하려면 `--assistants none`을 사용한다.

지침에는 보호 상태 검사와 비공개 수정 요청 생성용 argv 배열, PHP 코드 자동 재작성 금지, 필수 보호 우회 금지, 비밀·고객 코드 자동 전송 금지 및 기존 프로젝트 규칙 보존이 포함된다. 명령 경로는 데이터로 처리하며 셸에서 eval하지 않는다. 기존 사용자 지시가 이 지침보다 우선한다.

이 연동은 도우미가 프로젝트에서 읽는 지침을 준비하는 기능이다. Codex·Claude CLI의 설치·로그인·모델 호출이나 전역 설정 변경을 수행했다고 보고하지 않는다. 모델을 호출하지 않으므로 자동으로 모델 사용료가 발생하거나 프로젝트 코드가 외부 모델로 전송되지 않는다.

## 검증 범위

실제 정식 지원 범위는 릴리스 검증 문서에서 확인한다. 현재 개발 환경은 Linux x86_64, PHP 8.5.12 ZTS이며 다른 PHP ABI·libc·아키텍처에 같은 바이너리를 복사하지 않는다. 모든 CVE의 차단이나 모든 기존 앱의 무변경 호환성을 보장하지 않는다.

```bash
python3 -m unittest discover -s tests -p test_setup.py -v
```

설정 테스트는 임시 앱과 명령 대역으로 실행하고, 실제 운영 서비스나 모델 CLI를 실행하지 않는다.
