# AsylumEnforce — phese (폐쇄!)

**PHP high enforcing-security essentials**. 한국어 솔루션 별칭은 **“어떻게 병동이름이 폐쇄야” 보호 시스템**입니다.

PHP 엔진 보안 업데이트를 필수 조건으로 삼고, Linux 커널의 seccomp와 파일·네트워크 격리를 결합하는 방어 코드입니다. Suhosin의 보호 목적을 이어가는 새 프로젝트이며 Suhosin의 모든 기능을 구현한 확장이나 모든 CVE를 차단하는 제품은 아닙니다. **1.0.0**의 정식 지원 대상은 [검증 문서](docs/validation.md)의 플랫폼과 프로필로 한정합니다.

## 기본 동작

- PHP **8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 이상**의 해당 안정 브랜치를 확인합니다. 미패치 버전·미지원 브랜치·시험판은 실행을 거부합니다. 버전 허용 규칙과 정식 검증 범위는 구분합니다.
- 네이티브 `phese` 확장이 프로세스 실행, ptrace, namespace 변경, 주요 커널 관리 호출을 seccomp로 차단합니다. `disable_functions`에만 의존하지 않습니다.
- `phese run`은 bubblewrap 격리 안에서 앱을 읽기 전용으로 실행합니다. 임시 디렉터리는 별도이며 네트워크는 기본 차단합니다. 필요한 앱 내부 쓰기 디렉터리만 명시합니다.
- `phese scan`은 PHP 소스에서 검토할 위치를 찾아 **로컬 수정 요청 JSON**을 만듭니다. 소스는 바꾸지 않고 외부 메시지·GitHub issue를 자동 전송하지 않습니다.
- 서버 서비스에는 별도의 systemd 정책을 계획·적용·원복할 수 있습니다. CLI 실행과 운영 FPM/Apache의 보호는 각각 적용해야 합니다.

## 설치와 실행

정식 지원 프로필은 Linux x86_64·glibc·PHP 8.5.12 ZTS입니다. Python 3.10+, bubblewrap 0.10+, gcc 및 실행할 PHP와 맞는 `phpize`/`php-config`가 필요합니다. 실제 검증한 플랫폼과 범위는 [검증 문서](docs/validation.md)를 확인하세요. 배포 파일과 체크섬은 [GitHub Releases](https://github.com/NiSeullent/phese/releases)에서 제공하며 [배포 자동화](docs/releases.md)는 필수 CI 성공 후 게시합니다.

```bash
git clone https://github.com/NiSeullent/phese.git
cd phese
sudo ./tools/bootstrap.sh --php /path/to/patched/php \
  --php-config /path/to/matching/php-config --apply
phese setup --app /path/to/app
phese setup --app /path/to/app --write /path/to/app/storage --apply
phese start --config /path/to/app/.phese/config.json index.php

# 개별 런타임과 확장을 직접 지정할 수도 있습니다.
phese doctor --php /path/to/patched/php --extension /path/to/matching/phese.so

phese run --php /path/to/patched/php \
  --extension "$PWD/extension/modules/phese.so" \
  --app /path/to/app index.php

phese run --php /path/to/patched/php \
  --extension "$PWD/extension/modules/phese.so" \
  --app /path/to/app --write /path/to/app/storage index.php

phese scan /path/to/app --output /private/reports/change-requests.json
```

설치 전 `--apply`를 생략하면 계획만 검사합니다. 앱 설정은 앱 소유자로 실행합니다. [설치·자동 설정](docs/setup.md)에서 탐지와 Codex/Claude Code 지침 연동 범위를 확인할 수 있습니다. 설치 명령은 root 권한으로 실행합니다. 설치 없이 `python3 -m phese`도 사용할 수 있습니다. PHP 확장은 별도로 빌드·관리하며 `phpize`/`php-config`는 같은 PHP 설치의 도구여야 합니다. ABI, ZTS/NTS, libc가 다른 바이너리 사이에 `.so`를 공유하지 마세요.

`run`은 호스트 INI, 환경변수와 PHP 확장 검색 경로를 상속하지 않습니다. 컴파일된 확장은 유지되지만 별도의 동적 확장·환경변수·DB Unix 소켓·호스트 파일·외부 명령이 필요한 앱에는 추가 설계가 필요합니다. root 실행 시 내부 UID/GID는 65534이며 앱 읽기와 명시 쓰기 경로의 Unix 권한도 충족해야 합니다. 기존 앱의 무조건적인 호환성을 보장하지 않습니다. `--network host`는 명시적으로 호스트 네트워크를 허용하며 이 경우 SSRF·외부 유출 차단을 보장하지 않습니다.

`--timeout`은 실행 시간을 제한합니다. fork 수·메모리 총량·디스크 사용량의 완전한 상한이 필요한 작업은 systemd/cgroup 제한도 적용하세요. `RLIMIT_AS`/`RLIMIT_DATA`는 두 CVE의 완화책으로 사용하지 않습니다.

## 자동 설정과 AI 계획

```bash
sudo python3 tools/install_autosetup.py --install --php /path/to/patched/php
phese-setup --php /path/to/patched/php --discover-services --assistant-inventory
# 기존 계정의 Codex 또는 Claude Code로 허용된 설정 계획 요청
phese-setup --php /path/to/patched/php --service your-php.service --assistant codex
```

기본값은 모델 호출 없는 진단입니다. 서비스 적용은 명시한 대상과 정상 상태 확인 명령을 사용합니다. AI는 공개 개수·boolean 요약만 받고 기존 정책 안에서 권고하며 임의 명령을 만들거나 실행하지 않습니다. [자동 설정 안내](docs/auto-setup.md)에 설치·계정·도구 범위와 오류 처리, [앱 설정 안내](docs/setup.md)에 프로젝트 지침 연동을 설명합니다.

## PHP 서버에 적용

[네이티브 확장 안내](extension/README.md)와 [서버 적용·원복 절차](docs/server-rollout.md)를 먼저 읽고 격리된 PHP-FPM 및 Apache에서 검증합니다. 웹 서비스의 네이티브 확장은 [웹 설치 도구](docs/web-install.md)로 서비스별로 로드하고 `phese.scope=worker`를 사용합니다. FPM의 USR2와 Apache의 graceful reload를 유지하며, 요청 worker에서 필터를 설치합니다. 입력 처리 전 보호는 필수 PHP 엔진 패치가 담당합니다. 외부 프로그램을 실행하는 PHP 기능은 차단되므로 해당 기능은 수정 요청으로 검토해야 합니다. CLI 설치만으로 기존 서비스가 보호되지는 않습니다.

```bash
python3 tools/service_guard.py plan your-php-fpm.service
python3 tools/service_guard.py apply your-php-fpm.service --apply \
  --health-check '["/usr/bin/curl","--fail","--silent","--max-time","10","http://127.0.0.1/health"]'
python3 tools/service_guard.py status your-php-fpm.service
python3 tools/service_guard.py rollback your-php-fpm.service --apply
```

서비스 정책은 PHP 엔진 패치나 네이티브 확장 로드를 대신하지 않습니다. 두 CVE의 직접적인 수정은 PHP 공식 보안 패치입니다. 이미 실행 중인 worker에는 파일 변경만으로 보호가 생기지 않으며 재생성 후 확인해야 합니다.

## 보장 범위와 개발

[CVE 대응 근거](docs/cve-coverage.md), [위협 모델](docs/threat-model.md), [보안 정책](SECURITY.md)에 보호 경계와 남는 위험을 설명합니다. SQL injection, XSS, 권한 검사 오류, 허용된 파일·DB·네트워크의 악용은 별도 앱 보안 조치가 필요합니다. 탐지는 휴리스틱이므로 오탐·누락이 있습니다.

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q phese tools tests
```

차단 화면은 JSON 하나로 바꿀 수 있습니다: `phese page init /secure/path/theme.json`, `phese page build --config /secure/path/theme.json --output /secure/path/page`. [사용자 설정](docs/customization.md)에서 문구·미디어·이동 확률과 CSP 생성을 설명합니다.

차단 화면은 [입원 안내](docs/block-page.md), 실제 원인과 입원 과정의 누적 기록은 [로그 안내](docs/logging.md)를 확인하세요. 호스트의 추가 보안 업데이트는 [읽기 전용 감사](docs/host-audit.md)로 확인할 수 있습니다.

[기여 안내](CONTRIBUTING.md)와 [변경 기록](CHANGELOG.md)을 함께 제공합니다.

MIT 라이선스. 공개 저장소에는 방어 코드와 일반적인 검증만 포함하고 서버 인벤토리·인증값·고객 코드·비공개 수정 요청은 포함하지 않습니다.
