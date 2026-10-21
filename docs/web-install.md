# 웹 서비스 전용 phese 설치

`tools/web_guard.py`는 지정한 systemd 웹 서비스에만 별도 PHP INI 검색 경로를 추가합니다. 기본 `php.ini`, 기본 CLI 검색 디렉터리, PHP 앱 소스와 서비스의 `ExecReload`는 수정하지 않습니다. 실제 배포 대상은 먼저 공식 보안 패치를 적용한 PHP여야 합니다.

현재 배포 대상은 Linux x86_64 / glibc / PHP 8.5.12 ZTS입니다. 대상 PHP와 ABI가 일치하는 최종 네이티브 모듈, 검토한 페이지 빌더 출력, 해당 서비스를 실제로 통과하는 상태 확인 명령을 준비합니다. 서비스 전체에 환경 변수를 적용하므로 기존 `ExecStartPre` 등에서 별도 PHP CLI를 실행한다면 그 명령도 미리 검증해야 합니다.

## 준비와 계획

페이지 빌더가 생성한 `phese-page.ini`를 사용합니다. 파일에는 `phese.block_page`와 `phese.block_csp` 두 지시문만 허용합니다. 경로 전체가 root 소유이고 다른 사용자가 쓸 수 없어야 하며 심볼릭 링크는 허용하지 않습니다. HTML은 UTF-8, 최대 256 KiB, `{{EVENT_ID}}`와 `{{TIMESTAMP}}`를 포함하는 공개용 문서여야 합니다. CSP는 비어 있지 않은 최대 4 KiB 값이어야 합니다.

다음은 이 서버 경로를 사용한 계획 명령입니다. `--page-ini`는 검토를 끝낸 빌더 출력 위치로 지정합니다.

```sh
python3 /srv/asylumenforce/tools/web_guard.py plan your-php-fpm.service \
  --php /opt/php/bin/php \
  --extension /srv/asylumenforce/extension/modules/phese.so \
  --scan-dir /etc/php.d \
  --page-ini /usr/local/share/asylumenforce/block-page/phese-page.ini \
  --scope worker

python3 /srv/asylumenforce/tools/web_guard.py plan your-apache.service \
  --php /opt/php/bin/php \
  --extension /srv/asylumenforce/extension/modules/phese.so \
  --scan-dir /etc/php.d \
  --page-ini /usr/local/share/asylumenforce/block-page/phese-page.ini \
  --scope worker
```

`plan`은 파일·디렉터리·잠금을 만들거나 명령을 실행하지 않습니다. `apply`나 `rollback`도 `--apply`가 없으면 계획만 출력합니다. `--system-root`를 지정한 CLI 실행은 읽기 전용입니다. 테스트는 별도 임시 시스템 루트와 가짜 명령 실행기를 사용하며 실제 systemd를 호출하지 않습니다.

이 웹 설치 도구는 FPM과 Apache 모두 `worker` 프로필만 허용하며 CLI 기본값도 `worker`입니다. `--scope startup`은 거부합니다. FPM master는 기존 USR2 재실행을 유지하고 워커가 권한을 낮춘 뒤 필터를 설치합니다. Apache도 실제 워커의 요청 처리 단계에서 필터를 설치하는 지원 버전이 필요합니다. 최종 네이티브 모듈의 Apache worker/재로드 회귀 검증을 마치기 전에는 배포하지 않습니다. 네이티브 `startup` 프로필은 독립 CLI 검사·샌드박스에 사용합니다. 웹 master에 설치하면 재실행이나 재로드 시 필터가 누적될 수 있으므로 이 도구로 선택할 수 없습니다.

## 적용

`--health-check`는 절대 경로 실행 파일을 첫 항목으로 갖는 JSON argv입니다. 셸 명령은 허용하지 않습니다. 정상 상태 확인은 적용 전과 서비스 재시작 후에 모두 실행합니다. 응답 본문이나 실패한 명령의 출력은 설치 상태나 콘솔에 기록하지 않습니다. 상태 확인 argv 자체는 재시도와 원복을 위해 root 전용 상태 파일에 보관하므로 인증 비밀을 인자로 넘기지 않는 전용 확인 도구를 권장합니다.

예시의 상태 경로는 실제 FPM 서비스로 요청이 전달되는 정상 경로로 바꿉니다. Apache에서 직접 처리되는 페이지를 확인하는 것만으로 FPM의 상태를 검증할 수 없습니다.

```sh
python3 /srv/asylumenforce/tools/web_guard.py apply your-php-fpm.service \
  --php /opt/php/bin/php \
  --extension /srv/asylumenforce/extension/modules/phese.so \
  --scan-dir /etc/php.d \
  --page-ini /usr/local/share/asylumenforce/block-page/phese-page.ini \
  --scope worker \
  --config-check '["/opt/php/sbin/php-fpm","--fpm-config","/etc/php-fpm.conf","-t"]' \
  --health-check '["/usr/bin/curl","--fail","--silent","--output","/dev/null","--header","Host: example.com","http://127.0.0.1:8080/health"]' \
  --apply
```

Apache의 명령도 동일한 입력을 사용하되 서비스명을 `your-apache.service`로, 구성 확인을 다음 JSON argv로 지정합니다.

```json
["/opt/apache/sbin/httpd", "-t", "-f", "/etc/httpd/httpd.conf"]
```

도구는 기존 PHP 배포와 같은 서비스별 ServiceGuard `transaction.lock`을 먼저 잡고, 별도 web-guard 잠금을 추가로 잡습니다. 비활성 서비스는 자동으로 시작하지 않습니다. 적용 순서는 다음과 같습니다.

1. 기존 서비스 활성 상태·정상 상태·기본 PHP CLI의 phese 미로딩을 확인합니다. CLI 확인에는 `-n`을 사용하지 않습니다.
2. 모듈을 `/usr/local/lib/asylumenforce/native/<sha256>.so`에 읽기 전용 사본으로 고정하고 실제 PHP와 `phese doctor`를 실행합니다. 버전 게이트·모듈 ABI·seccomp·no_new_privs 확인이 실패하면 웹 설정을 쓰지 않습니다.
3. 새 INI와 drop-in을 각각 원자적으로 게시합니다. 공개 전에 inode·모드·내용 해시를 root 전용 상태 파일에 기록합니다. 기존 관리 밖 파일은 내용이 같아도 덮어쓰거나 인수하지 않습니다.
4. 지정한 구성 확인 명령이 있으면 새 서비스 전용 검색 경로로 다시 실행합니다. 그 뒤 `daemon-reload`·systemd 검증·해당 서비스 재시작·정상 상태·기본 CLI 미로딩을 확인합니다.

생성되는 서비스별 파일은 다음 두 개입니다.

```text
/usr/local/etc/asylumenforce/<service>.d/99-phese.ini
/etc/systemd/system/<service>.d/91-asylumenforce-phese.conf
```

Drop-in은 기존 검색 디렉터리 뒤에 새 검색 디렉터리를 추가하는 `Environment=PHP_INI_SCAN_DIR=...`와 독립 실행하는 `ExecStartPre=... phese doctor ...`만 추가합니다. 별도 검사 프로세스의 필터가 서비스 master로 전파되지는 않습니다. 기존 `90-asylumenforce.conf`와 다른 drop-in은 그대로 둡니다. 새 전용 검색 디렉터리에 관리 밖 INI가 있으면 함께 활성화하지 않고 중단합니다.

## 실제 보호 확인

정상 상태 확인 성공이나 `php-fpm -t`·`httpd -t` 성공은 웹 요청의 네이티브 보호 증명이 아닙니다. 실제로 각 PHP 핸들러·필요한 풀에 정상 요청을 보낸 뒤, 제한된 로컬 점검 경로에서 `phese_status()`의 `scope`, `enforcing`, `seccomp_active`, `no_new_privileges`, `version_gate`와 실제 UID를 확인해야 합니다. 해당 워커의 `/proc/<pid>/status`도 확인합니다. 점검 경로는 공개하지 않고 검증 후 제거합니다.

공식 수정 PHP 코어가 RINIT 이전의 요청·multipart 처리를 보호합니다. 워커 필터는 그 뒤의 추가 격리이며, master나 신뢰한 preload 초기화 전체를 격리했다는 뜻이 아닙니다. 모듈을 불러오지 못한 PHP가 경고 후 계속 실행할 수 있으므로 실제 웹 핸들러의 로딩 확인이 필요합니다. 이 도구의 성공 결과도 별도로 `requires-real-request-attestation`을 표시합니다.

PHP 소스에서 프로세스 실행이나 외부 helper가 필요한 경우 소스를 자동 수정하지 않고 수정 요청으로 처리합니다. 모든 앱의 호환성이나 모든 CVE 방어를 보장하지 않습니다.

## 원복과 변경

```sh
python3 /srv/asylumenforce/tools/web_guard.py rollback your-php-fpm.service
python3 /srv/asylumenforce/tools/web_guard.py rollback your-php-fpm.service --apply
```

원복은 `/var/lib/asylumenforce/web-guard/<service>/state.json`의 소유 기록과 현재 inode·모드·내용 해시가 일치하는 이번 설치 파일만 제거합니다. 먼저 두 파일을 모두 검사하므로 운영자가 바꾼 파일을 발견하면 자동 삭제하거나 재시작하지 않습니다. 관리하는 서비스가 중지된 상태에서도 원복을 진행하고 원래 구성으로 재시작할 수 있습니다. 정상 원복은 manager 재로드·구성 검증·재시작·기존 정상 상태·기본 CLI 미로딩을 다시 확인합니다. 실패하면 `failed` 상태와 복구 단계 이름을 남기며 보호를 복원했다고 주장하지 않습니다.

서비스가 이미 비활성화되어 있으면 관리자가 먼저 서비스 상태를 조사해야 합니다. 상태 파일은 0600이며 응답 내용은 저장하지 않습니다. 삭제된 파일의 디렉터리와 서비스 간 공유할 수 있는 모듈 캐시는 보관합니다. 공식 PHP 패치는 원복하지 않습니다.

같은 입력을 다시 적용하면 소유권을 확인한 뒤 재시작 없이 `unchanged`를 반환합니다. 설치된 입력·프로필·모듈·페이지가 달라졌다면 먼저 원복하고 새 계획을 검토합니다. 중단이나 디스크 오류 뒤의 불완전한 상태, 관리 밖 파일과의 게시 충돌은 자동 인수하지 않고 명시적인 복구 대상으로 남깁니다.
