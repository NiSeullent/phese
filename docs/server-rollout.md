# 서버 서비스 보호 적용

`tools/service_guard.py`는 지정한 기존 PHP-FPM 또는 Apache 서비스에 `policies/php-service.conf`를 별도 `90-asylumenforce.conf`로 추가합니다. PHP 엔진, 긴급 CVE 완화 ini, 애플리케이션 소스, 다른 drop-in 및 서비스는 수정하지 않습니다. 설치한 PHP 확장과 함께 사용하는 추가 보호 계층입니다. 네이티브 확장의 서비스별 로드는 별도 [웹 설치·원복 도구](web-install.md)를 사용합니다. 두 도구는 같은 서비스 트랜잭션 lock으로 재시작을 직렬화합니다.

먼저 전용 테스트 인스턴스에서 실제 PHP 버전·ABI와 사이트 기능을 확인합니다. FPM만 보호하면 Apache mod_php 또는 별도 CLI 경로는 포함되지 않습니다. 관리자가 각각의 진입 경로를 확인해야 합니다.

```bash
python3 tools/service_guard.py plan your-php.service
python3 tools/service_guard.py apply your-php.service --apply \
  --health-check '["/usr/bin/curl","--fail","--silent","--max-time","10","http://127.0.0.1:8080/health"]'
python3 tools/service_guard.py status your-php.service
python3 tools/service_guard.py rollback your-php.service --apply
```

위 건강 확인 URL은 예시입니다. 실제 서비스의 신뢰할 수 있는 비변경성 확인 명령으로 바꾸십시오. FPM은 HTTP 서버가 아니므로 해당 풀을 경유하는 HTTP 경로나 root 소유 FastCGI 검사 프로그램을 지정해야 합니다. HTTP 200 여부만으로 모든 기능의 호환성을 입증할 수 없습니다. 건강 확인 프로그램은 실패 시 0이 아닌 종료 코드를 반환해야 합니다.

`apply`와 `rollback`은 `--apply`가 없으면 계획만 출력합니다. 실제 변경은 root에서만 가능합니다. 이미 실행 중인 서비스만 적용하며, 설치되지 않은 서비스나 중지된 서비스를 자동으로 시작하지 않습니다. `--system-root`는 별도 파일시스템에 대한 읽기 전용 `plan`/`status` 조사용이며, 이 옵션으로 실제 systemd를 변경할 수 없습니다.

건강 확인 명령은 JSON 문자열 배열이며 실행 파일은 절대 경로여야 합니다. root 소유이며 다른 사용자가 변경할 수 없는 실행 파일과 상위 경로를 검증합니다. 셸 명령은 받지 않으며 `shell=False`로 실행합니다. 출력과 오류 응답은 로그에 내보내지 않습니다. 비밀 값을 인자로 전달하지 마십시오. 건강 확인 인자는 root 전용 상태 파일에 보관해 롤백에도 사용합니다. 롤백 시 `--health-check`를 다시 지정할 수도 있습니다.

변경 전에 계획을 출력하고 `/var/lib/asylumenforce/service-guard/<service>/state.json`에 권한 `0600`으로 원래 파일 부재 상태와 설치 내용의 SHA-256을 기록합니다. 기존 다른 내용의 `90-asylumenforce.conf`, 심볼릭 링크, 비신뢰 소유권 또는 쓰기 권한이 있는 경로는 거부합니다. 이미 같은 파일이 있으면 덮어쓰거나 재시작하지 않습니다. 다른 도구가 만든 동일 파일은 소유권을 인수하지 않으며 롤백으로 삭제하지 않습니다.

적용 순서는 drop-in 생성, `daemon-reload`, `systemd-analyze verify`, 지정 서비스 재시작, active 상태 확인, 애플리케이션 건강 확인입니다. 재시작·구성 검증·건강 확인이 실패하면 도구가 만든 파일을 제거하고 원래 구성으로 재시작해 상태와 건강을 다시 검사합니다. 복구에 실패하면 성공을 반환하지 않으며, 실패한 복구 단계를 알립니다. 이후 `rollback ... --apply`로 다시 시도할 수 있습니다. 파일이 외부에서 변경되었으면 자동 삭제하지 않습니다.

설정 적용에는 **서비스 재시작이 필요합니다**. `daemon-reload`나 애플리케이션의 graceful reload만으로 이미 실행 중인 프로세스의 권한, mount namespace, seccomp 상태가 바뀌지 않습니다. 활성 프로세스에서 해제할 수 없는 PHP 확장 필터도 새 프로세스를 만들어야 원복됩니다. 이 도구의 상태 조회는 systemd 구성값과 서비스 활성 상태를 보여줍니다. 실제 프로세스의 `/proc/<pid>/status`, namespace, PHP 확장 상태도 별도로 확인해야 합니다.

기본 `ProtectSystem=full`은 `/usr`, `/boot`, `/efi`, `/etc`를 읽기 전용으로 만들며 **`/srv` 전체에 대한 쓰기를 격리하지 않습니다**. 사이트별 세션·업로드·캐시·DB 쓰기 경로를 조사한 뒤 더 강한 `ProtectSystem=strict` 및 정확한 쓰기 허용 경로를 별도 검증해야 합니다. 공유 FPM master의 단일 systemd unit만으로 풀마다 서로 다른 파일·네트워크 namespace를 부여할 수는 없습니다.

`PrivateDevices=yes`는 일반적인 가상 장치를 제공하며 하드웨어 장치 접근을 제한합니다. GPU·인쇄·스캐너·특수 장치 사용이 있는 사이트는 사전 호환성 검토가 필요합니다. syscall·namespace 제한도 외부 도구, 컨테이너 실행 또는 디버깅 동작에 영향을 줄 수 있습니다. 실제 기능이 필요한 경우 자동으로 약한 설정으로 바꾸지 말고 검토할 정책 예외 또는 코드 수정 요청을 남깁니다.

도구는 기존 설정의 정확한 백업 상태만 원복합니다. PHP 보안 패치를 취약 버전으로 되돌리거나 기존 긴급 완화를 제거하지 않습니다. 운영 적용 전에는 별도 테스트 인스턴스의 검증 결과, 영향받는 기능, 짧은 재시작 영향, 위 롤백 명령을 기록하십시오.

테스트는 실제 systemd와 서비스를 변경하지 않고 파일시스템 fixture 및 명령 대역을 사용합니다.

```bash
python3 -m unittest discover -s tests -p 'test_service_guard.py' -v
```
