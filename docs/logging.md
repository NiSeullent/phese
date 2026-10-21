# 입원 및 차단 이벤트 기록

Python CLI와 PHP native 확장은 AsylumEnforce 이벤트를 `phese` 프로그램 이름 및 syslog `AUTHPRIV` facility로 보냅니다. 정책이 확인된 격리 실행은 `sandbox_started`, 실행 종료는 `sandbox_exited`, 정책 차단은 `policy_denied`, PHP 버전 거부는 `version_refused`로 기록합니다. 이벤트 종류와 `reason` 정적 코드가 실제 발생 원인을 구분합니다. 모든 HTTP 요청이나 모든 syscall을 관찰하는 감사 시스템은 아닙니다.

고정 JSON 필드는 `product`, `component`, `event`, `event_id`, UTC RFC3339 `timestamp`, `pid`, `reason`, `terminology`, `message`입니다. Python 종료 이벤트에는 선택적으로 정수 `exit_code`를 넣을 수 있습니다. 이벤트 ID는 UUID 또는 native가 생성한 32자리 hex입니다. 용어는 `입원`, `폐쇄적 환경`, `안정실`, `공격 위험성`으로 기록하고 메시지 값은 정확히 다음과 같습니다.

```text
ㅋㅋㅋㅋㅋ어떻게병동이름이폐쇄얔ㅋㅋㅋㅋㅋㅋ
```

Python 호출은 `phese.events.emit(event, reason, *, pid=None, exit_code=None, event_id=None)`이며 제출에 성공하면 이벤트 ID, 인자 검증이나 syslog 호출에 실패하면 `None`을 반환합니다. stdout·stderr에는 쓰지 않습니다. 반환값은 syslog API가 반환했음을 뜻하며 디스크의 영구 저장이나 수신 확인을 보장하지 않습니다. **로그 실패 때문에 보호를 해제해서는 안 됩니다.** 호출 측은 필요한 오류 처리를 하면서 실행 차단을 유지해야 합니다.

`reason`은 `phese/events.py`의 이벤트별 정적 allowlist에 있는 코드만 허용합니다. CLI는 `isolation_verified`, `normal_exit`, `nonzero_exit`, `signal_terminated`, `sandbox_timeout`, `policy_check_failed`, `sandbox_setup_failed`, `untrusted_runtime`, `php_version_gate_failed`를 사용할 수 있습니다. Native의 주요 코드는 `process_execution_attempt`, `native_interface_attempt`, `mandatory_seccomp_unavailable`, `unpatched_or_unsupported_php`입니다. Native에는 차단 대상의 고정 allowlist 함수 이름을 담는 선택 `function` 필드가 있을 수 있습니다. 코드 추가 시 실제 원인을 표현하는 정적 값으로만 추가하고 검증해야 합니다.

요청 내용, URL, 사용자 식별자, 예외 문자열, CLI 인자, 파일 경로, 토큰·쿠키·인증정보를 이벤트에 넣지 않습니다. 임의의 추가 JSON 키도 받지 않습니다. 호출 측이 사용자 입력을 이벤트 ID나 숫자 필드에 끼워 넣어서는 안 됩니다. 로그 파일 자체와 운영 보고서는 비공개로 유지해야 합니다.

`policies/asylumenforce-rsyslog.conf`는 `programname == phese` 메시지를 `/var/log/asylumenforce/admissions.jsonl`로 보냅니다. 디렉터리는 root:root `0750`, 파일은 root:root `0640`으로 생성하도록 지정합니다. `adm` 그룹 권한을 부여하지 않습니다. 기본 `stop`은 뒤의 일반 로그 규칙에 중복 저장되는 것을 막습니다. 이 규칙은 일반 authpriv 규칙보다 먼저 실행돼야 합니다. 중복 보존을 의도한 경우에만 `stop`을 제거하십시오.

설치 전 rsyslog 구성 검증과 root 소유권·경로·기존 파일 모드를 확인합니다. 샘플 파일을 복사하는 것만으로 기존 디렉터리나 파일의 권한이 바뀌지는 않습니다. rsyslog 설정 검증은 `rsyslogd -N1`, logrotate의 비변경성 검증은 `logrotate -d /path/to/asylumenforce-logrotate`로 할 수 있습니다. 이 저장소의 도구는 이 설정을 자동으로 설치하거나 서비스를 재시작하지 않습니다.

`policies/asylumenforce-logrotate`는 현재 파일이 10 MiB 이상일 때 순환하고 압축본을 20개 보존합니다. 새 파일은 root:root `0640`으로 생성하며 rsyslog에 HUP을 보내 열려 있는 로그 파일을 다시 엽니다. 파일을 삭제하는 `rm`이나 서비스를 중지하는 동작은 포함하지 않습니다. 운영체제의 기존 logrotate 실행 주기에 따라 크기를 확인하므로 정확한 10 MiB 디스크 상한은 아니며, 폭증 시 다음 순환까지 더 커질 수 있습니다. 기존 운영 주기와 디스크 용량을 함께 확인하고, 로그를 무제한 누적하지 마십시오.

로컬 프로세스도 syslog 프로그램 이름을 지정할 수 있으므로 `phese` 라우팅만으로 이벤트 발신자를 암호학적으로 인증하지는 못합니다. 로그 뷰어는 JSON 스키마와 길이를 검증하고 모든 값을 escape해야 합니다. 이벤트 ID는 추적용이며 보안 판정이나 세션 인증 토큰으로 사용하지 않습니다.

```bash
python3 -m unittest discover -s tests -p 'test_events.py' -v
```
