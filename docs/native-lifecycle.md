# 네이티브 필터와 웹서버 수명주기

웹서비스는 `phese.scope=worker`를 사용한다. PHP-FPM과 Apache `apache2handler`에서만 허용한다. CLI·phpdbg 등 다른 SAPI의 worker 설정은 시작 단계에서 거부한다. Apache의 startup 설정도 시작 단계에서 거부하고 worker 설정을 안내한다.

| 실행 경로 | PHP 초기화 시점 | 첫 HTTP 요청 시점 | 정상 관리 동작 |
| --- | --- | --- | --- |
| CLI startup | 버전 검사와 네이티브 필터 설치 | 해당 없음 | 필터가 프로세스 실행을 제한 |
| PHP-FPM worker | 수정 버전 검사·페이지 캐시·함수 훅 준비, master에 phese 필터 추가 없음 | 권한을 내린 worker에 필수 필터 설치 | master의 USR2 재실행 유지 |
| Apache worker | 수정 버전 검사·페이지 캐시·함수 훅 준비, master에 phese 필터 추가 없음 | 권한을 내린 worker 프로세스에 필수 필터 설치 | master의 USR1 graceful reload 유지 |

worker 모드는 `server_context`와 HTTP 요청 메서드가 준비된 실제 요청에서만 동작한다. 요청을 처리할 worker UID가 root이면 PHP 앱을 실행하지 않는다. 버전·정보 출력 및 preload에는 HTTP 요청이 없으므로 worker 필터 설치를 시도하지 않는다. 요청 파싱 등 RINIT 이전 단계의 취약점 대응에는 PHP 공식 엔진 패치가 필수이다. worker 필터는 그 패치를 대체하지 않는다.

Apache event MPM의 첫 요청들이 여러 스레드에서 동시에 들어오면 첫 설치만 mutex 안에서 수행한다. 필터 설치는 `SECCOMP_FILTER_FLAG_TSYNC`로 기존 worker 스레드 전체에 적용하고 이후 스레드도 커널 필터를 상속한다. 설치 성공 표식은 acquire/release 원자 연산으로 게시하며 다음 요청에서는 필터를 추가 설치하지 않는다. 임계 구역에서는 PHP 진단·콜백을 실행하지 않아 Zend bailout으로 잠금이 남지 않도록 한다.

TSYNC·seccomp·동기화가 실패하면 해당 프로세스의 실패 상태를 유지한다. 동시에 대기하던 요청과 이후 요청도 앱 진입을 거부한다. 다른 seccomp 정책이 이미 있다는 사실만으로 phese가 설치됐다고 간주하지 않는다. 정상 supervisor master는 RINIT를 거치지 않으므로 FPM·Apache가 만드는 새 worker는 잠기지 않은 초기 상태를 상속한다. 이미 필터를 가진 프로세스의 자식은 기존 필터를 상속하며 성공 표식 때문에 같은 필터를 재설치하지 않는다.

설치 실패는 SAPI에 따라 오류 응답이나 연결 종료로 나타날 수 있다. 앱 코드가 시작되지 않는 것이 이 경로의 보장이다. 요청 안에서 `phese_status()`의 `enforcing`은 필터 설치 성공과 실패 상태가 없음을 함께 뜻한다. 부모의 준비 단계에서는 아직 false이며, 기존 OS 정책의 seccomp 유무와 별도로 판단한다.

Apache startup 모드는 graceful reload 때 같은 master에서 PHP 확장이 재초기화되며 필터가 누적되는 문제가 실제로 확인되어 지원하지 않는다. worker 모드에서는 master 필터 수가 유지되고 새 worker에 한 개의 phese 필터만 추가된다. 기존 master에 이미 startup 필터를 설치한 상태라면 설정 변경과 graceful reload만으로 그 필터를 없앨 수 없다. 수정된 설정으로 supervisor가 전체 stop/start를 수행해야 한다. PHP 보안 패치를 취약 버전으로 되돌리지 않는다.

FPM startup 모드는 명시적으로 사용할 수 있지만 master의 `execve`가 차단되어 USR2 reload와 호환되지 않는다. 운영 FPM에는 worker를 권장한다. 파일·네트워크 격리, 앱의 데이터 권한과 자원 제한은 별도의 OS 정책으로 적용한다.

## 회귀 검증

실제 PHP 8.5.12 ZTS / Linux x86_64에서 다음 항목을 확인한다.

- Apache의 첫 PHP 요청 24개를 동시에 보내 worker 및 기존 스레드의 필터가 정확히 한 개 추가되는지 확인
- Apache USR1을 10회 반복해 master의 필터 수가 변하지 않고 매 새 worker의 필터 수가 기준값+1인지 확인
- 필터 설치를 실패시키는 임시 launcher에서 Apache 동시 요청과 후속 요청이 PHP 본문을 실행하지 않는지 확인
- FPM worker 교체와 USR2 reload 후 master의 필터 수 유지 및 각 worker의 필터 한 개 설치 확인
- 403 입원 화면·CSP·기존 상태 헤더·사용자 header callback 우회 방지와 CLI의 worker 설정 거부 확인

테스트는 임시 문서 루트·포트·Unix 소켓을 사용하며 운영 서비스에 신호를 보내지 않는다. 지원 범위 밖의 PHP ABI·운영체제·아키텍처를 검증했다고 주장하지 않는다.
