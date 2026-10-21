# 1.0.0 릴리스 검증

기준일: 2026-10-21 UTC. 이 문서는 실행한 검증과 보호 경계를 구분한다. 정식 지원 프로필은 **Linux x86_64, glibc, PHP 8.5.12 ZTS**이다. 다른 PHP 브랜치의 버전 허용 규칙과 AArch64 필터 코드가 있어도 해당 ABI·플랫폼의 배포 검증을 완료했다는 의미는 아니다.

## 지원 프로필과 필수 구성

| 구성 | 검증한 범위 |
| --- | --- |
| 호스트 | AlmaLinux 10.2 x86_64, Linux 6.12, glibc |
| PHP | 공식 8.5.12 ZTS, 일치하는 개발 헤더·CLI·FPM·Apache DSO |
| CLI | Python 3.12, bubblewrap 0.10 이상, 기본 네트워크 차단·읽기 전용 앱·명시 쓰기 경로 |
| FPM | `phese.scope=worker`, 비root 풀, worker 교체와 USR2 재실행 |
| Apache | event MPM·ZTS mod_php, `phese.scope=worker`, 동시 요청과 USR1 graceful reload |
| 서버 정책 | 별도 systemd drop-in, 정상 HTTP 확인·원복·실패 복구 |
| 감사 수집 | authpriv JSON, rsyslog 수집·logrotate 구성 |

프로그램과 필터는 방어 계층이다. 지정한 두 CVE의 메모리 손상 수정은 공식 PHP 엔진 보안 패치가 담당한다. 소스·바이너리의 진위는 별도로 확보해야 하며 숫자 버전 gate만으로 진위를 증명하지 않는다.

## 실행한 검증

전체 지원 환경 변수를 지정한 `unittest discover`에서 **222개 시험, 실패 0개, 건너뜀 0개**를 확인했다. 별도 네이티브 회귀 시험 33개도 통과했다. 이 집계에는 자동 설정 도구의 공개 회귀 시험 36개와 배포 workflow의 가짜 API 회귀 시험 18개가 포함된다.

- 실제 C syscall 시험: execve/execveat 차단, 기존·새 스레드 TSYNC, fork 상속, ptrace·namespace·대체 syscall ABI 제한, 정상 파일 입출력.
- 실제 CLI 격리: 호스트 UID/GID 65534로 권한을 내린 후 bubblewrap 진입, 비공개 root 파일 접근 거부, 앱 읽기 전용·명시 쓰기·네트워크 격리·환경 제거, 보호 확장 누락 시 거부.
- 실제 FPM: 비root worker, 요청 처리와 재생성, USR2 재실행, root 풀 및 seccomp 설치 실패 시 앱 진입 거부.
- 실제 Apache: 첫 PHP 요청 24개 동시 실행, 기존 스레드 전체에 프로세스당 필터 한 개, USR1 10회 후 master 필터 수 불변·새 worker 한 개 유지, 동시·후속 요청의 필터 설치 실패 시 앱 미실행.
- 실제 HTTP 차단: 403 본문·CSP, 기존 HTTP 200 상태·헤더 callback의 상태 복구 및 조기 종료 시도 방지, 출력 억제.
- 설치·설정 fixture: 관리하지 않는 파일·symlink·변조 거부, 완전한 새 릴리스 게시 후 CLI 전환, 게시·전환 실패 시 기존 CLI 유지, 관리 파일 원복과 비활성 서비스 복구.
- 페이지: 사용자 JSON 검증, HTML·스크립트 삽입 방지, 정확한 CSP 해시, 변경 감지·동시 실행 잠금·재빌드, 데스크톱과 모바일 렌더링.
- 배포 패키지: wheel과 소스 archive 생성, 깨끗한 가상 환경에서 버전·페이지 생성·실제 CLI 격리 실행 확인. 비공개 상태·보고서·컴파일된 `.so`는 소스 archive에서 제외한다.

운영 웹서비스에도 별도 scan 디렉터리와 `ExecStartPre` 검사를 적용하고 실제 정상 HTTP 요청 중 비root worker의 모듈 매핑·NoNewPrivs·seccomp 필터 증가를 확인했다. FPM USR2와 Apache graceful reload 후 정상 응답을 확인했다. 기존 관리자 CLI는 전역 확장을 로드하지 않으며 정상 프로세스 실행이 유지된다. 운영 설정·호스트명·PID·인벤토리·개별 수정 요청은 공개 저장소에 포함하지 않는다.

Codex 연동은 실제 기존 계정의 계획 요청 한 번과 엄격한 JSON 응답을 확인했다. Claude Code는 로컬 옵션·가용성 검사와 명령 대역 시험 범위이며 실제 모델 추론을 완료했다고 주장하지 않는다. AI 권고는 설정 권한을 확대하지 않으며, 같은 서비스 정책 재적용 시 재시작이 생략되는 것도 실제 확인했다.

## GitHub와 재현

[CI 안내](ci.md)의 두 작업은 Python 검사와 전용 Ubuntu 24.04 네이티브 프로필을 제공한다. 로컬 검증 결과를 원격 runner의 성공으로 대신하지 않는다. 릴리스에는 해당 커밋의 실제 GitHub 작업 결과를 함께 확인한다.

```sh
PHESE_TEST_PHP=/path/to/php \
PHESE_TEST_FPM=/path/to/php-fpm \
PHESE_TEST_EXTENSION=/path/to/phese.so \
PHESE_TEST_APACHE=/path/to/httpd \
PHESE_TEST_APACHE_ROOT=/path/to/apache \
PHESE_TEST_LIBPHP=/path/to/libphp.so \
python3 -m unittest discover -s tests -v
```

이 값 없이 실행한 시험은 실제 PHP·웹서버·namespace 시험을 건너뛸 수 있다. 성공 상태뿐 아니라 `skipped` 수와 대상 플랫폼을 확인해야 한다. 배포판 PHP backport, NTS, musl, AArch64, 다른 MPM·서드파티 확장 조합은 이 릴리스의 완료된 인증 범위가 아니다.

## 남는 제약

원격 RCE exploit을 운영 서버에 실행하지 않았다. SQL injection·XSS·권한 검사 오류·허용된 DB/파일/네트워크의 악용과 모든 후속 CVE를 차단한다는 보장은 없다. 외부 프로그램을 실행하는 PHP 앱은 수정 요청 또는 별도의 검토된 작업 서비스가 필요하다. `worker` 프로필의 master와 RINIT 전 입력 처리는 네이티브 worker 필터 밖이며 필수 PHP 패치에 의존한다.

기본 서비스 정책은 `/srv` 전체 쓰기를 격리하지 않는다. 앱별 Unix 권한·쓰기 경로·소켓·자원 상한은 추가 설계가 필요하다. CLI의 루트 실행은 실제 비root UID가 접근할 수 있는 런타임·모듈·guard와 앱 경로가 필요하다. 특히 root 전용 가상 환경이나 `umask 077`로 설치한 패키지에서는 접근을 거부할 수 있으므로 시스템 설치 도구 또는 권한을 검토한 배포 경로를 사용한다.

로그 전송은 best effort이며 모든 raw syscall과 종료를 기록하지 않는다. YouTube의 실제 소리 재생은 브라우저 자동 재생 정책·로그인·봇 확인 때문에 보장하지 않는다. 외부 이미지·영상은 원격 서비스에서 제공되며 이 프로젝트가 해당 저작물을 재배포하지 않는다.
