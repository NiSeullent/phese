# CI의 실행 범위

[워크플로](../.github/workflows/ci.yml)는 읽기 권한 `contents: read`만 사용한다. 비공개 staging과 공개 저장소 모두 이벤트 커밋을 `git fetch`로 직접 가져오며 외부 Action, 저장소 쓰기 토큰, `pull_request_target`을 사용하지 않는다.

내장 `github.token`은 각 checkout 단계의 환경에만 전달한다. Basic 인증 헤더를 메모리에서 만든 뒤 `GIT_CONFIG_COUNT` 환경으로 해당 저장소 URL의 단일 `git fetch` 명령에만 적용한다. credential helper를 해당 명령에서 끄고, 원격 URL·Git 설정 파일·credential 파일에 인증 값을 저장하거나 로그로 출력하지 않는다. fetch 뒤에는 헤더 변수도 제거한다. 이후 시험·root 빌드 단계에는 토큰이나 인증 환경을 전달하지 않는다. [Git 명령별 환경 설정](https://git-scm.com/docs/git-config#Documentation/git-config.txt-GITCONFIGCOUNT), [GitHub 내장 토큰과 최소 권한](https://docs.github.com/en/actions/tutorials/authenticate-with-github_token)

## 두 검사 작업

| 작업 | 환경과 검증 |
| --- | --- |
| `python` | 기본 Ubuntu runner에서 Python 컴파일·표준 라이브러리 단위 시험, 실제 C syscall filter 시험. PHP 빌드·bubblewrap이 없는 환경에서는 해당 선택 시험이 건너뛰어질 수 있다. |
| `native-supported` | Ubuntu 24.04 x86_64 전용 VM에서 PHP 8.5.12 ZTS, CLI·FPM·Apache DSO, phese 확장 및 bubblewrap 0.10.0을 준비해 전체 시험 실행. 필수 네이티브 시험 클래스가 없거나 어떤 시험이라도 건너뛰면 실패한다. |

네이티브 작업은 `PHESE_TEST_PHP`, `PHESE_TEST_FPM`, `PHESE_TEST_EXTENSION`, `PHESE_TEST_APACHE`, `PHESE_TEST_APACHE_ROOT`, `PHESE_TEST_LIBPHP`를 명시한다. FPM 시작 시 적용하는 보호와 worker별 적용, 비root worker, Apache event MPM·thread 상속과 재시작, 실제 CLI namespace·파일·쓰기 경로·네트워크·프로세스 제한을 시험한다. 시험 내용의 정확한 범위는 `tests/test_native*`와 `tests/test_sandbox_integration.py`에 있다.

## 소스 고정과 빌드

- PHP 공식 `php-8.5.12.tar.xz`의 SHA-256은 `08bc2eba2a588654ade1357174aa646b761556c862dda0678345ee29ed481209`이다. 다운로드 후 이 값과 다르면 중단한다. [PHP 공식 릴리스 JSON](https://www.php.net/releases/index.php?json&version=8.5.12)
- bubblewrap 0.10.0은 이동 가능한 tag 대신 커밋 `dc63ec667e6546f34e0b6c088cdf8ae7c7dea0f3`을 fetch하고 checkout 결과를 비교한다. 공식 v0.10.0의 annotated tag `8f417ab7f947f1167671e3becca48a9a7a93bc86`이 이 커밋을 가리키는 것을 확인했다. [공식 tag 레코드](https://api.github.com/repos/containers/bubblewrap/git/tags/8f417ab7f947f1167671e3becca48a9a7a93bc86)
- bubblewrap의 Meson 옵션은 해당 버전의 `meson_options.txt`를 기준으로 한다. `man`, SELinux, completion, upstream 자체 시험을 끄고 user namespace를 요구한다. phese의 실제 syscall·sandbox 시험은 별도로 실행한다. [고정 커밋의 빌드 옵션](https://github.com/containers/bubblewrap/blob/dc63ec667e6546f34e0b6c088cdf8ae7c7dea0f3/meson_options.txt)
- PHP는 `--disable-all --enable-zts --enable-fpm --with-apxs2=/usr/bin/apxs --enable-session --enable-pcntl --enable-posix`를 중심으로 빌드한다. 이 프로필은 운영 서버의 모든 PHP 확장 구성을 재현하지 않는다.

스크립트는 `/opt/phese-native-ci.XXXXXXXX` 아래에만 빌드·시험 복사본을 만든다. runner의 체크아웃은 일반 사용자 소유이므로 root 소유 경로가 필요한 관리 도구 시험을 위해 커밋의 파일을 별도로 추출한다. 그 checkout의 `git archive` 한 명령에만 정확한 `safe.directory`를 전달하고 전역 Git 설정은 바꾸지 않는다. PHP의 `install-cli`, `install-fpm`, `install-build`, `install-headers`, `install-programs`만 전용 prefix에 실행한다. Apache DSO는 빌드 결과를 전용 디렉터리에 복사하며 `install-sapi`를 실행하지 않는다. 따라서 PHP 빌드가 시스템 Apache 설정에 모듈을 설치하거나 활성화하지 않는다.

성공·실패 후 전용 임시 디렉터리를 정리한다. 빌드 실패 시 각 빌드 로그의 끝부분을 CI 로그에 남긴다. 설치된 애플리케이션이나 운영 서비스 설정은 이 스크립트의 대상이 아니다.

## 전용 VM에서 필요한 권한

FPM의 root master와 비root worker, 네이티브 블록 페이지의 root 소유 검증을 시험하므로 네이티브 작업은 root로 실행한다. Python 시험이 안전한 빌드 경로를 사용하고 비root CLI worker가 그 경로에 접근할 수 있도록 빌드 디렉터리 권한도 지정한다.

Ubuntu 24.04의 AppArmor user namespace 제한이 있으면 워크플로는 **해당 일회용 CI VM에서만** `kernel.apparmor_restrict_unprivileged_userns=0`으로 바꾼다. 원래 값을 기록하고 마지막 `always()` 단계에서 복원한다. VM도 작업 후 폐기된다. 운영 서버의 같은 제한을 변경하는 설치 지침으로 사용하면 안 된다.

`tools/ci-supported-profile.sh`는 `GITHUB_ACTIONS=true`, `PHESE_CI_EPHEMERAL_RUNNER=1`, root 권한이 모두 없으면 시작을 거부한다. 이 표시는 운영 실행을 실수로 시작하지 않게 하는 조건이며 신뢰 경계를 증명하는 인증 장치는 아니다. 해당 스크립트와 워크플로는 GitHub가 제공하는 전용 Ubuntu VM에서만 사용한다. Pull request 코드는 root 시험을 실행하므로 이 작업에 배포 자격 증명이나 서비스 비밀을 전달하지 않는다.

## 확인한 것과 아직 실행하지 않은 것

구현 시 PHP tarball 해시는 서버의 실제 파일과 공식 메타데이터에서 대조했다. 최소 PHP configure 옵션과 선택 설치 target은 별도 임시 소스 트리에서 확인했다. bubblewrap 옵션과 tag-to-commit 관계는 공식 소스·API에서 확인했다. 워크플로 YAML 파싱과 셸 구문 검사도 로컬 검증 대상이다.

**이 문서를 작성한 시점에는 GitHub의 Ubuntu 네이티브 작업을 실제 실행하지 않았다.** 로컬 AlmaLinux 10.2에서 실행한 지원 프로필 검증과 GitHub runner의 성공을 같은 것으로 보고하지 않는다. 먼저 비공개 staging의 배포 후보 커밋에서 두 작업의 성공과 건너뛴 필수 시험이 없음을 확인한 뒤 공개 전환과 정식 배포를 판단한다. 이후 변경한 커밋도 해당 커밋의 CI 결과를 다시 확인해야 한다. PHP 8.2·8.3·8.4, AArch64, NTS, 다른 libc·확장 조합의 네이티브 CI는 이 워크플로가 제공하지 않는다.
