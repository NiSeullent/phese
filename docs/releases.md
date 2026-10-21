# GitHub Releases

[Release workflow](../.github/workflows/release.yml)는 기존 `vX.Y.Z` 태그 push를 받으면 해당 커밋의 검사를 기다린 뒤 GitHub Release를 만든다. 태그는 `pyproject.toml`의 `project.version` 앞에 `v`를 붙인 값과 같아야 한다. `workflow_dispatch`로 기존 태그를 지정해 다시 시작할 수도 있다. 태그에서 실행하면 입력을 생략할 수 있고, 브랜치에서 실행하면 `tag` 입력이 필요하다. 이 워크플로는 태그를 생성하지 않는다.

## 게시 조건

읽기 전용 `verify` 작업은 원격 태그를 정확한 ref로 가져오고 커밋·버전을 확인한다. 같은 저장소와 커밋의 `.github/workflows/ci.yml`에서 실행된 `Checks`의 push run만 선택한다. Pull request, 다른 저장소·커밋·워크플로 및 Dependabot run을 사용하지 않는다. 여러 후보가 있으면 가장 최근 run을 기준으로 삼고, 최대 55분 동안 대기한다. 실패하거나 취소된 최신 run을 이전 성공으로 대신하지 않는다.

전체 run뿐 아니라 `python`과 `PHP 8.5.12 ZTS, FPM, Apache and bubblewrap` 작업 및 각 실제 시험 단계가 성공해야 한다. 동일 run의 정확한 재실행 attempt를 조회하고 조회 중 attempt가 바뀌면 다시 기다린다. 네이티브 작업의 `tools/ci-supported-profile.sh`는 필수 시험 클래스가 없거나 **단 한 건이라도 skip이면 실패**하므로 해당 단계의 성공을 필수 조건으로 사용한다. 기본 Python 작업만 성공한 경우는 배포 조건을 만족하지 않는다. [CI 범위](ci.md)

검증 작업은 읽기 권한만 가지며 태그·커밋·CI run ID만 게시 작업에 전달한다. 게시 작업은 쓰기 토큰을 단일 `Publish the verified tag once` 단계의 환경에만 받는다. 이 단계가 태그와 커밋을 다시 확인하고 동일 소스를 가져오며 패키지 빌드의 자식 프로세스 환경에서는 토큰을 제거한다. Git 인증은 해당 fetch 명령의 환경에만 적용하고 저장소 URL이나 Git 설정 파일에 기록하지 않는다. 외부 Action, 별도 PAT, 운영 서비스 배포·root 실행·모델 호출은 없다.

## 첨부 파일과 중복 방지

전용 `.release-venv`에 `build==1.6.1`, `setuptools==84.2.1`, `wheel==0.48.0`을 설치하고 `python -m build --no-isolation`으로 패키지를 만든다. 빌드 격리를 꺼 지정한 backend 버전을 사용한다. GitHub-hosted Ubuntu 환경과 추가 전이 의존성까지 모두 고정하는 재현 빌드를 보장하지는 않는다.

게시 파일은 다음 세 개이다.

- `phese-X.Y.Z-py3-none-any.whl`
- `phese-X.Y.Z.tar.gz`
- `SHA256SUMS`

소스 배포본에는 네이티브 빌드 SDK가 들어간다. wheel에는 미리 빌드된 PHP 모듈이 없으며, 서버 ABI에 맞는 모듈 빌드·설치는 [설치 안내](setup.md)를 따른다. 릴리스 설명에는 검증한 커밋과 CI run 링크를 기록한다.

게시 직전 원격 태그가 검증한 커밋을 계속 가리키는지 확인한다. 같은 태그의 Release가 이미 있으면 중단하며 기존 Release나 첨부 파일을 수정·교체·삭제하지 않는다. API 오류를 Release 부재로 간주하지 않는다. `gh release create --verify-tag --notes-file` 한 번으로 게시하며 `--clobber`는 사용하지 않는다. 업로드 도중 실패해 일부만 게시된 경우에도 자동으로 덮어쓰지 않는다. 운영자가 상태를 확인하고 별도의 복구를 판단해야 한다. [GitHub CLI 게시 옵션](https://cli.github.com/manual/gh_release_create)

## 현재 검증 상태

이 기능은 로컬 YAML·셸 구문 검사와 가짜 API 응답을 이용한 성공·대기·실패·오선택 방지 시험으로 검증한다. 원격 배포 여부와 성공 결과는 해당 태그의 Release workflow 실행 기록과 릴리스의 CI 링크에서 확인한다. 실제 배포 전 비공개 staging에서 동일 커밋의 두 Checks 작업과 게시 작업을 확인한다. 로컬 시험을 원격 성공으로 대신하지 않는다.
