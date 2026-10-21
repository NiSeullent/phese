# CLI 설치와 자동 설정

서비스 계획 코드는 Linux x86_64/aarch64와 Python 3.10 이상을 대상으로 합니다. 이 릴리스의 실제 완료된 네이티브 지원 검증은 Linux x86_64·glibc·PHP 8.5.12 ZTS·Python 3.12이며 [검증 범위](validation.md)를 따릅니다. 수정된 안정 PHP와 같은 설치의 개발 도구가 필요합니다. PHP 엔진 교체나 시스템 패키지 다운로드, 전역 PHP INI 수정은 자동으로 하지 않습니다.

신뢰한 소스 배포본에서 먼저 기존 bootstrap으로 CLI와 PHP ABI/ZTS에 맞는 확장을 검증·설치합니다. 경로는 자신의 PHP 설치에 맞춥니다.

```sh
./tools/bootstrap.sh --php /absolute/patched/php --php-config /absolute/matching/php-config --source "$PWD" --apply
python3 tools/install_autosetup.py --install --php /absolute/patched/php
```

두 번째 명령은 기존 정상 CLI 설치 도구를 재사용하고 별도 `phese-setup` 진입점을 설치한 뒤 진단을 출력합니다. 코드·서비스 backend·기존 정책을 content-addressed release에 함께 보관합니다. 이전 릴리스는 유지합니다. `phese setup`은 앱 설정과 Codex/Claude 프로젝트 지침용이며, `phese-setup`은 서비스 진단·선택 정책·선택적 AI 계획용입니다. 이름과 의미를 덮어쓰지 않습니다. pip 설치만으로 별도 launcher와 서비스 backend가 설치된다고 가정하지 마세요.

bootstrap 결과의 `module` 경로로 보호 확장을 확인합니다. CLI probe 성공은 실제 FPM worker나 reload 수명주기 검증을 대신하지 않습니다.

```sh
phese doctor --php /absolute/patched/php --extension /absolute/bootstrap-result-module.so
phese setup --app /absolute/app --php /absolute/patched/php --extension /absolute/bootstrap-result-module.so
```

`phese setup`은 기본 계획만 출력합니다. `--apply`를 붙이면 기존 앱 설정·도우미 지침을 검토한 범위에서 기록하며 PHP 소스나 서비스를 고치지 않습니다. 저장한 설정은 `phese start SCRIPT`로 사용합니다.

서비스와 AI CLI 가용성은 읽기 전용으로 확인할 수 있습니다.

```sh
phese-setup --php /absolute/patched/php --discover-services --assistant-inventory
```

PATH에서 선택되는 클라이언트를 그대로 쓰는 것이 기본입니다. 다른 설치를 쓰려면 절대 경로로 지정할 수 있습니다. 기존 실행 파일이나 패키지의 소유권을 바꾸거나 경로 보호 규칙을 완화하지 않습니다.

```sh
phese-setup --php /absolute/patched/php --assistant-inventory \
  --codex-cli /absolute/root-controlled/codex --claude-cli /absolute/root-controlled/claude
```

가용성 진단은 클라이언트별로 계속됩니다. 누락·신뢰하지 않는 소유권·미지원 옵션·메타데이터 실패는 `available:false`와 고정 reason 코드로 표시하며 경로나 원래 CLI 오류를 노출하지 않습니다. 상대 경로는 선택을 거절하고 PATH로 몰래 대체하지 않습니다. 이 결과는 다른 클라이언트 진단이나 기본 진단을 실패로 바꾸지 않습니다.

심볼릭 링크 루프 같은 경로 메타데이터 오류도 고정된 실패 코드로 처리합니다. 링크를 따라가도록 정책을 완화하거나 잘못된 경로 대신 다른 클라이언트를 몰래 실행하지 않습니다.

서비스 탐색은 기존 실행 중인 PHP/web 서비스 이름만 고릅니다. 탐색 결과를 묵시적으로 적용하지 않습니다. 실제 정책 적용에는 root, 명시한 기존 active 서비스와 credential 없는 신뢰한 health argv가 필요합니다. 아래 서비스 이름과 URL을 자신의 운영 계약에 맞춰 확인하세요.

```sh
phese-setup --php /absolute/patched/php --service php-fpm.service \
  --health-check 'php-fpm.service=["/usr/bin/curl","--fail","--silent","--max-time","10","http://127.0.0.1:8080/health"]' --apply
```

기존 ServiceGuard의 잠금·검증·재시작·health·실패 복구를 사용합니다. 다른 내용의 drop-in은 덮어쓰지 않고, 같은 정책이면 불필요한 재시작을 생략합니다. 여러 서비스는 순차적 개별 트랜잭션입니다. 뒤 서비스가 실패해도 앞 서비스의 성공 기록은 남습니다. private receipt를 확인한 뒤 재개하세요. 서비스 원복은 기존 `tools/service_guard.py rollback SERVICE --apply` 계약을 따릅니다. CLI 릴리스 원복과 서비스 원복은 별개입니다.

이 기능이 수행하는 최적화는 ABI에 맞는 기존 확장 선택·정책 재사용·동일 설정의 재시작 생략 범위입니다. worker/cache 설정이나 CPU·메모리 한도를 성능 측정 없이 바꾸지 않으며 처리량 향상·완전 자동 최적화를 보장하지 않습니다. 공유 전역 INI에 native 확장을 임의로 켜지 마세요. root CLI 및 FPM master 재실행과의 호환성은 별도로 검증해야 합니다.

기존 Codex 또는 Claude Code 계정으로 계획을 요청하려면 명시적으로 선택합니다.

```sh
phese-setup --php /absolute/patched/php --service php-fpm.service --assistant codex
phese-setup --php /absolute/patched/php --service php-fpm.service --assistant claude
```

실제 요청에도 `--codex-cli` 또는 `--claude-cli`를 함께 지정할 수 있습니다. 선택한 클라이언트가 검증되지 않으면 해당 요청은 실패하며 뒤 서비스 적용도 실행하지 않습니다. 가용성 정보가 부족한 경우 명령을 강행하거나 신뢰 검사를 우회하지 마세요.

이 요청은 기존 계정 quota를 소비할 수 있습니다. 모델·effort를 임의로 바꾸거나 유료 overage/fallback으로 재시도하지 않습니다. 인증·quota·클라이언트 오류가 나면 적용을 진행하지 않습니다. `--assistant-inventory`는 로컬 version/help/feature 검사이며 모델 호출이나 계정 잔여량 확인이 아닙니다. `--assistant-response-stdin`은 외부 호출 없이 같은 JSON을 검증합니다.

AI에는 새로 구성한 공개 boolean/count/고정 enum 요약만 stdin으로 전달합니다. 경로·서비스 이름·환경값·비공개 설정·계정·세션·소스·raw log는 prompt에 넣지 않습니다. 결과는 기존 정책과 허용된 권고 코드만 받으며 모델이 만든 shell/argv/파일/health 명령을 실행하지 않습니다. root가 선택한 서비스와 health argv는 AI 출력에서 받지 않습니다.

Codex는 read-only sandbox와 지원되는 통합 비활성화 옵션을 사용합니다. Claude는 tools-empty/safe/restricted/빈 MCP 옵션을 사용합니다. 이 설정을 클라이언트 자체 인증 파일까지 차단하는 OS 격리나 모든 private 읽기가 불가능한 보증으로 해석하지 마세요. 신뢰한 설치 CLI와 관리 정책을 사용해야 합니다. 클라이언트 시간·출력·JSON 크기/깊이를 제한하고, 정상/오류/timeout 모두 같은 프로세스 그룹을 정리합니다. 다른 세션으로 이탈한 악성 프로그램의 완전 격리는 보장하지 않습니다.

일반 회귀 검증은 `python3 -m unittest discover -s tests -p 'test_autosetup.py' -v`입니다. 테스트는 일반 프로젝트 경로와 공개 소스만 쓰며 설치된 Codex/Claude, 실제 모델·PHP·서비스·설치 작업 없이 fake CLI/가짜 systemd/임시 파일 시스템으로 실행됩니다. 실제 배포·계정 연결·provider 응답과 운영 성능은 별도 검증 대상입니다.
