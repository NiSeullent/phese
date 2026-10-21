# 차단 페이지를 JSON으로 바꾸기

문구·용어·색상·이미지·배경 영상·이동 링크는 JSON 하나로 설정한다. 빌더는 HTML과 **그 HTML의 스크립트에 맞는 CSP**를 함께 생성한다. PHP 코드 변경, 운영 파일 복사, 서비스 재시작은 자동으로 수행하지 않는다.

```bash
python3 -m phese.pages init /srv/phese-pages/theme.json
python3 -m phese.pages build \
  --config /srv/phese-pages/theme.json \
  --output /srv/phese-pages/preview
```

`init`은 기존 설정을 덮어쓰지 않는다. [기본 설정 예제](../themes/default.json)를 복사해 시작해도 된다. 설치 패키지는 `phese/assets/theme.json`과 `blocked.template.html`을 사용한다. 저장소의 `web/blocked.html`은 빌더가 수정하지 않는다.

## 바꿀 수 있는 값

| JSON 항목 | 의미 |
| --- | --- |
| `text.page_title` | 브라우저 제목 |
| `text.heading_lines` | 정확히 두 줄의 큰 제목 |
| `text.description` | 차단 이유 안내 |
| `text.button_text` | 외부 영상 이동 버튼 문구 |
| `text.footer` | 마지막 강조 문구 |
| `text.meme_caption` | 이미지 아래 문구 |
| `text.brand`, `text.name` | 제품명과 별칭 |
| `terms.isolation` | 입원 도장·대상·기록에 쓰는 용어 |
| `terms.sandbox`, `terms.deep`, `terms.risk` | 보호 구역·추가 보호 구역·판정 |
| `colors` | `paper`, `ink`, `blue`, `line`, `wash`, `red`, `amber`의 7개 `#RRGGBB` 색상 |
| `media.image_url`, `media.image_alt` | HTTPS 이미지와 대체 설명 |
| `media.youtube_video_id`, `media.youtube_title` | 배경 영상의 11자리 ID와 표시 제목 |
| `redirects` | 외부 이동 URL과 양의 정수 `weight` 목록 |

문구는 HTML 문법으로 처리하지 않고 문자로 표시한다. 제목 줄바꿈은 `heading_lines`의 두 항목으로 지정한다. 알 수 없는 필드나 잘못된 색상·URL·가중치는 빌드 오류로 보고한다.

`redirects`의 `weight` 합계는 정확히 100이어야 한다. 기본값은 `UBiXxfeiWq4` 98%, `zmfAMMwMOQc` 1%, `dQw4w9WgXcQ` 1%이다. 클릭마다 `crypto.getRandomValues`를 사용하며, 나머지 연산의 편향을 피하려고 4,294,960,000 이상의 값을 버리고 다시 추출한다. 이동 주소는 다음 형식만 허용한다.

- `https://www.youtube.com/watch?v=영상ID` 또는 `https://youtube.com/watch?v=영상ID`
- `https://youtu.be/영상ID`

인증 정보, 별도 포트, 추가 쿼리, fragment, 다른 호스트는 허용하지 않는다. JavaScript가 꺼져 있으면 첫 번째 URL이 일반 링크의 대체 주소가 된다. 이 버튼은 차단된 원래 요청을 다시 실행하거나 허용하지 않는다.

이미지는 인증 정보 없는 HTTPS URL이어야 한다. 해당 이미지의 origin만 생성 CSP의 `img-src`에 추가된다. 이미지를 빌더 서버로 다운로드하거나 가공하지 않는다. YouTube는 가시 재생창을 유지하며 자동 재생·반복 설정을 사용한다. 브라우저 자동 재생 정책, 네트워크 또는 YouTube의 로그인·봇 확인 때문에 실제 재생이 제한될 수 있다. 이미지나 영상이 열리지 않아도 핵심 차단 문구는 표시된다.

## 생성 파일과 안전한 업데이트

출력 디렉터리에 다음 파일이 생성된다.

- `blocked.html`: 페이지, 권한 `0644`
- `phese-page.ini`: 절대 페이지 경로와 해당 스크립트의 SHA-256 CSP, 권한 `0644`
- `.phese-page-build.json`: 두 생성 파일의 해시를 기록한 관리 manifest, 권한 `0600`

출력 디렉터리는 `0755`가 된다. 모든 경로 구성요소에서 symlink를 거부한다. 경로는 root 또는 실행 사용자 소유여야 하고 group/other 쓰기가 허용되면 안 된다. root로 실행할 때는 root 소유 경로만 사용할 수 있다. 이 정책은 `/tmp` 같은 공유 쓰기 디렉터리에도 적용되므로 작업 공간이나 안전한 전용 디렉터리를 사용한다.

다시 빌드할 때는 manifest와 기존 출력의 해시가 일치하는 경우에만 갱신한다. 같은 설정이면 `changed: false`를 반환한다. 출력 HTML이나 INI를 직접 편집했거나 다른 프로그램의 파일이 이미 있으면 덮어쓰기를 거부한다. 설정 JSON을 고쳐 다시 빌드하거나 새 출력 디렉터리를 사용한다. manifest를 임의로 다시 만들거나 해시 검사를 건너뛰지 않는다.

파일은 임시 파일을 작성한 후 교체하고 manifest를 마지막에 반영한다. 저장 중 중단돼 파일과 manifest가 불일치하면 다음 빌드는 거부한다. 해당 출력을 검토하고 새 디렉터리에 다시 생성한다. 여러 빌더 실행은 출력 디렉터리 lock으로 직렬화한다.

## 미리보기와 적용

```bash
python3 -m http.server 9080 --bind 127.0.0.1 \
  --directory /srv/phese-pages/preview
```

브라우저에서 `http://127.0.0.1:9080/blocked.html`을 연다. 다른 컴퓨터에서는 기존 관리용 SSH 터널 등을 통해 접속한다. 이 서버는 시각 확인용이며 응답 상태는 일반 정적 파일의 `200`이다. 운영의 네이티브 차단 응답 `403`과 활성 CSP 검증은 해당 PHP handler에서 별도로 수행한다.

검토를 마치면 운영자가 생성 HTML과 INI의 경로·소유권·권한을 확인하고, 해당 PHP의 관리자 시작 설정에 `phese-page.ini` 내용을 적용한다. HTML과 INI는 한 쌍으로 관리한다. `{{EVENT_ID}}`, `{{TIMESTAMP}}`는 네이티브 응답 시 바꾸는 토큰이므로 삭제하거나 직접 다른 형식으로 바꾸지 않는다. 기존 worker에는 파일 변경만으로 새 설정이 적용되지 않는다. 서비스 운영 절차에 따라 전체 프로세스를 재생성하고 실제 차단 응답을 확인한다. 빌더는 배포나 재시작을 수행하지 않는다.

레이아웃을 바꾸려면 관리하는 템플릿을 수정한 뒤 다시 빌드한다. CSP를 손으로 복사하거나 `script-src 'unsafe-inline'`로 바꿀 필요가 없다. 각 빌드에서 최종 스크립트 본문의 해시를 다시 계산하므로 문구·URL·템플릿 변경 후에도 생성 INI와 페이지가 일치한다.
