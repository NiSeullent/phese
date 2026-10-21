"""Build a configurable block page and its exact CSP without deploying it."""
import argparse
import base64
from contextlib import contextmanager
import fcntl
import hashlib
import html
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
from urllib.parse import parse_qsl, urlsplit

# A normal Python installation may reach site-packages through a trusted
# lib64 -> lib interpreter path. Normalize our already-imported package path;
# user-supplied config/output paths still reject symlinks component by component.
ASSETS = Path(__file__).resolve().with_name("assets")
MANIFEST = ".phese-page-build.json"
OUTPUTS = {"blocked.html", "phese-page.ini"}
VIDEO_ID = re.compile(r"[A-Za-z0-9_-]{11}\Z")
MARKER = re.compile(r"@@([A-Z_]+)@@")
LIMIT = 1024 * 1024


class PagesError(ValueError):
    pass


def _absolute(value):
    path = Path(value).expanduser()
    if ".." in path.parts:
        raise PagesError("경로에 '..'는 허용하지 않습니다.")
    return path if path.is_absolute() else Path.cwd() / path


def _trusted(metadata):
    if metadata.st_uid not in {0, os.geteuid()} or metadata.st_mode & 0o022:
        raise PagesError("모든 경로는 root 또는 실행 사용자 소유이며 group/other 쓰기가 금지돼야 합니다.")


@contextmanager
def _directory(value, *, create=False, mode=0o755):
    path = _absolute(value)
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        _trusted(os.fstat(descriptor))
        for component in path.parts[1:]:
            try:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY |
                                os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(component, mode, dir_fd=descriptor)
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY |
                                os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            _trusted(os.fstat(descriptor))
        yield path, descriptor
    finally:
        os.close(descriptor)


def _read_at(directory_fd, name, *, limit=LIMIT):
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=directory_fd)
    with os.fdopen(descriptor, "rb") as handle:
        metadata = os.fstat(handle.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise PagesError("일반 파일만 읽을 수 있습니다.")
        _trusted(metadata)
        data = handle.read(limit + 1)
        if len(data) > limit:
            raise PagesError("설정 또는 출력 파일의 크기 한도를 초과했습니다.")
        return data


def _read(value):
    path = _absolute(value)
    with _directory(path.parent) as (_, descriptor):
        return _read_at(descriptor, path.name)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PagesError("JSON에 중복 키가 있습니다.")
        result[key] = value
    return result


def _load_json(data):
    return json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object)


def _text(value, label, maximum=2000):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise PagesError(f"{label}: 비어 있지 않은 길이 제한 내 문자열이 필요합니다.")
    if any(ord(character) < 32 for character in value):
        raise PagesError(f"{label}: 제어 문자는 허용하지 않습니다.")
    return value


def _https(value, label):
    value = _text(value, label, 2048)
    if any(character in value for character in "\\<>\"'`") or any(character.isspace() for character in value):
        raise PagesError(f"{label}: 안전한 HTTPS URL이 필요합니다.")
    try:
        parsed = urlsplit(value)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None:
            raise ValueError
        hostname = parsed.hostname
        if ":" in hostname:
            hostname = "[" + str(ipaddress.IPv6Address(hostname)) + "]"
        else:
            hostname = hostname.encode("idna").decode("ascii").lower()
            if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", hostname):
                raise ValueError
        port = parsed.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError
    except (ValueError, UnicodeError):
        raise PagesError(f"{label}: 인증 정보 없는 올바른 HTTPS URL이 필요합니다.") from None
    origin = "https://" + hostname + (f":{port}" if port is not None else "")
    return parsed, origin


def _redirect(value):
    parsed, _ = _https(value, "redirects.url")
    if parsed.netloc.lower() not in {"youtube.com", "www.youtube.com", "youtu.be"} or parsed.fragment:
        raise PagesError("이동 URL은 지정한 YouTube HTTPS 호스트만 허용합니다.")
    if parsed.hostname == "youtu.be":
        valid = not parsed.query and bool(VIDEO_ID.fullmatch(parsed.path.lstrip("/"))) and parsed.path.count("/") == 1
    else:
        query = parse_qsl(parsed.query, keep_blank_values=True)
        valid = parsed.path == "/watch" and len(query) == 1 and query[0][0] == "v" and bool(VIDEO_ID.fullmatch(query[0][1]))
    if not valid:
        raise PagesError("이동 URL은 YouTube watch?v=영상ID 또는 youtu.be/영상ID 형식이어야 합니다.")
    return value


def validate_theme(theme):
    if not isinstance(theme, dict):
        raise PagesError("설정의 최상위 값은 JSON 객체여야 합니다.")
    groups = {
        "text": ("page_title", "description", "button_text", "footer", "meme_caption", "brand", "name"),
        "terms": ("isolation", "sandbox", "deep", "risk"),
        "colors": ("paper", "ink", "blue", "line", "wash", "red", "amber"),
        "media": ("image_url", "image_alt", "youtube_video_id", "youtube_title"),
    }
    if set(theme) != set(groups) | {"redirects"}:
        raise PagesError("설정의 최상위 키는 기본 설정과 같아야 합니다.")
    for group, keys in groups.items():
        if not isinstance(theme.get(group), dict):
            raise PagesError(f"{group}: JSON 객체가 필요합니다.")
        expected = set(keys) | ({"heading_lines"} if group == "text" else set())
        if set(theme[group]) != expected:
            raise PagesError(f"{group}: 설정 키는 기본 설정과 같아야 합니다.")
        for key in keys:
            _text(theme[group].get(key), f"{group}.{key}")
    lines = theme["text"].get("heading_lines")
    if not isinstance(lines, list) or len(lines) != 2:
        raise PagesError("text.heading_lines는 정확히 두 문자열이어야 합니다.")
    for line in lines:
        _text(line, "text.heading_lines", 200)
    for value in theme["colors"].values():
        if not isinstance(value, str) or not re.fullmatch(r"#[0-9a-fA-F]{6}", value):
            raise PagesError("colors는 #RRGGBB 형식의 7개 색상을 사용합니다.")
    if set(theme["colors"]) != set(groups["colors"]):
        raise PagesError("colors의 키는 기본 설정과 같아야 합니다.")
    _https(theme["media"]["image_url"], "media.image_url")
    if not VIDEO_ID.fullmatch(theme["media"]["youtube_video_id"]):
        raise PagesError("media.youtube_video_id는 11자리 YouTube 영상 ID여야 합니다.")
    redirects = theme.get("redirects")
    if not isinstance(redirects, list) or not 1 <= len(redirects) <= 100:
        raise PagesError("redirects에는 1~100개 이동 대상이 필요합니다.")
    for item in redirects:
        if (not isinstance(item, dict) or set(item) != {"url", "weight"} or
                type(item.get("weight")) is not int or not 1 <= item["weight"] <= 100):
            raise PagesError("각 이동 weight는 1~100의 정수여야 합니다.")
        _redirect(item.get("url"))
    if sum(item["weight"] for item in redirects) != 100:
        raise PagesError("이동 weight의 합계는 정확히 100이어야 합니다.")
    return theme


def _js_json(value):
    return json.dumps(value, ensure_ascii=True).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def render_page(theme):
    validate_theme(theme)
    replacements = {key.upper(): html.escape(value, quote=True) for key, value in theme["text"].items() if key != "heading_lines"}
    replacements["HEADING"] = "<br>".join(html.escape(line, quote=True) for line in theme["text"]["heading_lines"])
    replacements.update({key.upper(): html.escape(value, quote=True) for key, value in theme["terms"].items()})
    replacements.update({"COLOR_" + key.upper(): value for key, value in theme["colors"].items()})
    replacements.update({key.upper(): html.escape(value, quote=True) for key, value in theme["media"].items()})
    routes = theme["redirects"]
    replacements["FALLBACK_URL"] = html.escape(routes[0]["url"], quote=True)
    replacements["DESTINATIONS_JSON"] = _js_json([route["url"] for route in routes])
    cumulative, choices = 0, []
    for index, route in enumerate(routes[:-1]):
        cumulative += route["weight"] * 100
        choices.append(f"choice < {cumulative} ? {index} : ")
    replacements["DESTINATION_INDEX"] = "".join(choices) + str(len(routes) - 1)
    template = _read(ASSETS / "blocked.template.html").decode("utf-8")
    if set(MARKER.findall(template)) != set(replacements):
        raise PagesError("템플릿과 설정 필드가 일치하지 않습니다.")
    if any(template.count(token) != 1 for token in ("{{EVENT_ID}}", "{{TIMESTAMP}}")):
        raise PagesError("템플릿은 두 네이티브 기록 토큰을 각각 한 번 유지해야 합니다.")
    # Substitute once: configuration text containing marker-like strings is data.
    page = MARKER.sub(lambda match: replacements[match.group(1)], template)
    scripts = re.findall(r"<script>([\s\S]*?)</script>", page)
    if len(scripts) != 1:
        raise PagesError("예상한 고정 제어 스크립트를 찾지 못했습니다.")
    digest = base64.b64encode(hashlib.sha256(scripts[0].encode("utf-8")).digest()).decode("ascii")
    _, image_origin = _https(theme["media"]["image_url"], "media.image_url")
    csp = ("default-src 'none'; base-uri 'none'; object-src 'none'; form-action 'none'; "
           "frame-ancestors 'none'; style-src 'unsafe-inline'; "
           f"script-src 'sha256-{digest}'; img-src {image_origin}; "
           "frame-src https://www.youtube-nocookie.com")
    return page.encode("utf-8"), csp


def _present(directory_fd, name):
    try:
        os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def _temporary(directory_fd, data, mode):
    name = ".phese-page-" + secrets.token_hex(12)
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=directory_fd)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            os.fchmod(handle.fileno(), mode)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        return name
    except BaseException:
        os.unlink(name, dir_fd=directory_fd)
        raise


def init_theme(destination):
    path = _absolute(destination)
    data = _read(ASSETS / "theme.json")
    validate_theme(_load_json(data))
    with _directory(path.parent, create=True, mode=0o700) as (_, descriptor):
        if _present(descriptor, path.name):
            raise PagesError("기존 설정 파일은 덮어쓰지 않습니다.")
        temporary = _temporary(descriptor, data, 0o644)
        try:
            # A hard-link publishes the new file without replacing a racing path.
            os.link(temporary, path.name, src_dir_fd=descriptor,
                    dst_dir_fd=descriptor, follow_symlinks=False)
            os.fsync(descriptor)
        finally:
            os.unlink(temporary, dir_fd=descriptor)
    return {"config": str(path), "created": True}


def build_page(config, output):
    theme = validate_theme(_load_json(_read(config)))
    page, csp = render_page(theme)
    output = _absolute(output)
    if any(character in str(output) for character in '"\\\r\n'):
        raise PagesError("출력 경로에 INI 인용을 깨뜨리는 문자는 허용하지 않습니다.")
    ini = ('; Generated by phese.pages; review before applying.\n'
           f'phese.block_page = "{output / "blocked.html"}"\n'
           f'phese.block_csp = "{csp}"\n').encode("utf-8")
    files = {"blocked.html": page, "phese-page.ini": ini}
    hashes = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
    manifest = {"generator": "phese.pages", "format": 1, "files": hashes}
    manifest_data = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode("utf-8")
    with _directory(output, create=True) as (_, descriptor):
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        existing = {}
        if _present(descriptor, MANIFEST):
            previous = _load_json(_read_at(descriptor, MANIFEST, limit=65536))
            if (not isinstance(previous, dict) or previous.get("generator") != "phese.pages" or
                    type(previous.get("format")) is not int or previous["format"] != 1 or
                    not isinstance(previous.get("files"), dict) or set(previous["files"]) != OUTPUTS):
                raise PagesError("출력 manifest가 phese 관리 형식과 일치하지 않습니다.")
            for name in OUTPUTS:
                if not _present(descriptor, name):
                    raise PagesError("관리된 출력 파일이 사라졌습니다. 새 출력 디렉터리를 사용하세요.")
                existing[name] = _read_at(descriptor, name)
                if hashlib.sha256(existing[name]).hexdigest() != previous["files"][name]:
                    raise PagesError("기존 출력이 직접 변경됐습니다. 덮어쓰지 않습니다.")
        elif any(_present(descriptor, name) for name in OUTPUTS):
            raise PagesError("phese가 관리하지 않는 기존 출력 파일은 덮어쓰지 않습니다.")
        changed = existing != files
        pending = []
        try:
            if changed:
                for name, data in [*files.items(), (MANIFEST, manifest_data)]:
                    mode = 0o600 if name == MANIFEST else 0o644
                    pending.append((_temporary(descriptor, data, mode), name))
                # Publish the manifest last; interrupted writes fail validation on
                # the next build rather than silently adopting a partial state.
                for temporary, name in pending:
                    os.replace(temporary, name, src_dir_fd=descriptor, dst_dir_fd=descriptor)
                os.fsync(descriptor)
            for name in [*OUTPUTS, MANIFEST]:
                item_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                  dir_fd=descriptor)
                try:
                    os.fchmod(item_fd, 0o600 if name == MANIFEST else 0o644)
                finally:
                    os.close(item_fd)
            os.fchmod(descriptor, 0o755)
        finally:
            for temporary, _ in pending:
                if _present(descriptor, temporary):
                    os.unlink(temporary, dir_fd=descriptor)
    return {"output": str(output), "page": str(output / "blocked.html"),
            "ini": str(output / "phese-page.ini"), "changed": changed, "csp": csp}


def main(argv=None):
    parser = argparse.ArgumentParser(description="phese 차단 페이지 설정과 HTML/CSP 생성")
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="기본 JSON 설정 생성")
    init.add_argument("config")
    build = commands.add_parser("build", help="HTML과 대응 INI 생성; 자동 적용 없음")
    build.add_argument("--config", required=True)
    build.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        result = init_theme(args.config) if args.command == "init" else build_page(args.config, args.output)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (OSError, ValueError) as error:
        print("phese pages: " + (str(error) if isinstance(error, PagesError) else type(error).__name__), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
