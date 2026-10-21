#!/usr/bin/env bash
# Build/test helper for an explicitly disposable GitHub-hosted Ubuntu VM only.
set -euo pipefail
umask 022

if [[ ${GITHUB_ACTIONS:-} != true || ${PHESE_CI_EPHEMERAL_RUNNER:-} != 1 || $(id -u) != 0 ]]; then
    printf '%s\n' 'This script requires the explicit disposable-CI flag, GitHub Actions and root.' >&2
    exit 2
fi
if [[ $(uname -m) != x86_64 || ! -x /usr/bin/apxs || ! -x /usr/sbin/apache2 ]]; then
    printf '%s\n' 'The supported CI profile requires Ubuntu x86_64 with apache2-dev.' >&2
    exit 2
fi

phese_ci_repository=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
python3 - <<'PY'
import os
import stat

parent = os.lstat("/")
print(f"CI build parent /: uid={parent.st_uid} mode={stat.S_IMODE(parent.st_mode):04o}", flush=True)
if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o022:
    raise SystemExit("CI build parent must be a root-owned directory without group/other write access")
try:
    previous_parent = os.lstat("/opt")
except FileNotFoundError:
    print("CI /opt diagnostic: absent", flush=True)
else:
    print(f"CI /opt diagnostic: uid={previous_parent.st_uid} mode={stat.S_IMODE(previous_parent.st_mode):04o} symlink={stat.S_ISLNK(previous_parent.st_mode)}", flush=True)
PY
phese_ci_root=$(mktemp -d /phese-native-ci.XXXXXXXX)
chmod 0755 "$phese_ci_root"
stat -c 'CI temporary build root: uid=%u mode=%a' "$phese_ci_root"
cleanup() {
    phese_ci_exit=$?
    trap - EXIT
    if [[ $phese_ci_exit != 0 ]]; then
        for phese_ci_log in "$phese_ci_root"/*.log; do
            if [[ -f $phese_ci_log ]]; then
                printf '\n%s\n' "Last build output: $phese_ci_log" >&2
                tail -n 80 "$phese_ci_log" >&2
            fi
        done
    fi
    # The path is created above, never accepted as an arbitrary cleanup argument.
    rm -rf -- "$phese_ci_root"
    exit "$phese_ci_exit"
}
trap cleanup EXIT

phese_ci_php_version=8.5.12
phese_ci_php_sha256=08bc2eba2a588654ade1357174aa646b761556c862dda0678345ee29ed481209
phese_ci_bwrap_commit=dc63ec667e6546f34e0b6c088cdf8ae7c7dea0f3
phese_ci_php_source="$phese_ci_root/php-source"
phese_ci_php_prefix="$phese_ci_root/php"
phese_ci_bwrap_source="$phese_ci_root/bubblewrap-source"
phese_ci_bwrap_prefix="$phese_ci_root/bubblewrap"
phese_ci_test_checkout="$phese_ci_root/checkout"
mkdir -m 0755 "$phese_ci_php_source" "$phese_ci_test_checkout"

# Root-owned ancestors are required by the page/setup trust checks. A hosted
# runner's /home/runner checkout is not a suitable root-owned fixture path.
git -c safe.directory="$phese_ci_repository" -C "$phese_ci_repository" archive HEAD |
    tar -xf - -C "$phese_ci_test_checkout"
chown -R 0:0 "$phese_ci_test_checkout"
chmod -R u=rwX,go=rX "$phese_ci_test_checkout"

curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --retry 3 --connect-timeout 20 --max-time 180 \
    "https://www.php.net/distributions/php-$phese_ci_php_version.tar.xz" \
    --output "$phese_ci_root/php.tar.xz"
printf '%s  %s\n' "$phese_ci_php_sha256" "$phese_ci_root/php.tar.xz" | sha256sum --check --strict -
tar -xJf "$phese_ci_root/php.tar.xz" --strip-components=1 -C "$phese_ci_php_source"

git init "$phese_ci_bwrap_source"
git -C "$phese_ci_bwrap_source" -c protocol.file.allow=never fetch --no-tags --depth=1 \
    https://github.com/containers/bubblewrap.git "$phese_ci_bwrap_commit"
git -C "$phese_ci_bwrap_source" checkout --detach FETCH_HEAD
[[ $(git -C "$phese_ci_bwrap_source" rev-parse HEAD) == "$phese_ci_bwrap_commit" ]]
meson setup "$phese_ci_root/bubblewrap-build" "$phese_ci_bwrap_source" \
    --prefix "$phese_ci_bwrap_prefix" -Dman=disabled -Dselinux=disabled \
    -Dbash_completion=disabled -Dzsh_completion=disabled -Dtests=false -Drequire_userns=true \
    > "$phese_ci_root/bubblewrap-configure.log" 2>&1
meson compile -C "$phese_ci_root/bubblewrap-build" -j 2 > "$phese_ci_root/bubblewrap-build.log" 2>&1
meson install -C "$phese_ci_root/bubblewrap-build" --no-rebuild > "$phese_ci_root/bubblewrap-install.log" 2>&1
[[ $("$phese_ci_bwrap_prefix/bin/bwrap" --version) == 'bubblewrap 0.10.0' ]]

cd "$phese_ci_php_source"
./configure --prefix="$phese_ci_php_prefix" \
    --with-config-file-path="$phese_ci_php_prefix/etc" \
    --with-config-file-scan-dir="$phese_ci_php_prefix/etc/conf.d" \
    --disable-all --enable-zts --enable-fpm --with-apxs2=/usr/bin/apxs \
    --enable-session --enable-pcntl --enable-posix \
    --disable-cgi --disable-phpdbg --without-pear \
    > "$phese_ci_root/php-configure.log" 2>&1
make -j 2 > "$phese_ci_root/php-build.log" 2>&1
# Deliberately omit install-sapi: apxs must not install/enable a module in the
# runner's system Apache configuration. Every PHP output stays under our root.
make install-cli install-fpm install-build install-headers install-programs \
    > "$phese_ci_root/php-install.log" 2>&1
install -m 0644 libs/libphp.so "$phese_ci_php_prefix/libphp.so"

export PATH="$phese_ci_bwrap_prefix/bin:$phese_ci_php_prefix/bin:/usr/sbin:/usr/bin:/sbin:/bin"
unset PHPRC PHP_INI_SCAN_DIR LD_PRELOAD LD_LIBRARY_PATH
cd "$phese_ci_test_checkout"
sh extension/build.sh "$phese_ci_php_prefix/bin/php-config" > "$phese_ci_root/phese-build.log" 2>&1
chmod 0644 extension/modules/phese.so phese/guard.php
export PHESE_TEST_PHP="$phese_ci_php_prefix/bin/php"
export PHESE_TEST_FPM="$phese_ci_php_prefix/sbin/php-fpm"
export PHESE_TEST_EXTENSION="$phese_ci_test_checkout/extension/modules/phese.so"
export PHESE_TEST_APACHE=/usr/sbin/apache2
export PHESE_TEST_APACHE_ROOT=/usr/lib/apache2
export PHESE_TEST_LIBPHP="$phese_ci_php_prefix/libphp.so"
"$PHESE_TEST_PHP" -n -r 'exit(PHP_VERSION_ID === 80512 && PHP_ZTS && extension_loaded("session") && extension_loaded("pcntl") && extension_loaded("posix") ? 0 : 1);'
"$PHESE_TEST_PHP" -n -d "extension=$PHESE_TEST_EXTENSION" -r '$s=phese_status(); exit($s["enforcing"] && $s["seccomp_active"] && $s["no_new_privileges"] ? 0 : 1);'
python3 -m compileall -q phese tools tests
python3 - <<'PY'
import sys
import unittest

suite = unittest.defaultTestLoader.discover("tests")

def cases(value):
    for item in value:
        if isinstance(item, unittest.TestSuite):
            yield from cases(item)
        else:
            yield item

identifiers = [item.id() for item in cases(suite)]
required = (
    "test_native_seccomp.SeccompFilterTests.",
    "test_native_seccomp.PHPNativeExtensionTests.",
    "test_native_fpm.FPMNativeExtensionTests.",
    "test_native_fpm.FPMWorkerNativeExtensionTests.",
    "test_native_apache.ApacheNativeExtensionTests.",
    "test_sandbox_integration.ActualSandboxTests.",
)
for prefix in required:
    if not any(identifier.startswith(prefix) for identifier in identifiers):
        raise SystemExit("Required supported-profile test class missing: " + prefix)
result = unittest.TextTestRunner(verbosity=2).run(suite)
if result.skipped:
    for test, reason in result.skipped:
        print("Unexpected supported-profile skip:", test.id(), reason, file=sys.stderr)
raise SystemExit(0 if result.wasSuccessful() and not result.skipped else 1)
PY
