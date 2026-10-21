# phese (폐쇄!) native enforcement

The validated support target is **Linux x86_64, PHP 8.5.12 ZTS, glibc**. Other PHP ABIs, NTS, musl and AArch64 require separate build and runtime validation before release support. The source contains admission rules for other fixed PHP branches and an AArch64 filter definition; those are not claims of completed platform qualification.

This Linux PHP extension is one containment layer of AsylumEnforce. It is new defensive code, not a port of the Suhosin PHP 5 extension, and does not reproduce its engine patches or cookie/session encryption.

Load from a root-controlled PHP startup configuration, before accepting requests. At module initialization it checks the **running interpreter's** `PHP_VERSION_ID` and `PHP_EXTRA_VERSION` constants. The patched-version admission rules begin at PHP 8.2.35, 8.3.36, 8.4.27 and 8.5.12 respectively; only the support target above has been exercised end to end. Older versions, other branches and nonempty prerelease/vendor suffixes are refused. Numeric version checks cannot authenticate a malicious or incorrectly labeled PHP build; install authentic vendor/upstream binaries. A backport with a lower numeric version requires a separately reviewed policy change, not an application flag.

In the default `startup` scope, after the version check the extension sets irreversible `no_new_privs` and installs a seccomp filter with `SECCOMP_FILTER_FLAG_TSYNC` during MINIT. An installation or thread synchronization failure aborts PHP startup. There is no disable switch, application INI override or execution exception. Existing threads synchronize; subsequent forks and threads inherit the filter. For `startup` scope, installation occurs during MINIT, before PHP request startup and multipart processing. The `worker` scope described below installs it at the first accepted FPM or Apache request in RINIT, after worker privileges have been dropped. Apache rejects `startup` scope because repeated module initialization during graceful reload can otherwise accumulate irreversible filters in the master.

The filter denies process replacement (`execve`, `execveat`), process tracing and cross-process memory operations, namespace creation and switching, mount operations, kernel module loading, BPF/performance instrumentation, kernel keyrings, io_uring and selected system administration calls. It rejects alternate syscall architectures and x32 syscall numbers. Namespace flags on `clone` are rejected; `clone3` returns `ENOSYS` so glibc can fall back for ordinary threads. Ordinary fork, file I/O, PHP evaluation, sockets and pool privilege dropping remain available.

**Filesystem visibility, writable paths, database permissions, network connections and resource limits require the outer sandbox/service policy.** This extension does not prevent execution of injected native instructions inside the current process. It limits selected kernel operations those instructions could perform. It neither repairs memory corruption nor replaces the official fixes for CVE-2026-109618 and CVE-2026-109619.

## Enforcement scopes

`phese.scope` is **PHP_INI_SYSTEM**, validated and cached during MINIT. Application code cannot switch the effective scope.

| Scope | Where seccomp is installed | Intended use | FPM USR2 |
| --- | --- | --- | --- |
| `startup` (default) | Module initialization, inherited by threads/children | CLI sandboxes; FPM only with a reviewed full-restart lifecycle | Blocked by no-exec policy |
| `worker` | First accepted nonroot FPM or Apache request, once per worker process | FPM and Apache services, including normal graceful reload | Master remains able to re-execute |

`worker` is rejected during module startup in every SAPI except `fpm-fcgi` and `apache2handler`. Apache requires `worker` scope. Thread synchronization and a process-local initialization lock prevent concurrent Apache requests from installing duplicate filters. The fixed-version gate, trusted page/CSP cache and internal-call hook remain active during MINIT in both scopes. In `worker` scope, PHP-FPM `-v`/`-i` and preload initialization without an accepted FastCGI request do not install a filter or claim a protected worker. A real request in a root-UID worker is refused. A failed seccomp installation terminates request startup before the application can execute; no weaker fallback is attempted.

The FPM and Apache masters, plus trusted preload/module initialization, are outside the worker filter. Input and multipart parsing before RINIT depend on the mandatory official PHP security patches. Worker scope is additional containment and must never be used to run an unpatched interpreter. Keep server startup configuration and preload sources under trusted administrative control. A successfully started master or an FPM configuration syntax check does not prove that request workers can install seccomp: issue a real readiness request and check `phese_status()` in each intended handler.

Configure a separate service-specific PHP scan directory for each web service, leaving operational CLI instances unchanged. See [transactional web installation](../docs/web-install.md):

```ini
extension=/absolute/path/to/matching/phese.so
phese.scope=worker
```

The integration tests exercise both scopes, a real USR2 master re-execution with a newly protected worker, pool UID dropping, worker recycling, rejection of worker scope in CLI and Apache startup scope, refusal of root workers, and refusal to execute application code when an outer test filter denies seccomp installation. The outer failure-injection launcher is a test fixture and must not be used as a production sandbox.

## Build and test

Build with development headers matching the target interpreter's architecture, PHP module ABI, thread-safety mode and C library. A glibc/ZTS module must not be copied into an Alpine musl/NTS runtime.

```sh
./extension/build.sh /absolute/path/to/php-config
PHESE_TEST_PHP=/absolute/path/to/patched/php python3 -m unittest discover -s tests -p 'test_native*' -v
/absolute/path/to/patched/php -n -d extension="$PWD/extension/modules/phese.so" -r 'echo json_encode(phese_status()), PHP_EOL;'
```

`phese_status()` returns the cached effective `scope`, `seccomp_active`, `no_new_privileges`, `version_gate`, `enforcing` and version information. `network_isolated` and `filesystem_isolated` are false because the extension alone cannot attest an outer sandbox. The CLI attests those separately.

The C tests run actual syscalls in disposable child processes. They cover direct execve/execveat, existing/new threads, fork inheritance, ptrace, namespace restrictions, clone3 fallback, normal file I/O, x32 and an incompatible x86 syscall architecture. AArch64 filter code is present, but the current x86_64 test host cannot validate an AArch64 kernel.

## Service compatibility and rollback

A no-exec policy necessarily breaks PHP applications that start shell commands, Composer children, mail transport binaries or media converters. Leave application sources unchanged and generate a modification request. Run a reviewed external helper service with narrowly scoped inputs when subprocess work is necessary.

**With `phese.scope=startup`, FPM graceful reload (`SIGUSR2`) re-executes the FPM master and is blocked.** In that scope use a full supervisor-controlled stop/start or restart. For FPM installations that require USR2 reload, configure `phese.scope=worker`; its unfiltered master can re-execute while every request worker installs enforcement after the pool UID drop. Configure the service management command accordingly before rollout. This may briefly interrupt requests unless a separate listener/reverse-proxy handoff is arranged. In `startup` scope, pool `chroot` is also blocked after MINIT. In `worker` scope, FPM can complete its configured chroot and UID/GID drop before RINIT installs the filter. With startup scope the FPM master can still drop UID/GID for pools, and its no_new_privs restriction prevents privilege gains through setuid executables. With worker scope those restrictions apply to request workers; the trusted master remains outside the filter.

Apache loads the module and trusted page during server startup but installs the filter only in nonroot request workers. With `worker` scope, the event/worker MPM master remains able to perform graceful reload without accumulating filters. The first concurrent request wave synchronizes all existing threads once; later requests reuse the process filter. External commands invoked within the protected worker remain incompatible. Configuration syntax checks do not establish enforcement; issue a real mod_php request and inspect the responding process. The exact MPM and loaded modules still require compatibility testing. See [native lifecycle validation](../docs/native-lifecycle.md).

To roll back, remove only the phese extension startup directive and its associated service override, then perform a full supervisor-controlled service restart. Already filtered processes cannot remove the seccomp filter. Keep official PHP security updates installed.

PHP itself treats a missing or ABI-incompatible `extension=` library as a startup warning and may continue without loading it. Native code cannot intervene when the loader never invokes it. Therefore the `phese` CLI verifies `extension_loaded` and status before running an application, and a web installation must verify the module before starting the service and attest each actual PHP handler. The transactional web installer adds an `ExecStartPre` doctor check against its root-controlled immutable module and scopes the INI to the selected service. An early application guard can provide a further check where the deployment supports it. A successful `php -v` or `php-fpm -t` alone is not proof of enforcement.

The extension does not sanitize already inherited file descriptors, shared memory, already-created io_uring queues, or other modules' credentials. Launch PHP from a clean, least-privileged supervisor; the CLI closes inherited descriptors. New kernel interfaces are allowed unless explicitly covered here, so keep the kernel updated and review the syscall policy for each supported deployment. This deny policy is additional containment, not a claim that every future syscall or CVE is blocked.

An optional integration test starts its own Apache event-MPM listener bound to loopback, sends concurrent mod_php requests, checks the real worker's `/proc` flags, and checks protection after an Apache graceful restart. It never touches installed services:

```sh
PHESE_TEST_PHP=/path/to/patched/php \
PHESE_TEST_APACHE=/path/to/apache/sbin/httpd \
PHESE_TEST_LIBPHP=/path/to/patched/libphp.so \
PHESE_TEST_APACHE_ROOT=/path/to/apache \
python3 -m unittest discover -s tests -p 'test_native*' -v
```

The optional FPM integration test uses a separate temporary Unix socket and pool. It issues real FastCGI requests with the Python standard library, checks ordinary JSON processing and the dropped pool UID, and verifies denial remains effective across `pm.max_requests` worker recycling:

```sh
PHESE_TEST_PHP=/path/to/patched/php \
PHESE_TEST_FPM=/path/to/patched/php-fpm \
python3 -m unittest discover -s tests -p 'test_native_fpm.py' -v
```

## Web admission response and audit events

A chained `zend_execute_internal` hook observes only an explicit list of internal APIs: `exec`, `system`, `shell_exec`, `passthru`, `proc_open`, `popen`, `pcntl_exec`, `mail`, `mb_send_mail`, `dl` and the `FFI` class. In web SAPIs the hook logs the policy reason, sends a generic Korean 403 admission page, and bails out before calling the selected native API. Subsequent application-buffer output is suppressed. CLI/phpdbg keeps its existing behavior: the attempt is observed and logged; seccomp still rejects process execution, while a non-execution FFI or `dl` operation can succeed. The CLI audit event therefore records an attempted API use, not proof of a blocked native interface.

The `phese.block_page` **PHP_INI_SYSTEM** directive accepts an optional HTML file. MINIT opens it with `O_NOFOLLOW`, checks regular-file/root ownership/no group or world write bits and a 256 KiB size limit, and caches its content. Requests do not read this host path. Only `{{EVENT_ID}}` and `{{TIMESTAMP}}` are replaced. The response deliberately omits function names, arguments, host paths and technical details. An empty directive uses the built-in Korean fallback page. An invalid configured page aborts startup.

`phese.block_csp` is also PHP_INI_SYSTEM and cached at startup. It must be nonempty, at most 4 KiB and contain no CR/LF. The built-in default CSP permits images from `https://i.ibb.co`, YouTube-nocookie frames and inline styles; the page builder generates a separate CSP for its configured image origin; scripts are denied unless the administrator adds the exact static script hash. Responses also set `Cache-Control: no-store`, `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`. If an application already transmitted response headers before attempting the operation, HTTP cannot retroactively change its status or headers; the extension still stops the selected call and sends the generic body.

Audit records use local `/dev/log` Unix datagrams with authpriv facility and fixed `phese` identity. This avoids libc `openlog`'s shared identity being changed by application code. The message is JSON with `product`, `component`, `event`, a 32-hex `event_id`, UTC `timestamp`, `pid`, fixed `reason`, a whitelisted function name, the requested Korean terminology and the exact message `ㅋㅋㅋㅋㅋ어떻게병동이름이폐쇄얔ㅋㅋㅋㅋㅋㅋ`. Raw arguments, request bodies, URL parameters and host paths are never included. Events distinguish unsupported PHP, missing mandatory seccomp, process API attempts and native-interface API attempts.

Logging is best effort and nonblocking: the local collector must exist, and full queues or sandbox paths that omit `/dev/log` can drop native events. The outer CLI still records its own policy/lifecycle events. Direct raw syscalls, code paths that bypass Zend's internal-function dispatcher, unavailable/disabled PHP functions, and already inherited kernel resources are not completely observed by this hook. Seccomp enforcement remains independent of this audit layer. Do not claim that every attacker or every syscall attempt is logged.

A `sandbox_started`/`seccomp_installed` event is emitted after successful installation: MINIT in `startup` scope, or first accepted-request RINIT in each `worker` scope process. On the first request in each PID, an atomic check emits one `sandbox_started`/`policy_enforced` event; Apache threads in the same worker do not duplicate it, and a forked FPM worker logs its own PID. This indicates a PHP process entered enforcement, not that a particular person was identified. Native shutdown events are not guaranteed when a worker crashes, is killed or exits outside PHP shutdown.

Admission responses cancel the application's pending header callback without executing it before the response, discard stale status lines/`Status:` headers, and set the SAPI status through its header API. Regression tests cover callbacks that attempt to restore HTTP 200 or exit, and both PHP forms of an existing HTTP 200 status. Outside an active HTTP request (for example, preload/module startup), the hook audits attempts without invoking HTTP response callbacks.
