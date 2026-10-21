<?php
/* Runs inside the namespace before the application, even if loading the
 * native module failed. PHP's missing-extension startup warning is not fatal. */
if (!extension_loaded('phese') || !function_exists('phese_status')) {
    error_log("phese: protection module unavailable; execution refused");
    exit(78);
}
$pheseProtection = phese_status();
foreach (['seccomp_active', 'no_new_privileges', 'version_gate'] as $pheseKey) {
    if (($pheseProtection[$pheseKey] ?? null) !== true) {
        error_log("phese: enforcement unavailable; execution refused");
        exit(78);
    }
}
unset($pheseProtection, $pheseKey);
