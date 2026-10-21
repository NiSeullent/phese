#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
if [ "$#" -ne 1 ]; then
    echo "usage: $0 /absolute/path/to/php-config" >&2
    exit 2
fi
config=$1
case "$config" in /*) ;; *) echo "php-config must be absolute" >&2; exit 2;; esac
phpize="$(dirname "$config")/phpize"
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
"$phpize"
./configure --enable-phese --with-php-config="$config"
make -j2
printf '%s\n' "Built extension/modules/phese.so; test against the matching patched PHP before installation."
