PHP_ARG_ENABLE([phese], [whether to enable phese],
  [AS_HELP_STRING([--enable-phese], [Enable mandatory phese syscall enforcement])], [no])

if test "$PHP_PHESE" != "no"; then
  AC_CHECK_HEADERS([linux/seccomp.h linux/filter.h linux/audit.h], [],
    [AC_MSG_ERROR([phese requires Linux seccomp headers])])
  PHP_NEW_EXTENSION([phese], [phese.c], [$ext_shared])
fi
