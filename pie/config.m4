PHP_ARG_ENABLE([pqcrypto],
  [whether to enable pqcrypto support],
  [AS_HELP_STRING([--enable-pqcrypto], [Enable pqcrypto support])],
  [no])

if test "$PHP_PQCRYPTO" != "no"; then
  AC_PATH_PROG(CARGO, cargo)
  if test -z "$CARGO"; then
    AC_MSG_ERROR([cargo is required to build pqcrypto. Please install rust (https://rustup.rs).])
  fi

  PHP_ADD_MAKEFILE_FRAGMENT()
  PHP_SUBST(PQCRYPTO_SHARED_LIBADD)
  PHP_NEW_EXTENSION(pqcrypto, pqcrypto.c, $ext_shared)
fi
