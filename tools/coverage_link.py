# Native-coverage helper: gcov needs --coverage at LINK time too, and
# build_flags do not reach the program link line. Only used by the
# [env:native-cov] test environment (see platformio.ini).
Import("env")

env.Append(LINKFLAGS=["--coverage"])
