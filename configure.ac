#########################################
##### Prelude #####

AC_PREREQ(2.59)
AC_INIT([pd], [0.56.0])
AC_CONFIG_SRCDIR(src/m_pd.c)
AC_CONFIG_AUX_DIR([m4/config])
AC_CONFIG_MACRO_DIR([m4/generated])
AM_INIT_AUTOMAKE([subdir-objects])
AC_CANONICAL_HOST


########################################
#### ohoh. automake<<1.16 does not like $(top_srcdir) in _SOURCES.
AS_IF([test "$( (echo 1.16; echo ${am__api_version}) | sort -t. -k 1,1n -k 2,2n -k 3,3n -k 4,4n | head -1)" != "1.16"], [
  enable_dependency_tracking=no
  AC_MSG_WARN([legacy automake detected: disabled dependency-tracking!
	       to get rid of this warning and enable dependency-tracking,
	       please install at least automake-1.16 and rerun './autogen.sh'
	       ])
])

# check whether the user has provided --program-transform-name
# we need this so we can fall back to a default transformation
# in case the user passed --with-floatsize
AS_CASE([$ac_configure_args],
        [*\'--program-transform-name*], [have_program_transform_name=yes],
        [*\'--program-prefix*], [have_program_transform_name=yes],
        [*\'--program-suffix*], [have_program_transform_name=yes],
        [have_program_transform_name=no])

#########################################
##### Default values #####

# set here and not in AC_ARG_ENABLE so the values set in the OS detection
# below are not overwritten if the configure argument isn't used
portaudio=no
portmidi=no
local_portaudio=yes
local_portmidi=yes
mmio=no
asio=no
wasapi=no
jack_framework=no
locales=yes

# wish command info, the actual value is set using the WISH define
# "wish" mirrors the default WISH define in s_inter.c
wish="wish"

# list of detected apis
audio_backends=""
midi_backends=""

# deken information
deken_os=""
deken_cpu=""
deken_ext="so"
floatsize=""

# debug/release defaults
DEBUG_CFLAGS="-O0"
RELEASE_CFLAGS="-ffast-math -fno-finite-math-only -funroll-loops -fomit-frame-pointer -O3"

# common flags applied to all pd binaries
PD_CPPFLAGS=""
PD_CFLAGS=""
PD_LDFLAGS=""


#########################################
##### OS Detection #####

# you will need to install XCode on Mac OS X to use this:
PD_CHECK_IPHONE(IPHONEOS=yes, IPHONEOS=no, AC_MSG_ERROR([iOS SDK not available]))
PD_CHECK_ANDROID(ANDROID=yes, ANDROID=no, AC_MSG_ERROR([Android SDK not available]))

AS_CASE([$host],
[*darwin*],[
    AS_IF([test "x${IPHONEOS}" = "xno"],[
        MACOSX=yes
        platform="Mac OSX"
        deken_os=darwin
        coreaudio=yes
        portaudio=yes
        portmidi=yes
        jack_framework=yes
        watchdog=yes
        EXTERNAL_CFLAGS="-fPIC"
        EXTERNAL_EXTENSION=d_fat

        # helps for machine/endian.h to be found
        PD_CFLAGS="-D_DARWIN_C_SOURCE"

        # increase max allowed file descriptors
        PD_CFLAGS="$PD_CFLAGS -D_DARWIN_UNLIMITED_SELECT -DFD_SETSIZE=10240"

        # a set of search paths are used on macOS in s_inter.c
        wish="default search paths"

        # required for dlopen & weak linking for older macOS version support
        macos_version_min=10.6
    ],[
        platform=iOS
        locales=no
        wish="not used"
    ])

    # homebrew paths
    AS_IF([test -e /usr/local],[
        AM_CPPFLAGS="-I/usr/local/include $INCLUDES"
        PD_LDFLAGS="-L/usr/local/lib $PD_LDFLAGS"
    ])

    # fink paths
    AS_IF([test -e /sw],[
        AM_CPPFLAGS="-I/sw/include $INCLUDES"
        PD_LDFLAGS="-L/sw/lib $PD_LDFLAGS"
    ])

    # macports paths
    AS_IF([test -e /opt/local],[
        AM_CPPFLAGS="-I/opt/local/include $INCLUDES"
        PD_LDFLAGS="-L/opt/local/lib $PD_LDFLAGS"
    ])

    EXTERNAL_LDFLAGS="-bundle -undefined dynamic_lookup"
],[*linux*|*kfreebsd*gnu*],[
    # GNU/kFreeBSD are for Debian, were they are treated very similar to linux
    AS_IF([test "x${ANDROID}" = "xno"],[
        LINUX=yes
        platform=Linux
        deken_os=linux
        portaudio=yes
        watchdog=yes
        EXTERNAL_CFLAGS="-fPIC"
        EXTERNAL_LDFLAGS="-Wl,--export-dynamic -fPIC"
        EXTERNAL_EXTENSION=pd_linux
    ],[
        platform=Android
        EXTERNAL_EXTENSION=so
    ])
],[*-*-gnu*],[
    HURD=yes
    platform=Hurd
    deken_os=linux
    watchdog=yes
    EXTERNAL_CFLAGS="-fPIC"
    EXTERNAL_LDFLAGS="-Wl,--export-dynamic -fPIC"
    EXTERNAL_EXTENSION=pd_linux
],[*mingw*],[
    WINDOWS=yes
    MINGW=yes
    platform=MinGW
    deken_os=windows
    mmio=yes
    asio=yes
    wasapi=yes
    portaudio=yes
    portmidi=yes

    # this mirrors the default windows WISH define in s_inter.c
    wish="wish86.exe"

    # externals need to be dynamically linked to pd.dll,
    # but we need to check for --with-floatsize first (see below)
    EXTERNAL_CFLAGS="-mms-bitfields"
    EXTERNAL_LDFLAGS="-Wl,--enable-auto-import -no-undefined"
    EXTERNAL_EXTENSION=dll

    # workaround for rpl_malloc/rpl_realloc bug in autoconf when cross-compiling
    ac_cv_func_malloc_0_nonnull=yes
    ac_cv_func_realloc_0_nonnull=yes
],[*cygwin*],[
    WINDOWS=yes
    CYGWIN=yes
    platform=Cygwin
    deken_os=windows
    mmio=yes
    asio=yes
    wasapi=yes
    portaudio=yes
    portmidi=yes

    # this mirrors the default windows WISH define in s_inter.c
    wish="wish86.exe"

    # externals need to be dynamically linked to pd.dll,
    # but we need to check for --with-floatsize first (see below)
    EXTERNAL_CFLAGS=
    EXTERNAL_LDFLAGS="-Wl,--export-dynamic"
    EXTERNAL_EXTENSION=dll
],[*bsd*],[
    BSD=yes
    EXTERNAL_EXTENSION=so
],[
    platform=Unknown
    EXTERNAL_EXTENSION=so
])

AS_IF([test "x${deken_os}" = "xwindows"],[deken_ext=dll])


AS_CASE([$host_cpu],
    [x86_64|amd64],[deken_cpu=amd64],
    [i386|i486|i586|i686],[deken_cpu=i386],
    [aarch64],[deken_cpu=arm64],
    [armv*l],[deken_cpu=${host_cpu%l}],
    [armv*b],[deken_cpu=${host_cpu}],
    [powerpc64],[deken_cpu=ppc64],
    [powerpc],[deken_cpu=ppc],
    [])


AM_CONDITIONAL(ANDROID, test x$ANDROID = xyes)
AM_CONDITIONAL(IPHONEOS, test x$IPHONEOS = xyes)
AM_CONDITIONAL(LINUX, test x$LINUX = xyes)
AM_CONDITIONAL(HURD, test x$HURD = xyes)
AM_CONDITIONAL(MACOSX, test x$MACOSX = xyes)
AM_CONDITIONAL(WINDOWS, test x$WINDOWS = xyes)
AM_CONDITIONAL(CYGWIN, test x$CYGWIN = xyes)
AM_CONDITIONAL(MINGW, test x$MINGW = xyes)
AM_CONDITIONAL(BSD, test x$BSD = xyes)

#########################################
##### Check for programs, libs, & headers #####

# Configure libtool.
AC_LIBTOOL_DLOPEN
AC_LIBTOOL_WIN32_DLL
AC_PROG_LIBTOOL

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_PROG_LN_S
AC_PROG_MKDIR_P
AC_PROG_GREP
AC_PROG_SED
AC_CHECK_TOOL([WINDRES], [windres], [:])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h \
                  limits.h \
                  malloc.h \
                  netdb.h \
                  netinet/in.h \
                  stddef.h \
                  stdlib.h \
                  string.h \
                  sys/ioctl.h \
                  sys/param.h \
                  sys/socket.h \
                  sys/time.h \
                  sys/timeb.h \
                  sys/utsname.h \
                  sys/filio.h \
                  unistd.h
                  ])

AC_CHECK_HEADERS([endian.h machine/endian.h])


# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T


AC_CHECK_TYPE(off64_t, [AC_DEFINE([HAVE_OFF64_T], 1, [Define if we have the 'off64_t' type])], [], [[
#define _LARGEFILE64_SOURCE
#include <sys/types.h>
#include <unistd.h>
]])
AC_CHECK_TYPE(sig_t, [], [AC_DEFINE([DONT_HAVE_SIG_T], 1, [Define if we do NOT have the 'sig_t' type])], [[
#include <signal.h>
]])

# Checks for functions.
AC_FUNC_ALLOCA
AC_FUNC_ERROR_AT_LINE
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([dup2 \
                floor \
                getcwd \
                gethostbyname \
                gettimeofday \
                memmove \
                memset \
                pow \
                regcomp \
                select \
                socket \
                sqrt \
                strchr \
                strerror \
                strrchr \
                strstr \
                strtol
                ])

dnl qsort_r: do we have it, and if so, which variant?
AC_CHECK_FUNCS_ONCE([qsort_r], [], [AC_DEFINE([STUPID_SORT], 1)])
if test $ac_cv_func_qsort_r = yes; then
  AC_CACHE_CHECK([for qsort_r signature], [ac_cv_libctf_qsort_r_signature],
    [AC_LINK_IFELSE(
       [AC_LANG_PROGRAM([[#undef qsort_r
                          #include <stdlib.h>
                          void qsort_r (void *, size_t, size_t,
                                        int (*) (void const *, void const *,
                                                 void *),
                                        void *);
                          void (*p) (void *, size_t, size_t,
                                     int (*) (void const *, void const *,
                                              void *),
                                     void *) = qsort_r;
                        ]])],
       [ac_cv_libctf_qsort_r_signature=GNU],
       [AC_LINK_IFELSE(
          [AC_LANG_PROGRAM([[#undef qsort_r
	                     #include <stdlib.h>
                             void qsort_r (void *, size_t, size_t, void *,
                                           int (*) (void *,
                                                    void const *,
                                                    void const *));
                             void (*p) (void *, size_t, size_t, void *,
                                        int (*) (void *, void const *,
                                                 void const *)) = qsort_r;
                           ]])],
          [ac_cv_libctf_qsort_r_signature=BSD],
          [ac_cv_libctf_qsort_r_signature=unknown])])])
fi

case x$ac_cv_libctf_qsort_r_signature in
  xGNU)     AC_DEFINE([HAVE_QSORT_R_ARG_LAST], 1,
	     [Whether a qsort_r exists with a void *arg as its last arg.]);;
  xBSD)     AC_DEFINE([HAVE_QSORT_R_COMPAR_LAST], 1,
	     [Whether a qsort_r exists with the compar function as its last arg.]);;
  *)        AC_DEFINE([STUPID_SORT], 1);;
esac

# Checks for libraries.
have_dl=yes
AC_SEARCH_LIBS([dlopen], [dl dld], [], [have_dl=no])
AS_IF([test "x${have_dl}" = "xyes"], AC_DEFINE([HAVE_DLOPEN], 1))

AC_CHECK_LIBM
# AC_CHECK_LIBM computes LIBM but does not add to LIBS, hence we add it in
# src/Makefile.am under pd_LDFLAGS as well

# Checking for `pthread_create' function in libpthread (MinGW uses unusual names)
## CHECK whether this can be replaced by AX_PTHREAD
AC_SEARCH_LIBS([pthread_create], [pthread pthreadGC2 pthreadGC1 pthreadGC], [],
               AC_MSG_WARN([pthreads required]))

# Illumos needs to link against libsocket for 'sendto' and friends
AC_SEARCH_LIBS([sendto], [socket])

# Define variables for use in Makefiles
AC_SUBST(EXTERNTARGET)
AC_SUBST(EXTERNAL_EXTENSION)
AC_SUBST(EXTERNAL_CFLAGS)
AC_SUBST(EXTERNAL_LDFLAGS)
AC_SUBST([OSS_LIBS])
AC_SUBST([ALSA_LIBS])
AC_SUBST([JACK_CFLAGS])
AC_SUBST([JACK_LIBS])

# Whether to strip symbol from binaries (msw_strip="") or not (msw_strip="-n") on windows. Used in msw/Makefile
AC_SUBST([msw_strip])

# pass include paths down to all Makefiles
AC_SUBST([AM_CPPFLAGS], [$AM_CPPFLAGS])

##### Build with debug flags? #####
AC_ARG_ENABLE([debug],
    [AS_HELP_STRING([--enable-debug], [use debugging support])],
    [debug=$enableval], [debug=no])
AS_IF([test x$debug = xyes],[
    PD_CFLAGS="$DEBUG_CFLAGS $PD_CFLAGS"
],[
    PD_CFLAGS="$RELEASE_CFLAGS $PD_CFLAGS"
    PD_CPPFLAGS="-DNDEBUG $PD_CPPFLAGS"
])

AS_IF([test "x${debug}" = "xyes" -a "x${WINDOWS}" = "xyes" ],[
    msw_strip="-n"
    ],[
    msw_strip=""
    ])

##### macOS version min #####
AS_IF([test "x$macos_version_min" != "x"],[
    PD_CFLAGS="-mmacosx-version-min=$macos_version_min $PD_CFLAGS"
])

#########################################
##### Configure Options #####


##### realtime watchdog #####
AC_ARG_ENABLE([watchdog],
    [AS_HELP_STRING([--enable-watchdog], [additionally build watchdog])],,enable_watchdog="$watchdog")
AS_IF([test "x$enable_watchdog" != "xyes"],[enable_watchdog=no])
AM_CONDITIONAL(PD_WATCHDOG, test x$enable_watchdog = xyes)

###### floatsize ########
AC_ARG_WITH([floatsize],
    [AS_HELP_STRING([--with-floatsize=<SIZE>],
    [build binaries for the given floatsize;
    SIZE can be 32 (single precision) or 64 (double precision)
    ]
    )],
    [floatsize=${withval}]
    )
AC_MSG_CHECKING([float size])
AS_CASE([${floatsize}],
    [32],[],
    [64],[],
    [""],[],
    [
        AC_MSG_WARN([${floatsize}bit floats not supported...use fallback])
        floatsize=""
    ])
AS_IF([test "x${floatsize}" != "x" ],
   [
    PD_CPPFLAGS="-DPD_FLOATSIZE=${floatsize} $PD_CPPFLAGS"
    AC_MSG_RESULT([${floatsize}])
   ],[AC_MSG_RESULT([default])
   ])

AS_IF([test "x${floatsize}" = "x64" && test "x${deken_cpu}" != "x" && test "x${deken_os}" != "x" && test "x${deken_ext}" != "x"],[
      EXTERNAL_EXTENSION="${deken_os}-${deken_cpu}-${floatsize}.${deken_ext}"
      AC_MSG_NOTICE([default external extension...${EXTERNAL_EXTENSION}])
      ])

pd_transform_name=$(echo ${program_transform_name} | sed -e 's|\$\$|$|')
pd_transformed=$(echo pd | sed -e "${pd_transform_name}")

AS_CASE([${floatsize}],
    [""],[],
    [32],[],
    [
      # if we specify a non-standard floatsize, make sure that the the program is also transformed.
      # this is especially important on Windows (where we link against a pd.dll variant)
      AS_IF([test "${pd_transformed}" = "pd" && test "${have_program_transform_name}" = "no"],[
        program_transform_name="s/pd\$\$/pd${floatsize}/"
        pd_transform_name=$(echo ${program_transform_name} | sed -e 's|\$\$|$|')
        pd_transformed=$(echo pd | sed -e "${pd_transform_name}")
      ])])

# on Windows, we need to link against a (floatsize-decorated) pd.dll
AS_IF([test "x${WINDOWS}" = "xyes" ],[
   EXTERNAL_LDFLAGS="${EXTERNAL_LDFLAGS} -l${pd_transformed}"
])

##### libpd #####
AC_ARG_ENABLE([libpd],
    [AS_HELP_STRING([--enable-libpd], [additionally build libpd])])
AC_ARG_ENABLE([libpd-utils],
    [AS_HELP_STRING([--enable-libpd-utils], [enable utilities if building libpd])])
AC_ARG_ENABLE([libpd-instance],
    [AS_HELP_STRING([--enable-libpd-instance], [enable multi-instance support for libpd])])
AC_ARG_ENABLE([libpd-extra],
    [AS_HELP_STRING([--enable-libpd-extra], [include extra objects (sigmund~,pd~,...) in libpd])])
AC_ARG_ENABLE([libpd-setlocale],
    [AS_HELP_STRING([--disable-libpd-setlocale], [prevent libpd from calling setlocale() - if you need to control LC_NUMERIC manually ])])

AM_CONDITIONAL(LIBPD, test x$enable_libpd = xyes)
AM_CONDITIONAL(LIBPD_UTILS, test x$enable_libpd_utils = xyes)
AM_CONDITIONAL(LIBPD_EXTRA, test x$enable_libpd_extra = xyes)
AM_CONDITIONAL(LIBPD_MULTIINSTANCE, test x$enable_libpd_instance = xyes)
AM_CONDITIONAL(LIBPD_NO_SETLOCALE, test x$enable_libpd_setlocale = xno)

##### Universal/multi architecture build on macOS #####
PD_CHECK_UNIVERSAL(ARCH, [universal=yes], [universal=no])
AM_CONDITIONAL(UNIVERSAL, test x$universal = xyes)
AS_IF([test x$universal = xyes],[
    PD_CFLAGS="$ARCH_CFLAGS $PD_CFLAGS"
    PD_LDFLAGS="$ARCH_LDFLAGS $PD_LDFLAGS"
])

##### Gettext #####
# Gettext is needed to build language localizations.
AC_ARG_ENABLE([locales],
    [AS_HELP_STRING([--disable-locales],
        [do not compile localizations (requires gettext)])],
    [locales=$enableval])
AS_IF([test x$locales = xyes],[
    AC_CHECK_PROG(HAVE_MSGFMT, [msgfmt], yes, no)
    AS_IF([test x$HAVE_MSGFMT = xno],[
        AC_MSG_WARN([Install GNU gettext with msgfmt if you want localizations to be compiled!])
        locales=no
    ])
])
AM_CONDITIONAL(MSGFMT, test x$HAVE_MSGFMT = xyes)

##### OSS #####
# Cygwin has sys/soundcard.h but Pd isn't ready for Cygwin since it only
# includes OSS for UNIX
AC_ARG_ENABLE([oss],
    [AS_HELP_STRING([--disable-oss], [do not use OSS driver])],
    [oss=$enableval], [oss=yes])
AS_IF([test x$oss = xyes],[
    oss=no
    AC_CHECK_HEADERS([sys/soundcard.h soundcard.h], [oss=yes; break])
    AC_CHECK_LIB([ossaudio], [_oss_ioctl], [OSS_LIBS="-lossaudio"])
])

##### ALSA #####
# shouldn't we use AM_PATH_ALSA from /usr/share/aclocal/alsa.m4
# alternatively we could use pkg-config
AC_ARG_ENABLE([alsa],
    [AS_HELP_STRING([--disable-alsa], [do not use ALSA audio driver])],
    [alsa=$enableval], [alsa=yes])
AS_IF([test x$alsa = xyes],[
    AC_CHECK_LIB([asound], [snd_pcm_info], [ALSA_LIBS="-lasound"], [alsa=no])
])

##### JACK FRAMEWORK #####
# on macOS, use the JackOSX.com Jackmp.framework not the jack lib by default
# this is set in src/Makefile.am based on the JACK & JACK_FRAMEWORK vars
AC_ARG_ENABLE([jack-framework],
    [AS_HELP_STRING([--disable-jack-framework],
        [do not weak link to Jackmp.framework on macOS])],
    [jack_framework=$enableval])
test x$MACOSX = xyes || jack_framework=no
AS_IF([test x$jack_framework = xyes],[
    AC_MSG_NOTICE([Weak linking to Jackmp.framework])
])

##### JACK #####
AC_ARG_ENABLE([jack],
    [AS_HELP_STRING([--enable-jack], [use JACK audio server])],
    [jack=$enableval], [jack=no])
AS_IF([test x$jack_framework != xyes -a x$jack = xyes],[
    AS_IF([pkg-config --exists jack],[
        AC_MSG_NOTICE([Using JACK as specified by pkg-config])
        JACK_CFLAGS=$(pkg-config --cflags jack)
        JACK_LIBS=$(pkg-config --libs jack)
        jack=yes
        ],[
        AC_CHECK_LIB([rt], [shm_open], [LIBS="$LIBS -lrt"])
        AC_CHECK_LIB([jack], [jack_set_xrun_callback], [JACK_LIBS="-ljack" ; jack=xrun])
        AC_CHECK_LIB([jack], [jack_set_error_function], [JACK_LIBS="-ljack" ; jack=yes],
            [AC_MSG_WARN([JACK development files not found... skipping (See INSTALL.txt)])
            jack=no])
        ])
])

##### MMIO #####
AC_ARG_ENABLE([mmio],
    [AS_HELP_STRING([--disable-mmio], [do not use MMIO driver])],
    [mmio=$enableval])
test x$WINDOWS = xyes || mmio=no

##### ASIO #####
AC_ARG_ENABLE([asio],
    [AS_HELP_STRING([--enable-asio], [use ASIO audio driver])],
    [asio=$enableval])
test x$WINDOWS = xyes || asio=no
AS_IF([test x$asio = xyes],
    test -f "${srcdir}"/asio/ASIOSDK/common/asio.h || asio=no
    AS_IF([test x$asio = xno],
        AC_MSG_WARN([ASIO SDK not found... skipping (See asio/README.txt)]))
)

#### WASAPI ####
AC_ARG_ENABLE([wasapi],
    [AS_HELP_STRING([--disable-wasapi], [do not use WASAPI backend])],
    [wasapi=$enableval])
test x$WINDOWS = xyes || wasapi=no

##### Apple's CoreAudio #####
# not used directly, implicitly needed when using PortAudio on OSX
AC_CHECK_HEADER(CoreAudio/CoreAudio.h, [coreaudio=yes], [coreaudio=no])

##### PortAudio #####
AC_ARG_ENABLE([portaudio],
    [AS_HELP_STRING([--disable-portaudio], [do not use portaudio])],
    [portaudio=$enableval])
AC_ARG_WITH([local-portaudio],
    [AS_HELP_STRING([--without-local-portaudio],
        [do not use the portaudio included with Pd])],
    [local_portaudio=$withval])
AS_IF([test x$portaudio = xyes],[
    AS_IF([test x$local_portaudio = xno],[
        # fall back to local portaudio if not foud
        AC_CHECK_LIB([portaudio], [Pa_Initialize],
            [AC_MSG_NOTICE([Using system PortAudio])], [local_portaudio=yes])
    ])
    AS_IF([test x$local_portaudio = xyes],[
        AS_IF([test -d "$srcdir/portaudio"],[
            AC_MSG_NOTICE([Using included PortAudio])
        ],[
            AC_MSG_WARN([PortAudio not found in Pd source directory])
            portaudio=no
        ])
    ])
],[local_portaudio=no])

##### PortMidi #####
AC_ARG_ENABLE([portmidi],
    [AS_HELP_STRING([--enable-portmidi], [use portmidi])],
    [portmidi=$enableval])
AC_ARG_WITH([local-portmidi],
    [AS_HELP_STRING([--without-local-portmidi],
        [do not use the portmidi included with Pd])],
    [local_portmidi=$withval])
# don't allow portmidi if already using oss
AS_IF([test x$oss = xyes -a x$portmidi != xno],
  [AC_MSG_WARN([Cannot enable both OSS-midi and PortMidi... preferring OSS])
  portmidi=no])
AS_IF([test x$portmidi = xyes],[
    AS_IF([test x$local_portmidi = xno],[
        # fall back to local portmidi if not foud
        AC_CHECK_LIB([portmidi], [Pm_Initialize],
            [AC_MSG_NOTICE([Using system PortMidi])], [local_portmidi=yes])
    ])
    AS_IF([test x$local_portmidi = xyes],[
        AS_IF([test -d "$srcdir/portmidi"],[
            AC_MSG_NOTICE([Using included PortMidi])
        ],[
            AC_MSG_WARN([PortMidi not found in Pd source directory])
            portmidi=no
        ])
    ])
],[local_portmidi=no])

##### fftw v3 #####
AC_ARG_ENABLE([fftw],
    [AS_HELP_STRING([--enable-fftw], [use FFTW package])],
    [fftw=$enableval], [fftw=no])
AS_IF([test x$fftw = xyes],[
    AC_CHECK_LIB([fftw3f], [fftwf_execute],
        [LIBS="$LIBS -lfftw3f"],
        [AC_MSG_WARN([FFTW development files not found... using built-in FFT])
        fftw=no])
])
AM_CONDITIONAL(FFTW, test x$fftw = xyes)

##### Wish #####
AC_ARG_WITH([wish],
    [AS_HELP_STRING([--with-wish=WISH],
        [which Tk Wish application to use for the Pd GUI])],
    [WISH=$withval])
AS_IF([test "x${WISH}" = "xyes" -o "x${WISH}" = "xno"],
    [AC_MSG_NOTICE([--with-wish requires an application, ignoring '${WISH}'])
    WISH=""])
AC_SUBST([WISH])

##### Deken OS and CPU #####
AC_ARG_WITH([deken-os],
    [AS_HELP_STRING([--with-deken-os=<OS>],
        [Operating System string to use for externals (e.g. Linux, Windows, Darwin,...)])],
    [DEKEN_OS=$withval])
AS_IF([test "x${DEKEN_OS}" = "xyes" -o "x${DEKEN_OS}" = "xno"],
    [AC_MSG_NOTICE([--with-deken-os requires an Operating System, ignoring '${DEKEN_OS}'])
    DEKEN_OS=""])
AC_SUBST([DEKEN_OS])
AS_IF([test "x${DEKEN_OS}" != "x"], [deken_os="${DEKEN_OS}"])

AC_ARG_WITH([deken-cpu],
    [AS_HELP_STRING([--with-deken-cpu=<CPU>],
        [CPU architecture string to use for externals (e.g. amd64, i386, arm64,...)])],
    [DEKEN_CPU=$withval])
AS_IF([test "x${DEKEN_CPU}" = "xyes" -o "x${DEKEN_CPU}" = "xno"],
    [AC_MSG_NOTICE([--with-deken-cpu requires a CPU, ignoring '${DEKEN_CPU}'])
    DEKEN_CPU=""])
AC_SUBST([DEKEN_CPU])
AS_IF([test "x${DEKEN_CPU}" != "x"], [deken_cpu="${DEKEN_CPU}"])

AC_ARG_WITH([external-extension],
    [AS_HELP_STRING([--with-external-extension=<EXT>],
        [Extension to use for externals in extra/ (e.g. pd_linux, dll, d_fat,...)])],
    [ext="${withval#.}"])
AS_IF([test "x${ext}" = "xyes" -o "x${ext}" = "xno"],
    [AC_MSG_NOTICE([--with-external-extension requires an extension, ignoring '${ext}'])
    ext=""])
AS_IF([test "x${ext}" != "x"], [EXTERNAL_EXTENSION="${ext}"])



##### Configure Build From Options #####
## configure the build based on what we have found above

##### OSS #####
# Cygwin has a function OSS /dev/dsp, but not MIDI,
# and Pd is only set up to handle a single MIDI API
AS_IF([test x$WINDOW = xyes -a x$oss != xno],
  [AC_MSG_WARN([OSS not working on W32... disabling]) ; oss=no])
AM_CONDITIONAL(OSS, test x$oss = xyes)
AS_IF([test x$oss = xyes], [audio_backends="OSS ${audio_backends}"])
AS_IF([test x$oss = xyes], [midi_backends="OSS ${midi_backends}"])

##### ALSA #####
AM_CONDITIONAL(ALSA, test x$alsa = xyes)
AS_IF([test x$alsa = xyes], [audio_backends="ALSA ${audio_backends}"])
AS_IF([test x$alsa = xyes], [midi_backends="ALSA ${midi_backends}"])

##### JACK #####
AM_CONDITIONAL(JACK, test x$jack = xyes)
AM_CONDITIONAL(JACK_FRAMEWORK, test x$jack_framework = xyes)
AS_IF([test x$jack = xyes], [audio_backends="JACK ${audio_backends}"])

##### MMIO #####
AM_CONDITIONAL(MMIO, test x$mmio = xyes)
AS_IF([test x$mmio = xyes], [audio_backends="MMIO ${audio_backends}"])
dnl AS_IF([test x$mmio = xyes], [midi_backends="MMIO ${midi_backends}"])

##### ASIO #####
AM_CONDITIONAL(ASIO, test x$asio = xyes)
AS_IF([test x$asio = xyes], [audio_backends="ASIO ${audio_backends}"])

##### WASAPI #####
AM_CONDITIONAL(WASAPI, test x$wasapi = xyes)
AS_IF([test x$wasapi = xyes], [audio_backends="WASAPI ${audio_backends}"])

##### CoreAudio #####
# portaudio doesn't work with iOS, so don't bother with CoreAudio
AS_IF([test x$IPHONEOS = xyes -a x$coreaudio != xno],
  [AC_MSG_WARN([PortAudio not working on iOS... disabling CoreAudio])
  coreaudio=no])
AM_CONDITIONAL(COREAUDIO, test x$coreaudio = xyes)

##### PortAudio #####
AM_CONDITIONAL(PORTAUDIO, test x$portaudio = xyes)
AM_CONDITIONAL(LOCAL_PORTAUDIO, test x$local_portaudio = xyes)
AS_IF([test x$portaudio = xyes], [audio_backends="PortAudio ${audio_backends}"])

##### PortMidi #####
AM_CONDITIONAL(PORTMIDI, test x$portmidi = xyes)
AM_CONDITIONAL(LOCAL_PORTMIDI, test x$local_portmidi = xyes)
AS_IF([test x$portmidi = xyes], [midi_backends="PortMidi ${midi_backends}"])

##### DUMMY #####
# warn if we end up trying to build without an audio or midi api
AM_CONDITIONAL(AUDIO_DUMMY, test "x$audio_backends" = "x")
AS_IF([test "x$audio_backends" = "x"],[
    AC_MSG_WARN([No audio API specified or detected])
    audio_backends="NONE!"
])
# we need the dummy MIDI backend, if there is no other backend providing the
# standard MIDI-functions (OSS and PortMidi provide them; ALSA not)
needs_midi_dummy="yes"
AS_IF([echo "${midi_backends}" | grep -wi OSS >/dev/null],[needs_midi_dummy="no"])
AS_IF([echo "${midi_backends}" | grep -wi PortMidi >/dev/null],[needs_midi_dummy="no"])

AM_CONDITIONAL(MIDI_DUMMY, test "x${needs_midi_dummy}" = "xyes")
AS_IF([test "x$midi_backends" = "x"],[
    AC_MSG_WARN([No MIDI API specified or detected])
    midi_backends="NONE!"
])

##### Wish #####
# add contextual info when adding a custom WISH path on macOS,
# other platforms use a single path so it's enough to print $wish as it is
AS_IF([test ! "x${WISH}" = "x"],[
    AS_IF([test x"$MACOSX" = x"yes"], [
        wish="prepending ${WISH} to search paths"
    ],[
        wish="${WISH}"
    ])
])

##### libpd #####
AS_IF([test "x${enable_libpd}" = "xyes"],[
    libpd="yes"
    libpd_=""
    AS_IF([test "x${enable_libpd_instance}" = "xyes"],[ libpd_="${libpd_}+multi "])
    AS_IF([test "x${enable_libpd_utils}" = "xyes"],[ libpd_="${libpd_}+utils "])
    AS_IF([test "x${enable_libpd_extra}" = "xyes"],[ libpd_="${libpd_}+extra "])
    AS_IF([test "x${enable_libpd_setlocale}" = "xno"],[ libpd_="${libpd_}-setlocale "])
    AS_IF([test "x${libpd_}" != "x"],[ libpd="${libpd} ( ${libpd_})"])
],[
    libpd="no"
])

# pass common flags via @PD_*@ AM variables for use in Makefiles
AC_SUBST(PD_CPPFLAGS)
AC_SUBST(PD_CFLAGS)
AC_SUBST(PD_LDFLAGS)

#########################################
##### Output files #####

# Specify what files are to be created.
AC_CONFIG_FILES([Makefile
                asio/Makefile
                doc/Makefile
                font/Makefile
                linux/Makefile
                mac/Makefile
                man/Makefile
                msw/Makefile
                portaudio/Makefile
                portmidi/Makefile
                tcl/Makefile
                tcl/pd-gui
                po/Makefile
                src/Makefile
                extra/Makefile
                extra/bob~/GNUmakefile
                extra/bonk~/GNUmakefile
                extra/choice/GNUmakefile
                extra/fiddle~/GNUmakefile
                extra/loop~/GNUmakefile
                extra/lrshift~/GNUmakefile
                extra/pd~/GNUmakefile
                extra/pique/GNUmakefile
                extra/sigmund~/GNUmakefile
                extra/stdout/GNUmakefile
                pd.pc
                ])
AC_OUTPUT

#########################################
##### Print a summary for the user #####

AC_MSG_NOTICE([

    ${PACKAGE} ${VERSION} is now configured

    Platform:             ${platform}
    Float size:           ${floatsize:-default}
    Debug build:          ${debug}
    Universal build:      ${universal}
    Localizations:        ${locales}
    Source directory:     ${srcdir}
    Installation prefix:  ${prefix}

    Compiler:             ${CC}
    CPPFLAGS:             ${PD_CPPFLAGS} ${CPPFLAGS}
    CFLAGS:               ${PD_CFLAGS} ${CFLAGS}
    LDFLAGS:              ${PD_LDFLAGS} ${LDFLAGS}
    INCLUDES:             ${AM_CPPFLAGS}
    LIBS:                 ${LIBS}

    External extension:   ${EXTERNAL_EXTENSION}
    External CFLAGS:      ${EXTERNAL_CFLAGS}
    External LDFLAGS:     ${EXTERNAL_LDFLAGS}
    Deken identifier:     ${deken_os:-???}-${deken_cpu:-???}

    fftw:                 ${fftw}
    wish(tcl/tk):         ${wish}
    watchdog:             ${enable_watchdog}
    audio APIs:           ${audio_backends}
    midi APIs:            ${midi_backends}
    libpd:                ${libpd}
])

AS_IF([test "x${enable_locales}" = xyes -a "x${locales}" = xno ],
 AC_MSG_WARN([localization requested but no GNU gettext with msgfmt found... disabled]))
AS_IF([test "x${enable_oss}" = xyes -a "x${oss}" = xno ],
 AC_MSG_WARN([OSS requested but no development files found... disabled]))
AS_IF([test "x${enable_alsa}" = xyes -a "x${alsa}" = xno ],
 AC_MSG_WARN([ALSA requested but no development files found... disabled (See INSTALL.txt)]))
AS_IF([test "x${enable_jack}" = xyes -a "x${jack}" = xno ],
 AC_MSG_WARN([JACK requested but no development files found... disabled (See INSTALL.txt)]))
AS_IF([test "x${enable_jack_framework}" = xyes -a "x${jack_jack}" != xyes ],
 AC_MSG_WARN([JACK-Framework requested but no development files found... disabled (See INSTALL.txt)]))
AS_IF([test "x${enable_mmio}" = xyes -a "x${mmio}" = xno ],
 AC_MSG_WARN([MMIO requested but not available... disabled (requires Windows)]))
AS_IF([test "x${enable_asio}" = xyes -a "x${asio}" = xno ],
 AC_MSG_WARN([ASIO requested but no SDK found... disabled (see asio/README.txt)]))

# TODO portaudio

AS_IF([test "x${enable_fftw}" = xyes -a "x${fftw}" = xno ],
 AC_MSG_WARN([FFTW requested but no development files found... disabled]))

AS_CASE([${floatsize}],
    [""],[],
    [32],[],
    [
      AS_IF([test "${pd_transformed}" = "pd"],[
        AC_MSG_WARN([Using a non-standard floatsize without name-mangling.
        You should use something like "--program-suffix=${floatsize}"?
        ])
      ])])
