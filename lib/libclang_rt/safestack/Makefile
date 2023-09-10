# $FreeBSD$

.include <bsd.init.mk>

NOCFI=		yes

LIB=		clang_rt.safestack-${CRTARCH}

SRCS+=		interception/interception_linux.cc
SRCS+=		interception/interception_type_test.cc
SRCS+=		safestack/safestack.cc

.include <bsd.lib.mk>
