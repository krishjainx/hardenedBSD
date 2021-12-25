# $FreeBSD$

.include <src.opts.mk>

PROG_CXX=	llvm-ar
MAN=		llvm-ar.1 llvm-ranlib.1

SRCDIR=		llvm/tools/llvm-ar
SRCS+=		llvm-ar.cpp

LIBADD+=	z

LINKS+=		${BINDIR}/llvm-ar ${BINDIR}/llvm-ranlib

<<<<<<< HEAD
.if ${MK_LLVM_AR_IS_AR} != "no"
SYMLINKS=	${BINDIR}/llvm-ar ${BINDIR}/ar \
    ${BINDIR}/llvm-ar ${BINDIR}/ranlib
=======
.if ${MK_LLVM_BINUTILS} != "no"
LINKS=		${BINDIR}/llvm-ar ${BINDIR}/ar ${BINDIR}/llvm-ar ${BINDIR}/ranlib
MLINKS=		llvm-ar.1 ar.1 llvm-ar.1 ranlib.1
>>>>>>> origin/freebsd/12-stable/main
.endif

.include "../llvm.prog.mk"
