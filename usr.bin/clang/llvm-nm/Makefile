# $FreeBSD$

.include <src.opts.mk>

PROG_CXX=	llvm-nm

SRCDIR=		llvm/tools/llvm-nm
SRCS+=		llvm-nm.cpp

LIBADD+=	z

<<<<<<< HEAD
.if ${MK_LLVM_NM_IS_NM} != "no"
SYMLINKS=	${BINDIR}/llvm-nm ${BINDIR}/nm
=======
.if ${MK_LLVM_BINUTILS} != "no"
LINKS=		${BINDIR}/llvm-nm ${BINDIR}/nm
MLINKS=		llvm-nm.1 nm.1
>>>>>>> origin/freebsd/13-stable/main
.endif

.include "../llvm.prog.mk"
