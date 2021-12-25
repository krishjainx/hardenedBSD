# $FreeBSD$

.include <src.opts.mk>

ELFTCDIR=	${SRCTOP}/contrib/elftoolchain
NMDIR=		${ELFTCDIR}/nm

.PATH: ${NMDIR}

PROG=	elftc-nm
SRCS=	nm.c
MAN=	nm.1

LIBADD=	dwarf elftc elf

CFLAGS+=-I${ELFTCDIR}/libelftc -I${ELFTCDIR}/common

.if ${MK_LLVM_BINUTILS} == "no"
SYMLINKS=	${BINDIR}/elftc-nm ${BINDIR}/nm
.endif

.include <bsd.prog.mk>
