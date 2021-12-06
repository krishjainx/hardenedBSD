# $FreeBSD$

.include <src.opts.mk>

PROG_CXX=	llvm-objdump

SRCDIR=		llvm/tools/llvm-objdump
SRCS+=		COFFDump.cpp
SRCS+=		ELFDump.cpp
SRCS+=		MachODump.cpp
SRCS+=		WasmDump.cpp
SRCS+=		XCOFFDump.cpp
SRCS+=		llvm-objdump.cpp

LIBADD+=	z

<<<<<<< HEAD
.if ${MK_LLVM_OBJDUMP_IS_OBJDUMP} != "no"
SYMLINKS=	${BINDIR}/llvm-objdump \
    ${BINDIR}/objdump
=======
.if ${MK_LLVM_BINUTILS} != "no"
LINKS=		${BINDIR}/llvm-objdump ${BINDIR}/objdump
MLINKS=		llvm-objdump.1 objdump.1
>>>>>>> origin/freebsd/13-stable/main
.endif

.include "../llvm.prog.mk"
