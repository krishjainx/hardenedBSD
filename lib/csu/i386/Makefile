# $FreeBSD$

.include <bsd.init.mk>

.PATH: ${.CURDIR:H}/common

CFLAGS+=	-I${.CURDIR}
CFLAGS+=	-DCRT_IRELOC_REL

MK_CROSS_DSO_CFI=	no

CRT1OBJS+=	crt1_s.o

.include <bsd.lib.mk>
