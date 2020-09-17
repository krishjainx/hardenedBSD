# $FreeBSD$

PACKAGE=	iscsi
PROG=		iscsid
SRCS=		chap.c discovery.c iscsid.c keys.c log.c login.c pdu.c
CFLAGS+=	-I${.CURDIR}
CFLAGS+=	-I${SRCTOP}/sys/cam
CFLAGS+=	-I${SRCTOP}/sys/dev/iscsi
CFLAGS+=	-DICL_KERNEL_PROXY
MAN=		iscsid.8

LIBADD=		md util

<<<<<<< HEAD

WARNS=		6
=======
WARNS?=		6
>>>>>>> origin/freebsd/12-stable/master

.include <bsd.prog.mk>
