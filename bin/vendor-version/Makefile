# $FreeBSD$

PACKAGE=runtime
SCRIPTS= vendor-version
MAN=
CLEANFILES = vendor-version vendor-version.sh
NEWVERS = ${SRCTOP}/sys/conf/newvers.sh

vendor-version.sh: ${.CURDIR}/vendor-version.sh.in
	eval $$(sh ${NEWVERS} -v); \
	if ! sed -e "\
			s/@@TYPE@@/$${TYPE}/g; \
			s/@@REVISION@@/$${REVISION}/g; \
			s/@@BRANCH@@/$${BRANCH}/g; \
			s/@@VENDOR_VERSION@@/$${VENDOR_VERSION}/g; \
		" ${.CURDIR}/vendor-version.sh.in >${.TARGET} ; then \
		rm -f ${.TARGET} ; \
		exit 1 ; \
	fi

.include <bsd.prog.mk>
