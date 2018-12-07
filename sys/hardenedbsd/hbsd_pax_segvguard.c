/*-
 * Copyright (c) 2006 Elad Efrat <elad@NetBSD.org>
 * Copyright (c) 2013-2017, by Oliver Pinter <oliver.pinter@hardenedbsd.org>
 * Copyright (c) 2014, by Shawn Webb <shawn.webb@hardenedbsd.org>
 * Copyright (c) 2014, by Danilo Egea Gondolfo <danilo at FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_pax.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/kernel.h>
#include <sys/fnv_hash.h>
#include <sys/imgact.h>
#include <sys/imgact_elf.h>
#include <sys/jail.h>
#include <sys/libkern.h>
#include <sys/mount.h>
#include <sys/pax.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/sysent.h>
#include <sys/vnode.h>
#include <sys/types.h>

#include "hbsd_pax_internal.h"

#define PAX_SEGVGUARD_EXPIRY		(2 * 60)
#define PAX_SEGVGUARD_SUSPENSION	(10 * 60)
#define PAX_SEGVGUARD_MAXCRASHES	5

FEATURE(hbsd_segvguard, "Segmentation fault protection.");

#ifdef PAX_HARDENING
static int pax_segvguard_status = PAX_FEATURE_OPTOUT;
#else
static int pax_segvguard_status = PAX_FEATURE_OPTIN;
#endif
static int pax_segvguard_expiry = PAX_SEGVGUARD_EXPIRY;
static int pax_segvguard_suspension = PAX_SEGVGUARD_SUSPENSION;
static int pax_segvguard_maxcrashes = PAX_SEGVGUARD_MAXCRASHES;


struct pax_segvguard_entry {
	uid_t se_uid;
	ino_t se_inode;
	char se_mntpoint[MNAMELEN];
	size_t se_ncrashes;
	struct callout se_callout;
	LIST_ENTRY(pax_segvguard_entry) se_entry;
};

struct pax_segvguard_entryhead {
	struct pax_segvguard_entry *lh_first;
	struct mtx bucket_mtx;
};

static struct pax_segvguard_entryhead *pax_segvguard_hashtbl;
static int pax_segvguard_hashsize = 512;

#define PAX_SEGVGUARD_LOCK_INIT(bucket)							\
	mtx_init(&(bucket)->bucket_mtx, "segvguard mutex", NULL, MTX_DEF)

#define PAX_SEGVGUARD_HASH(se) ({							\
	uint32_t _hash;									\
	_hash = fnv_32_buf(&(se)->se_inode, sizeof((se)->se_inode), FNV1_32_INIT);	\
	_hash = fnv_32_buf((se)->se_mntpoint, strnlen((se)->se_mntpoint,		\
		MNAMELEN), _hash);	\
	_hash = fnv_32_buf(&(se)->se_uid, sizeof((se)->se_uid), _hash);			\
	_hash % pax_segvguard_hashsize; })						\

#define PAX_SEGVGUARD_BUCKET(se)							\
	(&pax_segvguard_hashtbl[PAX_SEGVGUARD_HASH(se)])

#define PAX_SEGVGUARD_LOCK(se)	 							\
	mtx_lock(&PAX_SEGVGUARD_BUCKET(se)->bucket_mtx)

#define PAX_SEGVGUARD_UNLOCK(se)	 						\
	mtx_unlock(&PAX_SEGVGUARD_BUCKET(se)->bucket_mtx)

MALLOC_DECLARE(M_PAX);
MALLOC_DEFINE(M_PAX, "pax_segvguard", "PaX segvguard memory");

TUNABLE_INT("hardening.pax.segvguard.status", &pax_segvguard_status);
TUNABLE_INT("hardening.pax.segvguard.expiry_timeout", &pax_segvguard_expiry);
TUNABLE_INT("hardening.pax.segvguard.suspend_timeout", &pax_segvguard_suspension);
TUNABLE_INT("hardening.pax.segvguard.max_crashes", &pax_segvguard_maxcrashes);

#ifdef PAX_SYSCTLS
static int sysctl_pax_segvguard_expiry(SYSCTL_HANDLER_ARGS);
static int sysctl_pax_segvguard_suspension(SYSCTL_HANDLER_ARGS);
static int sysctl_pax_segvguard_maxcrashes(SYSCTL_HANDLER_ARGS);

SYSCTL_DECL(_hardening_pax);
SYSCTL_NODE(_hardening_pax, OID_AUTO, segvguard, CTLFLAG_RD, 0, "PaX segvguard");

SYSCTL_HBSD_4STATE(pax_segvguard_status, pr_hbsd.segvguard.status,
    _hardening_pax_segvguard, status,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON|CTLFLAG_SECURE);

SYSCTL_PROC(_hardening_pax_segvguard, OID_AUTO, expiry_timeout,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON|CTLFLAG_SECURE,
    NULL, 0, sysctl_pax_segvguard_expiry, "I",
    "Entry expiry timeout (in seconds).");

SYSCTL_PROC(_hardening_pax_segvguard, OID_AUTO, suspend_timeout,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON|CTLFLAG_SECURE,
    NULL, 0, sysctl_pax_segvguard_suspension, "I",
    "Entry suspension timeout (in seconds).");

SYSCTL_PROC(_hardening_pax_segvguard, OID_AUTO, max_crashes,
    CTLTYPE_INT|CTLFLAG_RWTUN|CTLFLAG_PRISON|CTLFLAG_SECURE,
    NULL, 0, sysctl_pax_segvguard_maxcrashes, "I",
    "Max number of crashes before expiry.");
#endif

#ifdef PAX_JAIL_SUPPORT
SYSCTL_DECL(_security_jail_param_hardening_pax);

SYSCTL_JAIL_PARAM_SUBNODE(hardening_pax, segvguard, "PaX segvguard");
SYSCTL_JAIL_PARAM(_hardening_pax_segvguard, status,
    CTLTYPE_INT | CTLFLAG_RD, "I",
    "segvguard status");
#endif

#ifdef PAX_SYSCTLS
static int
sysctl_pax_segvguard_expiry(SYSCTL_HANDLER_ARGS)
{
	int err;
	int val;
	struct prison *pr;

	pr = pax_get_prison_td(req->td);

	val = pr->pr_hbsd.segvguard.expiry;
	err = sysctl_handle_int(oidp, &val, sizeof(int), req);
	if (err || (req->newptr == NULL))
		return (err);

	if (pr == &prison0)
		pax_segvguard_expiry = val;

	pr->pr_hbsd.segvguard.expiry = val;

	return (0);
}

static int
sysctl_pax_segvguard_suspension(SYSCTL_HANDLER_ARGS)
{
	int err;
	int val;
	struct prison *pr;

	pr = pax_get_prison_td(req->td);

	val = pr->pr_hbsd.segvguard.suspension;
	err = sysctl_handle_int(oidp, &val, sizeof(int), req);
	if (err || (req->newptr == NULL))
		return (err);

	if (pr == &prison0)
		pax_segvguard_suspension = val;

	pr->pr_hbsd.segvguard.suspension = val;

	return (0);
}

static int
sysctl_pax_segvguard_maxcrashes(SYSCTL_HANDLER_ARGS)
{
	int err;
	int val;
	struct prison *pr;

	pr = pax_get_prison_td(req->td);

	val = pr->pr_hbsd.segvguard.maxcrashes;
	err = sysctl_handle_int(oidp, &val, sizeof(int), req);
	if (err || (req->newptr == NULL))
		return (err);

	if (pr == &prison0)
		pax_segvguard_maxcrashes = val;

	pr->pr_hbsd.segvguard.maxcrashes = val;

	return (0);
}
#endif

int
pax_segvguard_init_prison(struct prison *pr, struct vfsoptlist *opts)
{
	struct prison *pr_p;
	int error;

	if (pr == &prison0) {
		/* prison0 has no parent, use globals */
		pr->pr_hbsd.segvguard.status =
		    pax_segvguard_status;
		pr->pr_hbsd.segvguard.expiry =
		    pax_segvguard_expiry;
		pr->pr_hbsd.segvguard.suspension =
		    pax_segvguard_suspension;
		pr->pr_hbsd.segvguard.maxcrashes =
		    pax_segvguard_maxcrashes;
	} else {
		KASSERT(pr->pr_parent != NULL,
		   ("%s: pr->pr_parent == NULL", __func__));
		pr_p = pr->pr_parent;

		pr->pr_hbsd.segvguard.status =
		    pr_p->pr_hbsd.segvguard.status;
		error = pax_handle_prison_param(opts, "hardening.pax.segvguard.status",
		    &pr->pr_hbsd.segvguard.status);
		if (error != 0)
			return (error);

		pr->pr_hbsd.segvguard.expiry =
		    pr_p->pr_hbsd.segvguard.expiry;
		pr->pr_hbsd.segvguard.suspension =
		    pr_p->pr_hbsd.segvguard.suspension;
		pr->pr_hbsd.segvguard.maxcrashes =
		    pr_p->pr_hbsd.segvguard.maxcrashes;
	}

	return (0);
}

pax_flag_t
pax_segvguard_setup_flags(struct image_params *imgp, struct thread *td, pax_flag_t mode)
{
	struct prison *pr;
	struct vattr vap;
	pax_flag_t flags;
	uint32_t status;
	int ret;

	KASSERT(imgp->proc == td->td_proc,
	    ("%s: imgp->proc != td->td_proc", __func__));

	flags = 0;
	status = 0;

	pr = pax_get_prison_td(td);
	status = pr->pr_hbsd.segvguard.status;

	if (status == PAX_FEATURE_DISABLED) {
		flags &= ~PAX_NOTE_SEGVGUARD;
		flags |= PAX_NOTE_NOSEGVGUARD;

		return (flags);
	}

	if (status == PAX_FEATURE_FORCE_ENABLED) {
		flags |= PAX_NOTE_SEGVGUARD;
		flags &= ~PAX_NOTE_NOSEGVGUARD;

		return (flags);
	}

	if (status == PAX_FEATURE_OPTIN) {
		/*
		 * If the program has setuid, enforce the
		 * segvguard.
		 */
		ret = VOP_GETATTR(imgp->vp, &vap, td->td_ucred);
		if (ret != 0 ||
		    (vap.va_mode & (S_ISUID | S_ISGID)) != 0 ||
		    (mode & PAX_NOTE_SEGVGUARD)) {
			flags |= PAX_NOTE_SEGVGUARD;
			flags &= ~PAX_NOTE_NOSEGVGUARD;
		} else {
			flags &= ~PAX_NOTE_SEGVGUARD;
			flags |= PAX_NOTE_NOSEGVGUARD;
		}

		return (flags);
	}

	if (status == PAX_FEATURE_OPTOUT) {
		if (mode & PAX_NOTE_NOSEGVGUARD) {
			flags &= ~PAX_NOTE_SEGVGUARD;
			flags |= PAX_NOTE_NOSEGVGUARD;
		} else {
			flags |= PAX_NOTE_SEGVGUARD;
			flags &= ~PAX_NOTE_NOSEGVGUARD;
		}

		return (flags);
	}

	/*
	 * unknown status, force segvguard
	 */
	flags |= PAX_NOTE_SEGVGUARD;
	flags &= ~PAX_NOTE_NOSEGVGUARD;

	return (flags);
}

static bool
pax_segvguard_active_td(struct thread *td)
{
	pax_flag_t flags;

	pax_get_flags_td(td, &flags);

	CTR3(KTR_PAX, "%s: pid = %d p_pax = %x",
	    __func__, td->td_proc->p_pid, flags);

	if ((flags & PAX_NOTE_SEGVGUARD) == PAX_NOTE_SEGVGUARD)
		return (true);

	if ((flags & PAX_NOTE_NOSEGVGUARD) == PAX_NOTE_NOSEGVGUARD)
		return (false);

	return (true);
}

static void
pax_segvguard_cleaner(void *args)
{
	struct pax_segvguard_entry *se = args;

	printf("Entry for inode %lu on %s expired and removed for user %d.\n",
	    se->se_inode, se->se_mntpoint, se->se_uid);
	LIST_REMOVE(se, se_entry);
	free(se, M_PAX);
}

static struct pax_segvguard_entry *
pax_segvguard_add(struct thread *td, struct vnode *vn, sbintime_t sbt)
{
	struct pax_segvguard_entry *se;
	struct prison *pr;
	struct vattr vat;
	int error;

	se = malloc(sizeof(struct pax_segvguard_entry), M_PAX, M_NOWAIT | M_ZERO);
	if (se == NULL)
		return (NULL);

	if (VOP_ISLOCKED(vn) != LK_EXCLUSIVE) {
		if (vn_lock(vn, LK_SHARED | LK_RETRY) != 0) {
			free(se, M_PAX);
			return (NULL);
		}

		error = VOP_GETATTR(vn, &vat, td->td_ucred);
		strncpy(se->se_mntpoint, vn->v_mount->mnt_stat.f_mntonname, MNAMELEN);
		VOP_UNLOCK(vn, 0);
	} else {
		strncpy(se->se_mntpoint, vn->v_mount->mnt_stat.f_mntonname, MNAMELEN);
		error = VOP_GETATTR(vn, &vat, td->td_ucred);
	}
	
	if (error) {
		pax_log_segvguard(td->td_proc, PAX_LOG_DEFAULT,
		    "%s:%d VOP_GETATTR error. Bailing.", __func__, __LINE__);
		free(se, M_PAX);
		return (NULL);
	}

	pr = pax_get_prison_td(td);

	se->se_inode = vat.va_fileid;
	se->se_uid = td->td_ucred->cr_ruid;
	se->se_ncrashes = 1;

	callout_init_mtx(&se->se_callout, &PAX_SEGVGUARD_BUCKET(se)->bucket_mtx, 0);

	PAX_SEGVGUARD_LOCK(se);
	LIST_INSERT_HEAD(PAX_SEGVGUARD_BUCKET(se), se, se_entry);
	PAX_SEGVGUARD_UNLOCK(se);

	callout_reset(&se->se_callout, pr->pr_hbsd.segvguard.expiry * hz,
	    pax_segvguard_cleaner, se);

	return (se);
}

static struct pax_segvguard_entry *
pax_segvguard_lookup(struct thread *td, struct vnode *vn)
{
	struct pax_segvguard_entry *se, sekey;
	struct vattr vat;
	int error;

	if (VOP_ISLOCKED(vn) != LK_EXCLUSIVE) {
		if (vn_lock(vn, LK_SHARED | LK_RETRY) != 0)
			return (NULL);

		error = VOP_GETATTR(vn, &vat, td->td_ucred);
		strncpy(sekey.se_mntpoint, vn->v_mount->mnt_stat.f_mntonname, MNAMELEN);
		VOP_UNLOCK(vn, 0);
	} else {
		strncpy(sekey.se_mntpoint, vn->v_mount->mnt_stat.f_mntonname, MNAMELEN);
		error = VOP_GETATTR(vn, &vat, td->td_ucred);
	}

	if (error) {
		pax_log_segvguard(td->td_proc, PAX_LOG_DEFAULT,
		    "%s:%d VOP_GETATTR error. Bailing.", __func__, __LINE__);

		return (NULL);
	}

	sekey.se_inode = vat.va_fileid;
	sekey.se_uid = td->td_ucred->cr_ruid;

	PAX_SEGVGUARD_LOCK(&sekey);
	LIST_FOREACH(se, PAX_SEGVGUARD_BUCKET(&sekey), se_entry) {
		if (se->se_inode == vat.va_fileid &&
		    !strncmp(sekey.se_mntpoint, se->se_mntpoint, MNAMELEN) &&
		    td->td_ucred->cr_ruid == se->se_uid) {

			return (se);
		}
	}
	PAX_SEGVGUARD_UNLOCK(&sekey);

	return (NULL);
}

int
pax_segvguard_segfault(struct thread *td, const char *name)
{
	struct pax_segvguard_entry *se;
	struct prison *pr;
	struct vnode *v;
	sbintime_t sbt;

	if (pax_segvguard_active_td(td) == false)
		return (0);

	v = td->td_proc->p_textvp;
	if (v == NULL)
		return (EFAULT);

	pr = pax_get_prison_td(td);

	sbt = sbinuptime();

	se = pax_segvguard_lookup(td, v);

	/*
	 * If a program we don't know about crashed, we need to create a new entry for it
	 */
	if (se == NULL) {
		pax_segvguard_add(td, v, sbt);
	} else {
		se->se_ncrashes++;

		if (se->se_ncrashes >= pax_segvguard_maxcrashes) {
			printf("[%s (%d)] Suspending execution for %d seconds after %zu crashes.\n",
			    name, td->td_proc->p_pid,
			    pax_segvguard_suspension, se->se_ncrashes);

			callout_reset(&se->se_callout,
			    pr->pr_hbsd.segvguard.suspension * hz,
			    pax_segvguard_cleaner, se);
		}

		PAX_SEGVGUARD_UNLOCK(se);
	}

	return (0);
}

int
pax_segvguard_check(struct thread *td, struct vnode *v, const char *name)
{
	struct pax_segvguard_entry *se;
	sbintime_t sbt;

	if (pax_segvguard_active_td(td) == false)
		return (0);


	if (v == NULL)
		return (EFAULT);

	sbt = sbinuptime();

	se = pax_segvguard_lookup(td, v);

	if (se != NULL) {

		if (se->se_ncrashes >= pax_segvguard_maxcrashes) {
			printf("[%s (%d)] Preventing execution due to repeated segfaults.\n",
			    name, td->td_proc->p_pid);
			PAX_SEGVGUARD_UNLOCK(se);

			return (EPERM);
		}
		PAX_SEGVGUARD_UNLOCK(se);
	}

	return (0);
}

static void
pax_segvguard_sysinit(void)
{
	pax_state_t old_state;
	int i;

	old_state = pax_segvguard_status;
	if (!pax_feature_validate_state(&pax_segvguard_status)) {
		printf("[HBSD SEGVGUARD] WARNING, invalid PAX settings in loader.conf!"
		    " (hardening.pax.segvguard.status = %d)\n", old_state);
	}
	if (bootverbose) {
		printf("[HBSD SEGVGUARD] status: %s\n",
		    pax_status_str[pax_segvguard_status]);
		printf("[HBSD SEGVGUARD] expiry: %d sec\n",
		    pax_segvguard_expiry);
		printf("[HBSD SEGVGUARD] suspension: %d sec\n",
		    pax_segvguard_suspension);
		printf("[HBSD SEGVGUARD] maxcrashes: %d\n",
		    pax_segvguard_maxcrashes);
	}

	pax_segvguard_hashtbl =
		malloc(pax_segvguard_hashsize * sizeof(struct pax_segvguard_entryhead),
		M_PAX, M_WAITOK | M_ZERO);

	for(i = 0; i < pax_segvguard_hashsize; i++)
		PAX_SEGVGUARD_LOCK_INIT(&pax_segvguard_hashtbl[i]);
}

SYSINIT(pax_segvguard_init, SI_SUB_PAX, SI_ORDER_ANY, pax_segvguard_sysinit, NULL);
