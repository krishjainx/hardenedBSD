/*-
 * Copyright (c) 2006 Elad Efrat <elad@NetBSD.org>
 * Copyright (c) 2013-2017, by Oliver Pinter <oliver.pinter@hardenedbsd.org>
 * Copyright (c) 2014-2022, by Shawn Webb <shawn.webb@hardenedbsd.org>
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
#include <sys/kernel.h>
#include <sys/exec.h>
#include <sys/imgact.h>
#include <sys/imgact_elf.h>
#include <sys/jail.h>
#include <sys/ktr.h>
#include <sys/libkern.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/pax.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

#include <machine/_inttypes.h>

static void pax_set_flags(struct proc *p, struct thread *td, const pax_flag_t flags);
static void pax_set_flags_td(struct thread *td, const pax_flag_t flags);
static int pax_validate_flags(const pax_flag_t flags);
static int pax_check_conflicting_modes(const pax_flag_t mode);

/*
 * Enforce and check HardenedBSD constraints
 */
#ifndef INVARIANTS
#ifndef PAX_INSECURE_MODE
#error "HardenedBSD required enabled INVARIANTS in kernel config... If you really know what you're doing you can add `options PAX_INSECURE_MODE` to the kernel config"
#endif
#endif

CTASSERT((sizeof((struct proc *)NULL)->p_pax) == sizeof(pax_flag_t));
CTASSERT((sizeof((struct thread *)NULL)->td_pax) == sizeof(pax_flag_t));
CTASSERT((sizeof((struct image_params *)NULL)->pax.req_acl_flags) == sizeof(pax_flag_t));
CTASSERT((sizeof((struct image_params *)NULL)->pax.req_extattr_flags) == sizeof(pax_flag_t));

/*
 * The PAX_HARDENING_{,NO}SHLIBRANDOM flags are
 * used from rtld.
 */
CTASSERT(PAX_NOTE_SHLIBRANDOM == PAX_HARDENING_SHLIBRANDOM);
CTASSERT(PAX_NOTE_NOSHLIBRANDOM == PAX_HARDENING_NOSHLIBRANDOM);


SYSCTL_NODE(_hardening, OID_AUTO, pax, CTLFLAG_RD, 0,
    "PaX (exploit mitigation) features.");

#ifdef PAX_JAIL_SUPPORT
SYSCTL_JAIL_PARAM_NODE(hardening, "HardenedBSD features.");
SYSCTL_JAIL_PARAM_SUBNODE(hardening, pax, "PaX (exploit mitigation) features");
#endif

#if defined(PAX_CONTROL_ACL) || defined(PAX_CONTROL_EXTATTR)
SYSCTL_NODE(_hardening, OID_AUTO, control, CTLFLAG_RD, 0,
    "PaX features control subnode.");
#endif

SYSCTL_U64(_hardening, OID_AUTO, version, CTLFLAG_RD|CTLFLAG_CAPRD,
    SYSCTL_NULL_U64_PTR, __HardenedBSD_version, "HardenedBSD version");

const char *pax_status_str[] = {
	[PAX_FEATURE_DISABLED] = "disabled",
	[PAX_FEATURE_OPTIN] = "opt-in",
	[PAX_FEATURE_OPTOUT] = "opt-out",
	[PAX_FEATURE_FORCE_ENABLED] = "force enabled",
};

const char *pax_status_simple_str[] = {
	[PAX_FEATURE_SIMPLE_DISABLED] = "disabled",
	[PAX_FEATURE_SIMPLE_ENABLED] = "enabled"
};


/*
 * @ brief Get current __HardenedBSD_version.
 *
 * @ return	__HardenedBSD_version
 */
__noinline uint64_t
pax_get_hardenedbsd_version(void)
{
	static const uint64_t HardenedBSD_version = __HardenedBSD_version;

	return (HardenedBSD_version);
}

struct prison *
pax_get_prison_td(struct thread *td)
{

	if (td == NULL || td->td_ucred == NULL)
		return (&prison0);

	return (td->td_ucred->cr_prison);
}

/*
 * @brief Get the current PaX status from process.
 *
 * @param p		The controlled process pointer.
 * @param flags		Where to write the current state.
 *
 * @return		none
 */
void
pax_get_flags(struct proc *p, pax_flag_t *flags)
{

	KASSERT(p == curthread->td_proc,
	    ("%s: p != curthread->td_proc", __func__));

#ifdef HBSD_DEBUG
	struct thread *td;

	FOREACH_THREAD_IN_PROC(p, td) {
		KASSERT(td->td_pax == p->p_pax, ("%s: td->td_pax != p->p_pax",
		    __func__));
	}
#endif

	*flags = p->p_pax;
}

void
pax_get_flags_td(struct thread *td, pax_flag_t *flags)
{

	KASSERT(td == curthread,
	    ("%s: td != curthread", __func__));

#ifdef HBSD_DEBUG
	struct proc *p;
	struct thread *td0;

	p = td->td_proc;

	FOREACH_THREAD_IN_PROC(p, td0) {
		KASSERT(td0->td_proc == p,
		    ("%s: td0->td_proc != p", __func__));
		KASSERT(td0->td_pax == p->p_pax, ("%s: td0->td_pax != p->p_pax",
		    __func__));
	}
#endif

	*flags = td->td_pax;
}

void
pax_set_flags(struct proc *p, struct thread *td, const pax_flag_t flags)
{
	struct thread *td0;

	KASSERT(td == curthread,
	    ("%s: td != curthread", __func__));
	KASSERT(td->td_proc == p,
	    ("%s: td->td_proc != p", __func__));

	PROC_LOCK(p);
	p->p_pax = flags;
	FOREACH_THREAD_IN_PROC(p, td0) {
		pax_set_flags_td(td0, flags);
	}
	PROC_UNLOCK(p);
}

void
pax_set_flags_td(struct thread *td, const pax_flag_t flags)
{

	td->td_pax = flags;
}

/*
 * rename to pax_valid_flags, and change return values and type to bool
 */
static int
pax_validate_flags(const pax_flag_t flags)
{

	if ((flags & ~PAX_NOTE_ALL) != 0)
		return (1);

	return (0);
}

/*
 * same as pax_valid_flags
 */
static int
pax_check_conflicting_modes(const pax_flag_t mode)
{

	if (((mode & PAX_NOTE_ALL_ENABLED) & ((mode & PAX_NOTE_ALL_DISABLED) >> 1)) != 0)
		return (1);

	return (0);
}

static pax_flag_t
pax_get_requested_flags(struct image_params *imgp)
{
	pax_flag_t req_flags;

	req_flags = 0;

#if defined(PAX_CONTROL_ACL) && defined(PAX_CONTROL_EXTATTR)
	req_flags = (imgp->pax.req_acl_flags & PAX_NOTE_PREFER_ACL) ?
	    imgp->pax.req_acl_flags : imgp->pax.req_extattr_flags;

	if (req_flags == 0 && imgp->pax.req_acl_flags != 0)
		req_flags = imgp->pax.req_acl_flags;
#elif defined(PAX_CONTROL_EXTATTR)
	req_flags =  imgp->pax.req_extattr_flags ? imgp->pax.req_extattr_flags : 0;
#elif defined(PAX_CONTROL_ACL)
	req_flags = imgp->pax.req_acl_flags ? imgp->pax.req_acl_flags : 0;
#endif

	return (req_flags);
}

/*
 * @bried Initialize the new process PaX state
 *
 * @param td		Pointer to the current thread.
 * @param imgp		Executable image's structure.
 *
 * @return		ENOEXEC on fail
 * 			0 on success
 */
int
pax_elf(struct thread *td, struct image_params *imgp)
{
	pax_flag_t flags, mode;

#ifdef PAX_CONTROL_ACL
#ifdef PAX_CONTROL_ACL_OVERRIDE_SUPPORT
	pax_get_flags_td(td, &flags);
	if ((flags & PAX_NOTE_PREFER_ACL) == PAX_NOTE_PREFER_ACL)
		return (0);
#endif
#endif

	mode = pax_get_requested_flags(imgp);

	flags = 0;

	if (pax_validate_flags(mode) != 0) {
		pax_log_internal_imgp(imgp, PAX_LOG_DEFAULT,
		    "unknown paxflags: %x", mode);
		pax_ulog_internal("unknown paxflags: %x\n", mode);

		return (ENOEXEC);
	}

	if (pax_check_conflicting_modes(mode) != 0) {
		/*
		 * indicate flags inconsistencies in dmesg and in user terminal
		 */
		pax_log_internal_imgp(imgp, PAX_LOG_DEFAULT,
		    "inconsistent paxflags: %x", mode);
		pax_ulog_internal("inconsistent paxflags: %x\n", mode);

		return (ENOEXEC);
	}

#ifdef PAX_ASLR
	flags |= pax_aslr_setup_flags(imgp, td, mode);
#ifdef MAP_32BIT
	flags |= pax_disallow_map32bit_setup_flags(imgp, td, mode);
#endif
#endif

#ifdef PAX_NOEXEC
	flags |= pax_noexec_setup_flags(imgp, td, mode);
#endif

#ifdef PAX_SEGVGUARD
	flags |= pax_segvguard_setup_flags(imgp, td, mode);
#endif

#ifdef PAX_HARDENING
	flags |= pax_hardening_setup_flags(imgp, td, mode);
#endif

	CTR3(KTR_PAX, "%s : flags = %x mode = %x",
	    __func__, flags, mode);

	/*
	 * Recheck the flags after the parsing: prevent broken setups.
	 */
	if (pax_validate_flags(flags) != 0) {
		pax_log_internal_imgp(imgp, PAX_LOG_DEFAULT,
		    "unknown paxflags after the setup: %x", flags);
		pax_ulog_internal("unknown paxflags after the setup: %x\n", flags);

		return (ENOEXEC);
	}

	/*
	 * Recheck the flags after the parsing: prevent conflicting setups.
	 * This check should be always false.
	 */
	if (pax_check_conflicting_modes(flags) != 0) {
		/*
		 * indicate flags inconsistencies in dmesg and in user terminal
		 */
		pax_log_internal_imgp(imgp, PAX_LOG_DEFAULT,
		    "inconsistent paxflags after the setup: %x", flags);
		pax_ulog_internal("inconsistent paxflags after the setup: %x\n", flags);

		return (ENOEXEC);
	}

#ifdef PAX_CONTROL_ACL
#ifdef PAX_CONTROL_ACL_OVERRIDE_SUPPORT
	if ((mode & PAX_NOTE_PREFER_ACL) == PAX_NOTE_PREFER_ACL)
		flags |= PAX_NOTE_PREFER_ACL;
	else
		flags &= ~PAX_NOTE_PREFER_ACL;
#endif
#endif

	pax_set_flags(imgp->proc, td, flags);

	/*
	 * if we enable/disable features with secadm, print out a warning
	 */
	if (mode != 0) {
		pax_log_internal_imgp(imgp, PAX_LOG_DEFAULT,
		   "the process started with non-default hardening settings");
	}

	return (0);
}


/*
 * @brief Print out PaX settings on boot time, and validate some of them.
 *
 * @return		none
 */
static void
pax_sysinit(void)
{

	printf("HardenedBSD: initialize and check features "
	    "(__HardenedBSD_version %"PRIu64" __FreeBSD_version %"PRIu64").\n",
	    (uint64_t)__HardenedBSD_version, (uint64_t)__FreeBSD_version);
}
SYSINIT(pax, SI_SUB_PAX, SI_ORDER_FIRST, pax_sysinit, NULL);

/*
 * @brief Initialize prison's state.
 *
 * The prison0 state initialized with global state.
 * The child prisons state initialized with it's parent's state.
 *
 * @param pr		Initializable prison's pointer.
 * @param opts		Jail parameter list.
 *
 * @return		true if initialization finished.
 */
bool
pax_init_prison(struct prison *pr, struct vfsoptlist *opts)
{
	bool ret;

	CTR2(KTR_PAX, "%s: Setting prison %s PaX variables\n",
	    __func__, pr->pr_name);

	if (pax_aslr_init_prison(pr, opts) != 0) {
		ret = false;
		goto out;
	}

	if (pax_hardening_init_prison(pr, opts) != 0) {
		ret = false;
		goto out;
	}

	if (pax_noexec_init_prison(pr, opts) != 0) {
		ret = false;
		goto out;
	}

	if (pax_segvguard_init_prison(pr, opts) != 0) {
		ret = false;
		goto out;
	}

#ifdef COMPAT_FREEBSD32
	if (pax_aslr_init_prison32(pr, opts) != 0) {
		ret = false;
		goto out;
	}
#endif

	if (pax_log_init_prison(pr, opts) != 0) {
		ret = false;
		goto out;
	}

	/* Every initialization finished w/o error. */
	ret = true;

out:
	KASSERT((pr == &prison0 && ret == true) || pr != &prison0,
	    ("Unexpected error during prison0 initialization."));

	return (ret);
}

/*
 * This function used from traps / panics.
 */
void
pax_print_hbsd_context(void)
{

	printf("__HardenedBSD_version = %"PRIu64" __FreeBSD_version = %"PRIu64"\n",
	    (uint64_t)__HardenedBSD_version, (uint64_t)__FreeBSD_version);
	printf("version = %s", version);
}

/*
 * Function to validate PaX feature states.
 * Always returns a proper state in state parameter.
 * Additionally return "true" when the validation passed,
 * but return "false" when a the validation failed.
 */
bool
pax_feature_validate_state(pax_state_t *state)
{

	switch (*state) {
	case PAX_FEATURE_DISABLED:
	case PAX_FEATURE_OPTIN:
	case PAX_FEATURE_OPTOUT:
	case PAX_FEATURE_FORCE_ENABLED:
		return (true);
	default:
		*state = PAX_FEATURE_FORCE_ENABLED;
	}

	return (false);
}

/*
 * Function to validate PaX simple feature states.
 * Always returns a proper state in state parameter.
 * Additionally return "true" when the validation passed,
 * but return "false" when a the validation failed.
 */
bool
pax_feature_simple_validate_state(pax_state_t *state)
{

	switch (*state) {
	case PAX_FEATURE_SIMPLE_DISABLED:
	case PAX_FEATURE_SIMPLE_ENABLED:
		return (true);
	default:
		*state = PAX_FEATURE_SIMPLE_ENABLED;
	}

	return (false);
}

int
pax_handle_prison_param(struct vfsoptlist *opts, const char *mib, pax_state_t *status)
{
#ifdef PAX_JAIL_SUPPORT
	pax_state_t new_state;
	int error;

	error = vfs_copyopt(opts, mib, &new_state, sizeof(new_state));
	switch (error) {
	case ENOENT:
		/* use system default */
		break;
	case 0:
		if (pax_feature_validate_state(&new_state))
			*status = new_state;
		break;
	default:
		return (error);
	}
#endif /* PAX_JAIL_SUPPORT */

	return (0);
}
