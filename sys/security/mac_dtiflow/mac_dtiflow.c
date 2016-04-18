/*-
 * Copyright (c) 2016 BAE Systems
 * All rights reserved.
 *
 * This software was developed by BAE Systems, the University of
 * Cambridge Computer Laboratory, and Memorial University under
 * DARPA/AFRL contract FA8650-15-C-7558 ("CADETS"), as part of
 * the DARPA Transparent Computing (TC) research program.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

/*
 * Developed by the TC/CADETS Project.
 *
 * dtiflow module that enables kernel information flow tracking by
 * associating MAC labels with information flows, and implementing new
 * DTrace probes when operations occur on those flows
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/acl.h>
#include <sys/conf.h>
#include <sys/domain.h>
#include <sys/extattr.h>
#include <sys/kernel.h>
#include <sys/ksem.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/sysproto.h>
#include <sys/sysent.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/pipe.h>
#include <sys/sx.h>
#include <sys/sysctl.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>

#include <fs/devfs/devfs.h>

#include <net/bpfdesc.h>
#include <net/if.h>
#include <net/if_types.h>
#include <net/if_var.h>

#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/ip_var.h>

#include <vm/vm.h>

#include <security/mac/mac_policy.h>
#include <security/mac_dtiflow/mac_dtiflow.h>

SYSCTL_DECL(_security_mac);

static SYSCTL_NODE(_security_mac, OID_AUTO, dtiflow, CTLFLAG_RW, 0,
    "mac_dtiflow policy controls");

static int	dtiflow_enabled = 1;
SYSCTL_INT(_security_mac_dtiflow, OID_AUTO, enabled, CTLFLAG_RW,
    &dtiflow_enabled, 0, "Enforce mac_dtiflow policy");

static int	destroyed_not_inited;
SYSCTL_INT(_security_mac_dtiflow, OID_AUTO, destroyed_not_inited, CTLFLAG_RD,
    &destroyed_not_inited, 0, "Count of labels destroyed but not inited");

static int	dtiflow_slot;
#define	SLOT(l)	((struct mac_dtiflow *)mac_label_get((l), dtiflow_slot))
#define	SLOT_SET(l, val) mac_label_set((l), dtiflow_slot, (uintptr_t)(val))

static MALLOC_DEFINE(M_DTIFLOW, "mac_dtiflow_label", "MAC/dtiflow labels");

static struct mac_dtiflow *
dtiflow_alloc(int flag)
{
	struct mac_dtiflow *ml;

	ml = malloc(sizeof(*ml), M_DTIFLOW, M_ZERO | flag);

	return (ml);
}

static void
dtiflow_free(struct mac_dtiflow *ml)
{
	if (ml != NULL)
		free(ml, M_DTIFLOW);
	else
		atomic_add_int(&destroyed_not_inited, 1);
}

static void
dtiflow_set_pid(struct mac_dtiflow *md, pid_t pid)
{
	KASSERT(md != NULL,
	    ("dtiflow_copy: label is NULL"));

	md->md_pid = pid;
}

static void
dtiflow_copy(struct mac_dtiflow *source, struct mac_dtiflow *dest)
{
	KASSERT( (source != NULL) && (dest != NULL),
	    ("dtiflow_copy: source or dest is NULL"));

	dest->md_pid = source->md_pid;
}

/*
 * Policy module operations.
 */
static void
dtiflow_destroy(struct mac_policy_conf *conf)
{

}

static void
dtiflow_init(struct mac_policy_conf *conf)
{

}

static int
dtiflow_syscall(struct thread *td, int call, void *arg)
{

	return (0);
}

/*
 * Label operations.
 */
static void
dtiflow_init_label(struct label *label)
{
	SLOT_SET(label, dtiflow_alloc(M_WAITOK));
}

static int
dtiflow_init_label_waitcheck(struct label *label, int flag)
{
	SLOT_SET(label, dtiflow_alloc(flag));
	if (SLOT(label) == NULL)
		return (ENOMEM);

	return (0);
}

static void
dtiflow_destroy_label(struct label *label)
{
	dtiflow_free(SLOT(label));
	SLOT_SET(label, NULL);

}

static void
dtiflow_copy_label(struct label *src, struct label *dest)
{
	if ((src != NULL) && (dest != NULL))
		*SLOT(dest) = *SLOT(src);
}

static int
dtiflow_externalize_label(struct label *label, char *element_name,
    struct sbuf *sb, int *claimed)
{

	return (0);
}

static int
dtiflow_internalize_label(struct label *label, char *element_name,
    char *element_data, int *claimed)
{

	return (0);
}

/*
 * Object-specific entry point imeplementations are sorted alphabetically by
 * object type name and then by operation.
 */
static int
dtiflow_pipe_check_ioctl(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel, unsigned long cmd, void /* caddr_t */ *data)
{

	return (0);
}

static int
dtiflow_pipe_check_poll(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel)
{

	return (0);
}

static int
dtiflow_pipe_check_read(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel)
{
	struct mac_dtiflow *obj;

	printf("%s\n", __func__);

	if (pplabel == NULL)
		return (0);

	obj = SLOT(pplabel);
	printf("%s: flow from pid: %d, currpid: %d(%s)\n", __func__, obj->md_pid, curthread->td_proc->p_pid, curthread->td_proc->p_comm);

	return (0);
}

static int
dtiflow_pipe_check_relabel(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel, struct label *newlabel)
{

	return (0);
}

static int
dtiflow_pipe_check_stat(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel)
{

	return (0);
}

static int
dtiflow_pipe_check_write(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel)
{
	struct mac_dtiflow *dest;

	printf("%s\n", __func__);

	if (pplabel == NULL)
		return (0);


	dest = SLOT(pplabel);
	dtiflow_set_pid(dest, curthread->td_proc->p_pid);

	return (0);
}

static void
dtiflow_pipe_create(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel)
{

}

static void
dtiflow_pipe_relabel(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel, struct label *newlabel)
{

}

static int
dtiflow_socket_check_accept(struct ucred *cred, struct socket *so,
    struct label *solabel)
{

#if 0
	SOCK_LOCK(so);
	SOCK_UNLOCK(so);
#endif

	return (0);
}

static int
dtiflow_socket_check_bind(struct ucred *cred, struct socket *so,
    struct label *solabel, struct sockaddr *sa)
{

#if 0
	SOCK_LOCK(so);
	SOCK_UNLOCK(so);
#endif

	return (0);
}

static int
dtiflow_socket_check_connect(struct ucred *cred, struct socket *so,
    struct label *solabel, struct sockaddr *sa)
{

#if 0
	SOCK_LOCK(so);
	SOCK_UNLOCK(so);
#endif

	return (0);
}

static int
dtiflow_socket_check_create(struct ucred *cred, int domain, int type, int proto)
{

	return (0);
}

static int
dtiflow_socket_check_deliver(struct socket *so, struct label *solabel,
    struct mbuf *m, struct label *mlabel)
{
	struct mac_dtiflow *p;

	printf("%s: %d(%s)\n", __func__, curthread->td_proc->p_pid, curthread->td_proc->p_comm);

	/* Restrict to UNIX domain sockets for now */
	if (so->so_proto->pr_domain->dom_family != AF_LOCAL)
		return (0);

	printf("%s: %d(%s)\n", __func__, curthread->td_proc->p_pid, curthread->td_proc->p_comm);

	if ((mlabel == NULL) || (solabel == NULL))
		return (0);

	p = SLOT(mlabel);

	printf("%s: flow from pid: %d, currpid: %d(%s)\n", __func__, p->md_pid, curthread->td_proc->p_pid, curthread->td_proc->p_comm);

	return (0);
}

static int
dtiflow_socket_check_listen(struct ucred *cred, struct socket *so,
    struct label *solabel)
{

#if 0
	SOCK_LOCK(so);
	SOCK_UNLOCK(so);
#endif

	return (0);
}

static int
dtiflow_socket_check_poll(struct ucred *cred, struct socket *so,
    struct label *solabel)
{

#if 0
	SOCK_LOCK(so);
	SOCK_UNLOCK(so);
#endif

	return (0);
}

static int
dtiflow_socket_check_receive(struct ucred *cred, struct socket *so,
    struct label *solabel)
{

	/* Restrict to UNIX domain sockets for now */
	if (so->so_proto->pr_domain->dom_family != AF_LOCAL)
		return (0);

	printf("%s: %d(%s)\n", __func__, curthread->td_proc->p_pid, curthread->td_proc->p_comm);

	return (0);
}

static int
dtiflow_socket_check_relabel(struct ucred *cred, struct socket *so,
    struct label *solabel, struct label *newlabel)
{

	SOCK_LOCK_ASSERT(so);

	return (0);
}
static int
dtiflow_socket_check_send(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	struct mac_dtiflow *dest;

#if 0
	SOCK_LOCK(so);
	SOCK_UNLOCK(so);
#endif
	/* Restrict to UNIX domain sockets for now */
	if (so->so_proto->pr_domain->dom_family != AF_LOCAL)
		return (0);

	printf("%s: %d(%s)\n", __func__, curthread->td_proc->p_pid, curthread->td_proc->p_comm);

	if (solabel == NULL)
		return (0);

	dest = SLOT(solabel);
	dtiflow_set_pid(dest, curthread->td_proc->p_pid);

	return (0);
}

static int
dtiflow_socket_check_stat(struct ucred *cred, struct socket *so,
    struct label *solabel)
{

#if 0
	SOCK_LOCK(so);
	SOCK_UNLOCK(so);
#endif

	return (0);
}

static int
dtiflow_socket_check_visible(struct ucred *cred, struct socket *so,
   struct label *solabel)
{

#if 0
	SOCK_LOCK(so);
	SOCK_UNLOCK(so);
#endif

	return (0);
}

static void
dtiflow_socket_create(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	struct mac_dtiflow *dest;

	/* Restrict to UNIX domain sockets for now */
	if (so->so_proto->pr_domain->dom_family != AF_LOCAL)
		return;

	printf("%s: %d(%s)\n", __func__, curthread->td_proc->p_pid, curthread->td_proc->p_comm);

	if (solabel == NULL)
		return;

	dest = SLOT(solabel);
	dtiflow_set_pid(dest, curthread->td_proc->p_pid);
}

static void
dtiflow_socket_create_mbuf(struct socket *so, struct label *solabel,
    struct mbuf *m, struct label *mlabel)
{
	struct mac_dtiflow *source, *dest;

	printf("%s: %d(%s)\n", __func__, curthread->td_proc->p_pid, curthread->td_proc->p_comm);

	/* Restrict to UNIX domain sockets for now */
	if (so->so_proto->pr_domain->dom_family != AF_LOCAL)
		return;

	printf("%s: %d(%s)\n", __func__, curthread->td_proc->p_pid, curthread->td_proc->p_comm);

	source = SLOT(solabel);
	dest = SLOT(mlabel);

	SOCK_LOCK(so);
	if ((source != NULL) && (dest != NULL))
		dtiflow_copy(source, dest);
	SOCK_UNLOCK(so);

}

static void
dtiflow_socket_newconn(struct socket *oldso, struct label *oldsolabel,
    struct socket *newso, struct label *newsolabel)
{

#if 0
	SOCK_LOCK(oldso);
	SOCK_UNLOCK(oldso);
#endif
#if 0
	SOCK_LOCK(newso);
	SOCK_UNLOCK(newso);
#endif
}

static void
dtiflow_socket_relabel(struct ucred *cred, struct socket *so,
    struct label *solabel, struct label *newlabel)
{

	SOCK_LOCK_ASSERT(so);
}

static void
dtiflow_socketpeer_set_from_mbuf(struct mbuf *m, struct label *mlabel,
    struct socket *so, struct label *sopeerlabel)
{

#if 0
	SOCK_LOCK(so);
	SOCK_UNLOCK(so);
#endif
}

static void
dtiflow_socketpeer_set_from_socket(struct socket *oldso,
    struct label *oldsolabel, struct socket *newso,
    struct label *newsopeerlabel)
{

#if 0
	SOCK_LOCK(oldso);
	SOCK_UNLOCK(oldso);
#endif
#if 0
	SOCK_LOCK(newso);
	SOCK_UNLOCK(newso);
#endif
}

/*
 * Register functions with MAC Framework policy entry points.
 */
static struct mac_policy_ops dtiflow_ops =
{
	.mpo_destroy = dtiflow_destroy,
	.mpo_init = dtiflow_init,
	.mpo_syscall = dtiflow_syscall,

	.mpo_mbuf_copy_label = dtiflow_copy_label,
	.mpo_mbuf_destroy_label = dtiflow_destroy_label,
	.mpo_mbuf_init_label = dtiflow_init_label_waitcheck,

	/*
	.mpo_pipe_check_ioctl = dtiflow_pipe_check_ioctl,
	.mpo_pipe_check_poll = dtiflow_pipe_check_poll,
	.mpo_pipe_check_read = dtiflow_pipe_check_read,
	.mpo_pipe_check_relabel = dtiflow_pipe_check_relabel,
	.mpo_pipe_check_stat = dtiflow_pipe_check_stat,
	.mpo_pipe_check_write = dtiflow_pipe_check_write,
	.mpo_pipe_copy_label = dtiflow_copy_label,
	.mpo_pipe_create = dtiflow_pipe_create,
	.mpo_pipe_destroy_label = dtiflow_destroy_label,
	.mpo_pipe_externalize_label = dtiflow_externalize_label,
	.mpo_pipe_init_label = dtiflow_init_label,
	.mpo_pipe_internalize_label = dtiflow_internalize_label,
	.mpo_pipe_relabel = dtiflow_pipe_relabel,
	*/

	.mpo_socket_check_accept = dtiflow_socket_check_accept,
	.mpo_socket_check_bind = dtiflow_socket_check_bind,
	.mpo_socket_check_connect = dtiflow_socket_check_connect,
	.mpo_socket_check_create = dtiflow_socket_check_create,
	.mpo_socket_check_deliver = dtiflow_socket_check_deliver,
	.mpo_socket_check_listen = dtiflow_socket_check_listen,
	.mpo_socket_check_poll = dtiflow_socket_check_poll,
	.mpo_socket_check_receive = dtiflow_socket_check_receive,
	.mpo_socket_check_relabel = dtiflow_socket_check_relabel,
	.mpo_socket_check_send = dtiflow_socket_check_send,
	.mpo_socket_check_stat = dtiflow_socket_check_stat,
	.mpo_socket_check_visible = dtiflow_socket_check_visible,
	.mpo_socket_copy_label = dtiflow_copy_label,
	.mpo_socket_create = dtiflow_socket_create,
	.mpo_socket_create_mbuf = dtiflow_socket_create_mbuf,
	.mpo_socket_destroy_label = dtiflow_destroy_label,
	.mpo_socket_externalize_label = dtiflow_externalize_label,
	.mpo_socket_init_label = dtiflow_init_label_waitcheck,
	.mpo_socket_internalize_label = dtiflow_internalize_label,
	.mpo_socket_newconn = dtiflow_socket_newconn,
	.mpo_socket_relabel = dtiflow_socket_relabel,

	.mpo_socketpeer_destroy_label = dtiflow_destroy_label,
	.mpo_socketpeer_externalize_label = dtiflow_externalize_label,
	.mpo_socketpeer_init_label = dtiflow_init_label_waitcheck,
	.mpo_socketpeer_set_from_mbuf = dtiflow_socketpeer_set_from_mbuf,
	.mpo_socketpeer_set_from_socket = dtiflow_socketpeer_set_from_socket

};

MAC_POLICY_SET(&dtiflow_ops, mac_dtiflow, "MAC/DTrace information flow",
    MPC_LOADTIME_FLAG_UNLOADOK, &dtiflow_slot);
