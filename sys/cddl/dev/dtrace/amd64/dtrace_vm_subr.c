/*-
 * Copyright (c) 2018 Domagoj Stolfa
 * All rights reserved.
 *
 * This software was developed by BAE Systems, the University of Cambridge
 * Computer Laboratory, and Memorial University under DARPA/AFRL contract
 * FA8650-15-C-7558 ("CADETS"), as part of the DARPA Transparent Computing
 * (TC) research program.
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
 */

#if 0
static boolean_t
dtrace_vm_map_lookup_entry(vm_map_t map, vm_offset_t address,
    vm_map_entry_t *entry)
{
	vm_map_entry_t cur;
	boolean_t locked;

	cur = map->root;
	if (cur == NULL)
		*entry = &map->header;
	else if (address >= cur->start && cur->end > address) {
		*entry = cur;
		return (TRUE);
	} else {
		/*
		 * Traverse the BST and find the address.
		 */
		for (;;) {
			if (address < cur->start) {
				if (cur->left == NULL) {
					*entry = cur->prev;
					break;
				}
				cur = cur->left;
			} else if (cur->end > address) {
				*entry = cur;
				return (TRUE);
			} else {
				if (cur->right == NULL) {
					*entry = cur;
					break;
				}
				cur = cur->right;
			}
		}

	}

	return (FALSE);
}

static vm_object_t *
dtrace_vm_map_lookup(vm_map_t *var_map, vm_offset_t vaddr,
    vm_prot_t fault_typea, vm_map_entry_t *out_entry,
    vm_object_t *object, vm_pindex_t *pindex,
    vm_prot_t *out_prot, boolean_t *wired)
{
	vm_map_entry_t entry;
	vm_map_t map = *var_map;
	vm_prot_t prot;
	vm_prot_t fault_type = fault_typea;

	/*
	 * Look up the address.
	 */
	if (!dtrace_vm_map_lookup_entry(map, vaddr, out_entry))
		return (KERN_INVALID_ADDRESS);

	entry = *out_entry;

	/*
	 * We don't care about submaps.
	 */
	if (entry->eflags & MAP_ENTRY_IS_SUB_MAP)
		return (KERN_FAILURE);

	prot = entry->protection;
	fault_type &= VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE;
	/*
	 * XXX(dstolfa): We might not care about this.
	 */
	if ((fault_type & prot) != fault_type)
		return (KERN_PROTECTION_FAILURE);

	*wired = (entry->wired_count != 0);
	if (*wired)
		fault_type = entry->protection;

	if (entry->eflags & MAP_ENTRY_NEEDS_COPY) {
		/*
		 * We don't care about CoW
		 */
		if (fault_type & VM_PROT_WRITE)
			return (KERN_FAILURE);

		prot &= ~VM_PROT_WRITE;
	}

	/*
	 * We don't create an object.
	 */
	if (entry->object.vm_object == NULL && !map->system_map)
		return (KERN_FAILURE);

	*pindex = UOFF_TO_IDX((vaddr - entry->start) + entry->offset);
	*object = entry->object.vm_object;

	*out_prot = prot;
	return (KERN_SUCCESS);
}

static pt_entry_t *
dtrace_pde_to_pte(pd_entry_t *pde, vm_offset_t va)
{
	pt_entry_t *pte;

	pte = (pt_entry_t *)PHYS_TO_DMAP(*pde & PG_FRAME);
	return (&pte[pmap_pte_index(va)]);
}

int
dtrace_gla2hpa(struct vm_guest_paging *paging, caddr_t gla, caddr_t *hpa)
{
	pt_entry_t *pte;
	const uint8_t shift = PAGE_SHIFT + 9;
	uint64_t pgsize = 0;

	*hpa = 0;
	if (paging->mode != PAGING_MODE_64)
		return (EINVAL);

	pte = dtrace_pde_to_pte((pd_entry_t *)paging->cr3, gla);
	/* Zero out the lower 'shift' bits and the upper 12 bits */
	pte >>= shift; pte <<= (shift + 12); pte >>= 12;
	pgsize = 1ULL << shift;
	gpa = pte | (gla & (pgsize - 1));
	*hpa = DMAP_TO_PHYS((uintptr_t)gpa);

	return (0);
}
#endif
