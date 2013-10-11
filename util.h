#ifndef _UTIL_H
#define _UTIL_H

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/*
 * foreach_child(Dwarf_Debug dbg, Dwarf_Die parent, Dwarf_Die child, Dwarf_Die
 * sibling, Dwarf_Error err)
 * "child" points to a new child at each iteration, sibling is used as a
 * temporay variable. If retval is DW_DLV_ERROR after the loop, check derr.
 */
#define foreach_child(dwarf, parent, child, sibling, retval, derr) \
	for ( \
		(retval) = dwarf_child((parent), &(child), &(derr)); \
		(retval) == DW_DLV_OK; \
		(retval) = dwarf_siblingof((dwarf), (child), &(sibling), &(derr)), \
		dwarf_dealloc((dwarf), (child), DW_DLA_DIE), \
		(child) = (sibling) \
	    )

#endif
