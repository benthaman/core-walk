#ifndef _UTIL_H
#define _UTIL_H

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:	the pointer to the member.
 * @type:	the type of the container struct this is embedded in.
 * @member:	the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})

#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

/*
 * foreach_child_werr(Dwarf_Debug dbg, Dwarf_Die parent, Dwarf_Die child,
 *                    Dwarf_Die sibling, Dwarf_Error err)
 * "child" points to a new child at each iteration, sibling is used as a
 * temporay variable. If retval is DW_DLV_ERROR after the loop, check derr.
 */
#define foreach_child_werr(dwarf, parent, child, sibling, retval, derr) \
	for ( \
		(retval) = dwarf_child((parent), &(child), &(derr)); \
		(retval) == DW_DLV_OK; \
		(retval) = dwarf_siblingof((dwarf), (child), &(sibling), &(derr)), \
		dwarf_dealloc((dwarf), (child), DW_DLA_DIE), \
		(child) = (sibling) \
	    )

#define foreach_child(dwarf, parent, child, sibling, retval) \
	for ( \
		(retval) = dwarf_child((parent), &(child), NULL); \
		(retval) == DW_DLV_OK; \
		(retval) = dwarf_siblingof((dwarf), (child), &(sibling), NULL), \
		dwarf_dealloc((dwarf), (child), DW_DLA_DIE), \
		(child) = (sibling) \
	    )

#endif
