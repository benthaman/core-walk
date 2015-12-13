#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <libelf.h>
#include <gelf.h>
#include <libdwarf/libdwarf.h>
#include <libdwarf/dwarf.h>

#include "list.h"
#include "util.h"


struct call_entry {
	unsigned long pc;
	char *symbol;
	int offset;
};

int print_call_info(char *objname, Dwarf_Debug dwarf, Dwarf_Arange *aranges,
		    Dwarf_Signed ar_cnt, struct call_entry *call);
void print_die_info(Dwarf_Debug dwarf, Dwarf_Die die);
void print_var_info(Dwarf_Debug dwarf, Dwarf_Die var_die);

int find_subprogram_by_pc(Dwarf_Debug dwarf, Dwarf_Die die, Dwarf_Addr pc,
			  Dwarf_Die *result);


int main(int argc, char *argv[])
{
	int fd, i;
	char *objname = argv[1];
	struct call_entry calltrace[] = {
		{0xffffffff8134e51d, "sysrq_handle_crash", 0xd},
		{0xffffffff8134eaa4, "__handle_sysrq", 0xa4},
		{0xffffffff81362239, "serial8250_handle_port", 0x2b9},
		{0xffffffff8136242c, "serial8250_interrupt", 0x8c},
		{0xffffffff810bd163, "handle_irq_event_percpu", 0x43},
		{0xffffffff810bd324, "handle_irq_event", 0x34},
		{0xffffffff810bfb8f, "handle_edge_irq", 0x5f},
		{0xffffffff81004085, "handle_irq", 0x15},
		{0xffffffff81003d22, "do_IRQ", 0x52},
		{0xffffffff81733d13, "common_interrupt", 0x13},
		{0xffffffff8102cbf2, "native_safe_halt", 0x2},
		{0xffffffff81009e27, "default_idle", 0x47},
		{0xffffffff81001186, "cpu_idle", 0x66},
		{0xffffffff8171d40c, "start_secondary", 0x232},
	};
	int retval;

	Elf *elf;

	Dwarf_Debug dwarf;
	Dwarf_Arange *aranges;
	Dwarf_Signed ar_cnt;

	if (argc != 2) {
		fprintf(stderr, "Wrong number of arguments.\n");
		fprintf(stderr, "Usage: %s <vmlinux>\n", argv[0]);
		return EXIT_FAILURE;
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
		fprintf(stderr,
			"Error: ELF library initialization failed: %s\n",
			elf_errmsg(-1));
		return EXIT_FAILURE;
	}

	dwarf_record_cmdline_options(
		(Dwarf_Cmdline_Options) {.check_verbose_mode = false});

	if ((fd = open(objname, O_RDONLY, 0)) == -1) {
		fprintf(stderr, "Error: open \"%s\" failed: %s\n", objname,
			strerror(errno));
		abort();
	}

	if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
		fprintf(stderr, "Error: at line %d, libelf says: %s\n",
			__LINE__, elf_errmsg(-1));
		abort();
	}

	if (elf_kind(elf) != ELF_K_ELF) {
		fprintf(stderr, "Error: \"%s\" is not an ELF object.\n",
			objname);
		abort();
	}

	retval = dwarf_elf_init(elf, DW_DLC_READ, NULL, NULL, &dwarf, NULL);
	if (retval == DW_DLV_NO_ENTRY) {
		fprintf(stderr,
			"Error: \"%s\" does not contain debug information.\n",
			objname);
		abort();
	}

	/* todo: fallback to traversing all DIEs, especially if searching by
	 * symbol instead of address */
	retval = dwarf_get_aranges(dwarf, &aranges, &ar_cnt, NULL);
	if (retval == DW_DLV_NO_ENTRY) {
		fprintf(stderr,
			"Error: \"%s\" does not contain a .debug_aranges section.\n",
			objname);
		abort();
	}

	i = 0;
	print_call_info(objname, dwarf, aranges, ar_cnt, &calltrace[i]);
	/*
	for (i = 0;
	     i < ARRAY_SIZE(calltrace) &&
	     print_call_info(objname, dwarf, aranges, ar_cnt, &calltrace[i]) == 0;
	     i++) {
	}
	*/

	for (i = 0; i < ar_cnt; i++) {
		dwarf_dealloc(dwarf, aranges[i], DW_DLA_ARANGE);
	}
	dwarf_dealloc(dwarf, aranges, DW_DLA_LIST);
	dwarf_finish(dwarf, NULL);
	elf_end(elf);
	close(fd);

	return EXIT_SUCCESS;
}


int print_call_info(char *objname, Dwarf_Debug dwarf, Dwarf_Arange *aranges,
		    Dwarf_Signed ar_cnt, struct call_entry *call)
{
	Dwarf_Arange cu_arange;
	Dwarf_Unsigned lang;
	Dwarf_Off cu_doff;
	Dwarf_Die cu_die, sp_die;
	char *name;
	int retval;

	/* lookup the CU using the .debug_aranges section */
	retval = dwarf_get_arange(aranges, ar_cnt, call->pc, &cu_arange,
				  NULL);
	if (retval == DW_DLV_NO_ENTRY) {
		fprintf(stderr,
			"Error: no arange entry found for the following call:\n");
		fprintf(stderr, "[<%016lx>] %s\n", call->pc, call->symbol);
		abort();
	}

	dwarf_get_cu_die_offset(cu_arange, &cu_doff, NULL);
	dwarf_offdie(dwarf, cu_doff, &cu_die, NULL);

	printf("Compilation Unit\n");
	print_die_info(dwarf, cu_die);

	retval = dwarf_srclang(cu_die, &lang, NULL);
	if (retval == DW_DLV_NO_ENTRY) {
		fprintf(stderr,
			"Error: expected CU DIE to contain a language attribute.\n");
		print_die_info(dwarf, cu_die);
		abort();
	} else if (lang == DW_LANG_Mips_Assembler) {
		printf("Info: \"%s\" is defined in assembly source, stopping here for now.\n",
		       call->symbol);
		return -EDOM;
	}

	/* lookup the subprogram DIE in the CU */
	retval = find_subprogram_by_pc(dwarf, cu_die, call->pc, &sp_die);
	if (retval == -1) {
		fprintf(stderr,
			"Error: no subprogram entry found for the following call:\n");
		fprintf(stderr, "[<%016lx>] %s+0x%x\n", call->pc,
			call->symbol, call->offset);
		abort();
	}
	dwarf_dealloc(dwarf, cu_die, DW_DLA_DIE);

	printf("Subprogram\n");
	print_die_info(dwarf, sp_die);

	retval = dwarf_diename(sp_die, &name, NULL);
	if (retval == DW_DLV_NO_ENTRY) {
		fprintf(stderr,
			"Error: expected subprogram DIE to have a name.\n");
		print_die_info(dwarf, sp_die);
		abort();
	} else {
		if (strcmp(name, call->symbol) != 0) {
			fprintf(stderr,
				"Error: wrong DIE found, expected \"%s\".\n",
				call->symbol);
			print_die_info(dwarf, sp_die);
			abort();
		}
		dwarf_dealloc(dwarf, name, DW_DLA_STRING);
	}

	/* print parameters and variables */
	Dwarf_Die child, sibling;

	foreach_child(dwarf, sp_die, child, sibling, retval) {
		Dwarf_Half tag;

		dwarf_tag(child, &tag, NULL);
		if (tag == DW_TAG_formal_parameter || tag == DW_TAG_variable) {
			printf("Data object entry\n");
			print_die_info(dwarf, child);

			print_var_info(dwarf, child);
		}
	}

	dwarf_dealloc(dwarf, sp_die, DW_DLA_DIE);
	return 0;
}


void print_die_info(Dwarf_Debug dwarf, Dwarf_Die die)
{
	Dwarf_Half tag;
	Dwarf_Off global_off, cu_off;
	Dwarf_Attribute *attrbuf;
	Dwarf_Signed attrcount;
	const char *name;
	int i;
	int retval;

	dwarf_die_offsets(die, &global_off, &cu_off, NULL);
	dwarf_tag(die, &tag, NULL);
	dwarf_get_TAG_name(tag, &name);

	printf("<0x%016" DW_PR_DUx "> <0x%016" DW_PR_DUx "> %s\n", global_off,
	       cu_off, name);

	retval = dwarf_attrlist(die, &attrbuf, &attrcount, NULL);
	if (retval == DW_DLV_NO_ENTRY) {
		return;
	}

	for (i = 0; i < attrcount; i++) {
		Dwarf_Half form, at;
		const char *form_name, *attr_name;

		dwarf_whatform(attrbuf[i], &form, NULL);
		dwarf_get_FORM_name(form, &form_name);
		dwarf_whatattr(attrbuf[i], &at, NULL);
		dwarf_get_AT_name(at, &attr_name);

		printf("    %s (%s)", attr_name, form_name);

		switch (form) {
			char *retstring;
			Dwarf_Unsigned retudata;
			Dwarf_Signed retsdata;
			Dwarf_Off retoffset;

		case DW_FORM_strp:
		case DW_FORM_string:
			dwarf_formstring(attrbuf[i], &retstring, NULL);
			printf(" = %s", retstring);
			break;

		case DW_FORM_ref1:
		case DW_FORM_ref2:
		case DW_FORM_ref4:
		case DW_FORM_ref8:
			dwarf_formref(attrbuf[i], &retoffset, NULL);
			printf(" = <DIE at CU offset 0x%" DW_PR_DUx">",
			       retoffset);
			break;

		case DW_FORM_data1:
		case DW_FORM_data2:
		case DW_FORM_data4:
		case DW_FORM_data8:
			dwarf_formudata(attrbuf[i], &retudata, NULL);
			dwarf_formsdata(attrbuf[i], &retsdata, NULL);
			printf(" = %" DW_PR_DSd "/%" DW_PR_DUu, retudata,
			       retsdata);
			break;
		}
		printf("\n");

		dwarf_dealloc(dwarf, attrbuf[i], DW_DLA_ATTR);
	}
	dwarf_dealloc(dwarf, attrbuf, DW_DLA_LIST);
}


/* retval must be free()'ed */
__attribute__((nonnull))
char *get_type_name(Dwarf_Debug dwarf, Dwarf_Die type_die,
		    const char *prefix)
{
	int retval;
	char *type_name;
	char *result;

	retval = dwarf_diename(type_die, &type_name, NULL);
	if (retval == DW_DLV_NO_ENTRY) {
		Dwarf_Half tag;
		const char *tag_repr;

		dwarf_tag(type_die, &tag, NULL);
		dwarf_get_TAG_name(tag, &tag_repr);
		/* skip the DW_TAG_ prefix */
		tag_repr += 7;
		fprintf(stderr,
			"Error: expected %s DIE to have a name.\n", tag_repr);
		print_die_info(dwarf, type_die);
		abort();
	}

	result = malloc(strlen(prefix) + strlen(type_name) + 2);
	sprintf(result, "%s%s ", prefix, type_name);
	dwarf_dealloc(dwarf, type_name, DW_DLA_STRING);

	return result;
}


struct type_atom {
	struct list_head list;
	Dwarf_Half tag;
	char *string;
	enum {
		ALLOC_DWARF,
		ALLOC_MALLOC,
		ALLOC_STATIC,
	} alloc_type;
};

enum formats {
	FORMAT_X,
	FORMAT_D,
	FORMAT_U,
	FORMAT_F,
	FORMAT_P,
	FORMAT_C,
	FORMAT_S,
	FORMAT_B,
};

const char* format_names[] = {
	[FORMAT_X] = "hex",
	[FORMAT_D] = "signed",
	[FORMAT_U] = "unsigned",
	[FORMAT_F] = "float",
	[FORMAT_P] = "pointer",
	[FORMAT_C] = "char",
	[FORMAT_S] = "string",
	[FORMAT_B] = "bool",
};

struct type_info {
	struct list_head repr;
	struct type_atom *start;
	unsigned int repeat;
	enum formats format;
	Dwarf_Unsigned size;
	void *address;
	unsigned int indir_nb;
};


/* technically, it prints info about a "data object entry", not just a "var" */
void print_var_info(Dwarf_Debug dwarf, Dwarf_Die var_die)
{
	Dwarf_Attribute attr;
	struct type_info type = {
		.repr = LIST_HEAD_INIT(type.repr),
		.start = NULL,
		.repeat = 1,
		/* todo: remove when location expression evaluation is done */
		.address = NULL,
		.indir_nb = 0,
	};
	struct type_atom *atom;
	union {
		char *string;
		Dwarf_Unsigned udata;
	} const_value;
	int retval;

	if (dwarf_attr(var_die, DW_AT_const_value, &attr, NULL) == DW_DLV_OK) {
		Dwarf_Half form;

		dwarf_whatform(attr, &form, NULL);
		switch (form) {
			const char *form_name;

		case DW_FORM_strp:
		case DW_FORM_string:
			dwarf_formstring(attr, &const_value.string, NULL);
			break;

		case DW_FORM_data1:
		case DW_FORM_data2:
		case DW_FORM_data4:
		case DW_FORM_data8:
			dwarf_formudata(attr, &const_value.udata, NULL);
			break;

		default:
			dwarf_get_FORM_name(form, &form_name);
			fprintf(stderr,
				"Error: unsupported const_value form \"%s\", please extend the code.\n",
				form_name);
			print_die_info(dwarf, var_die);
			abort();
		}

		type.address = &const_value;
	} else if (dwarf_attr(var_die, DW_AT_location, &attr, NULL) ==
		   DW_DLV_OK) {
		/* evaluate the location expression, oh boy! */
	}

	/* traverse the DW_TAG_*_type chain */
	atom = malloc(sizeof(*atom));
	list_add(&atom->list, &type.repr);
	if (dwarf_diename(var_die, &atom->string, NULL) == DW_DLV_NO_ENTRY) {
		fprintf(stderr,
			"Error: expected variable DIE to have a name.\n");
		print_die_info(dwarf, var_die);
		abort();
	}
	atom->alloc_type = ALLOC_DWARF;
	atom->tag = DW_TAG_variable;

	if (dwarf_attr(var_die, DW_AT_type, &attr, NULL) == DW_DLV_NO_ENTRY) {
		fprintf(stderr,
			"Error: expected variable DIE to have a type.\n");
		print_die_info(dwarf, var_die);
		abort();
	}
	while (true) {
		Dwarf_Off type_offset;
		Dwarf_Die type_die;
		Dwarf_Half tag;
		Dwarf_Error derr;

		dwarf_global_formref(attr, &type_offset, NULL);
		dwarf_offdie(dwarf, type_offset, &type_die, &derr);
		dwarf_tag(type_die, &tag, NULL);

		/* malloc and fill a repr element */
		atom = malloc(sizeof(*atom));
		list_add(&atom->list, &type.repr);
		atom->tag = tag;

		switch (tag) {
			Dwarf_Die subrange_die;
			Dwarf_Signed repeat;
			const char *tag_name;

		case DW_TAG_pointer_type:
			if (dwarf_attr(type_die, DW_AT_type, &attr, NULL) ==
			    DW_DLV_NO_ENTRY) {
				atom->string = "void *";
			} else {
				atom->string = "*";
			}
			atom->alloc_type = ALLOC_STATIC;

			type.indir_nb++;
			break;

		case DW_TAG_array_type:
			if (dwarf_child(type_die, &subrange_die, NULL) ==
			    DW_DLV_NO_ENTRY) {
				fprintf(stderr,
					"Error: expected array_type DIE to have a subrange_type child.\n");
				print_die_info(dwarf, type_die);
				abort();
			}

			if (dwarf_attr(subrange_die, DW_AT_upper_bound, &attr,
				       NULL) == DW_DLV_NO_ENTRY) {
				fprintf(stderr,
					"Error: expected subrange_type DIE to have an upper_bound.\n");
				print_die_info(dwarf, var_die);
				abort();
			}
			dwarf_dealloc(dwarf, subrange_die, DW_DLA_DIE);
			dwarf_formsdata(attr, &repeat, NULL);
			if (repeat < 1) {
				fprintf(stderr,
					"Error: expected upper_bound to be positive, got %" DW_PR_DSd ".\n",
					repeat);
				abort();
			}
			dwarf_dealloc(dwarf, attr, DW_DLA_ATTR);
			type.repeat *= repeat;

			atom->string = malloc(24);
			atom->alloc_type = ALLOC_MALLOC;
			snprintf(atom->string, 24, "[%" DW_PR_DSd "]%c",
				 repeat,
				 list_entry(atom->list.next, struct type_atom,
					    list)->tag == DW_TAG_array_type ?
				 '\0' : ' ');
			break;

		case DW_TAG_const_type:
			atom->string = "const ";
			atom->alloc_type = ALLOC_STATIC;
			break;

		case DW_TAG_structure_type:
			atom->string = get_type_name(dwarf, type_die,
						     "struct ");
			atom->alloc_type = ALLOC_MALLOC;
			break;

		case DW_TAG_typedef:
			atom->string = get_type_name(dwarf, type_die, "");
			atom->alloc_type = ALLOC_MALLOC;
			if (type.start == NULL) {
				type.start = atom;
			}
			break;

		case DW_TAG_enumeration_type:
			atom->string = get_type_name(dwarf, type_die,
						     "enum ");
			atom->alloc_type = ALLOC_MALLOC;
			if (type.start == NULL) {
				type.start = atom;
			}
			break;

		case DW_TAG_base_type:
			atom->string = get_type_name(dwarf, type_die, "");
			atom->alloc_type = ALLOC_MALLOC;
			break;

		default:
			dwarf_get_TAG_name(tag, &tag_name);
			fprintf(stderr,
				"Error: unsupported *_type DIE type \"%s\", please extend the code.\n",
				tag_name);
			print_die_info(dwarf, type_die);
			abort();
		}

		retval = dwarf_attr(type_die, DW_AT_type, &attr, NULL);
		if (retval == DW_DLV_NO_ENTRY) {
			/* we've reached the end of the type chain */
			if (tag == DW_TAG_pointer_type) {
				type.format = FORMAT_P;
			} else if (tag == DW_TAG_structure_type) {
				type.format = FORMAT_X;
			} else if (tag == DW_TAG_enumeration_type) {
				/* todo: add a member to type with
				 * DW_TAG_enumerator values */
				type.format = FORMAT_U;
			} else {
				Dwarf_Unsigned encoding;

				if (dwarf_attr(type_die, DW_AT_encoding,
					       &attr, NULL) ==
				    DW_DLV_NO_ENTRY) {
					fprintf(stderr,
						"Error: expected this leaf *_type DIE to have an encoding\n");
					print_die_info(dwarf, type_die);
					abort();
				}
				dwarf_formudata(attr, &encoding, NULL);
				switch (encoding) {
					const char *ate_name;

				case DW_ATE_float:
					type.format = FORMAT_F;
					break;
				case DW_ATE_signed:
					type.format = FORMAT_D;
					break;
				case DW_ATE_unsigned:
					type.format = FORMAT_U;
					break;
				case DW_ATE_signed_char:
					type.format = FORMAT_C;
					break;
				case DW_ATE_boolean:
					type.format = FORMAT_B;
					break;
				default:
					dwarf_get_ATE_name(encoding, &ate_name);
					fprintf(stderr,
						"Error: unsupported encoding \"%s\", please extend the code.\n",
						ate_name);
					print_die_info(dwarf, type_die);
					abort();
				}
			}

			if (dwarf_attr(type_die, DW_AT_byte_size, &attr, NULL)
			    == DW_DLV_NO_ENTRY) {
				fprintf(stderr, "Error: expected leaf *_type DIE to have a byte_size\n");
				print_die_info(dwarf, type_die);
				abort();
			}
			dwarf_formudata(attr, &type.size, NULL);

			dwarf_dealloc(dwarf, type_die, DW_DLA_DIE);
			break;
		} else {
			dwarf_dealloc(dwarf, type_die, DW_DLA_DIE);
		}
	}
	if (type.start == NULL) {
		type.start = list_first_entry(&type.repr, typeof(*type.start),
					      list);
	}

	/* print and destroy the repr list */
	struct type_atom *pos, *n;
	bool print = false;

	list_for_each_entry_safe(pos, n, &type.repr, list) {
		if (!print && pos == type.start) {
			print = true;
		}
		if (print) {
			printf("%s", pos->string);
		}
		switch (pos->alloc_type) {
		case ALLOC_DWARF:
			dwarf_dealloc(dwarf, pos->string, DW_DLA_STRING);
			break;
		case ALLOC_MALLOC:
			free(pos->string);
			break;
		case ALLOC_STATIC:
			break;
		default:
			fprintf(stderr,
				"Error: unhandled alloc_type \"%u\", please extend the code.\n",
				pos->alloc_type);
			abort();
		}
		free(pos);
	}
	printf("\n");
	printf("address: %p, repeat: %u, indir_nb: %u, format: %s, size: %" DW_PR_DUu "\n",
	       type.address, type.repeat, type.indir_nb,
	       format_names[type.format], type.size);
}


int find_subprogram_by_pc(Dwarf_Debug dwarf, Dwarf_Die cu_die, Dwarf_Addr pc,
			  Dwarf_Die *result)
{
	Dwarf_Die child, sibling;
	int retval;

	foreach_child(dwarf, cu_die, child, sibling, retval) {
		Dwarf_Half tag;
		Dwarf_Addr retpc;

		dwarf_tag(child, &tag, NULL);
		if (tag != DW_TAG_subprogram) {
			continue;
		}

		/* low_pc/high_pc case */
		retval = dwarf_lowpc(child, &retpc, NULL);
		if (retval == DW_DLV_OK) {
			if (pc < retpc) {
				continue;
			}

			retval = dwarf_highpc(child, &retpc, NULL);
			if (retval == DW_DLV_OK) {
				if (pc > retpc) {
					continue;
				}

				*result = child;
				return 0;
			}
		}

		/* ranges case */
		// TODO

		/* a subprogram entry may have been inlined (DW_AT_inline) or
		 * may be external (DW_AT_external), in which case it will not
		 * have code addresses. We assume this is what's happening
		 * if the control flow makes it here. For completeness, we
		 * could instead check that this is really the case. */
	}

	return -1;
}
