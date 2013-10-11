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
#include <dwarf.h>

#include "util.h"


struct call_entry {
	unsigned long pc;
	char *symbol;
	int offset;
};

int print_call_info(char *objname, Dwarf_Debug dwarf, Dwarf_Arange *aranges,
		    Dwarf_Signed ar_cnt, struct call_entry *call);
int find_subprogram_by_pc(Dwarf_Debug dwarf, Dwarf_Die die, Dwarf_Addr pc, Dwarf_Die *result);
void print_die_info(Dwarf_Debug dwarf, Dwarf_Die die);


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
	Elf_Scn *scn;
	GElf_Shdr shdr;
	size_t shstrndx;

	Dwarf_Debug dwarf;
	Dwarf_Arange *aranges;
	Dwarf_Signed ar_cnt;
	Dwarf_Error derr;

	if (argc != 2) {
		fprintf(stderr, "Wrong number of arguments\n");
		fprintf(stderr, "Usage: %s <vmlinux>\n", argv[0]);
		return EXIT_FAILURE;
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
		fprintf(stderr, "Error: ELF library initialization failed: %s\n", elf_errmsg(-1));
		return EXIT_FAILURE;
	}

	dwarf_record_cmdline_options((Dwarf_Cmdline_Options) {.check_verbose_mode = false});

	if ((fd = open(objname, O_RDONLY, 0)) == -1) {
		fprintf(stderr, "Error: open \"%s\" failed: %s\n", objname, strerror(errno));
		abort();
	}

	if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
		fprintf(stderr, "Error: at line %d, libelf says: %s\n", __LINE__, elf_errmsg(-1));
		abort();
	}

	if (elf_kind(elf) != ELF_K_ELF) {
		fprintf(stderr, "Error: \"%s\" is not an ELF object\n", objname);
		abort();
	}

	if (elf_getshdrstrndx(elf, &shstrndx) != 0) {
		fprintf(stderr, "Error: at line %d, libelf says: %s\n", __LINE__, elf_errmsg(-1));
		abort();
	}

	scn = NULL;
	for (scn = NULL; (scn = elf_nextscn(elf, scn)) != NULL;) {
		char *name;

		if (gelf_getshdr(scn, &shdr) != &shdr) {
			fprintf(stderr, "Error: at line %d, libelf says: %s\n", __LINE__, elf_errmsg(-1));
			abort();
		}

		if ((name = elf_strptr(elf, shstrndx, shdr.sh_name)) == NULL) {
			fprintf(stderr, "Error: at line %d, libelf says: %s\n", __LINE__, elf_errmsg(-1));
			abort();
		}

		if (strcmp(name, ".eh_frame") == 0 ||
		    strcmp(name, ".debug_frame") == 0 ||
		    strcmp(name, ".debug_info") == 0 ||
		    strcmp(name, ".debug_aranges") == 0) {
			printf("section %zd: %s\n", elf_ndxscn(scn), name);
		}
	}

	retval = dwarf_elf_init(elf, DW_DLC_READ, NULL, NULL, &dwarf, NULL);
	if (retval == DW_DLV_NO_ENTRY) {
		fprintf(stderr, "Error: \"%s\" does not contain debug information\n", objname);
		abort();
	} else if (retval != DW_DLV_OK) {
		fprintf(stderr, "Error: at line %d, libdwarf operation failed\n", __LINE__);
	}

	retval = dwarf_get_aranges(dwarf, &aranges, &ar_cnt, &derr);
	if (retval == DW_DLV_NO_ENTRY) {
		fprintf(stderr, "Error: \"%s\" does not contain a .debug_aranges section\n", objname);
		abort();
	} else if (retval != DW_DLV_OK) {
		fprintf(stderr, "Error: at line %d, libdwarf says: %s\n", __LINE__, dwarf_errmsg(derr));
		abort();
	}


	for (i = 0;
	     i < ARRAY_SIZE(calltrace) &&
	     print_call_info(objname, dwarf, aranges, ar_cnt, &calltrace[i]) == 0;
	     i++) {
	}

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
	Dwarf_Arange arange;
	Dwarf_Unsigned lang;
	Dwarf_Off doff;
	Dwarf_Die cu_die, sp_die;
	Dwarf_Error derr;
	char *name;
	int retval;

	/* lookup the CU using the .debug_aranges section */
	/* todo: fallback to traversing all DIEs, especially if searching by
	 * symbol instead of address */
	retval = dwarf_get_arange(aranges, ar_cnt, call->pc, &arange, &derr);
	if (retval == DW_DLV_NO_ENTRY) {
		fprintf(stderr, "Error: no arange entry found for the following call:\n");
		fprintf(stderr, "[<%016lx>] %s\n", call->pc, call->symbol); 
		abort();
	} else if (retval != DW_DLV_OK) {
		fprintf(stderr, "Error: at line %d, libdwarf says: %s\n", __LINE__, dwarf_errmsg(derr));
		abort();
	}

	if (dwarf_get_cu_die_offset(arange, &doff, &derr) != DW_DLV_OK) {
		fprintf(stderr, "Error: at line %d, libdwarf says: %s\n", __LINE__, dwarf_errmsg(derr));
		abort();
	}

	if (dwarf_offdie(dwarf, doff, &cu_die, &derr) != DW_DLV_OK) {
		fprintf(stderr, "Error: at line %d, libdwarf says: %s\n", __LINE__, dwarf_errmsg(derr));
		abort();
	}

	printf("Compilation Unit\n");
	print_die_info(dwarf, cu_die);

	retval = dwarf_srclang(cu_die, &lang, &derr);
	if (retval == DW_DLV_ERROR) {
		fprintf(stderr, "Error: at line %d, libdwarf says: %s\n", __LINE__, dwarf_errmsg(derr));
		abort();
	} else if (retval == DW_DLV_OK && lang == DW_LANG_Mips_Assembler) {
		fprintf(stderr,
			"Warning: \"%s\" is defined in assembly source, stopping here for now\n",
			call->symbol);
		return -EDOM;
	}

	/* lookup the subprogram DIE in the CU */
	retval = find_subprogram_by_pc(dwarf, cu_die, call->pc, &sp_die);
	if (retval == -1) {
		fprintf(stderr, "Error: no subprogram entry found for the following call:\n");
		fprintf(stderr, "[<%016lx>] %s+0x%x\n", call->pc, call->symbol, call->offset); 
		abort();
	}
	dwarf_dealloc(dwarf, cu_die, DW_DLA_DIE);

	printf("Subprogram\n");
	print_die_info(dwarf, sp_die);

	retval = dwarf_diename(sp_die, &name, &derr);
	if (retval == DW_DLV_ERROR) {
		fprintf(stderr, "Error: at line %d, libdwarf says: %s\n", __LINE__, dwarf_errmsg(derr));
		abort();
	} else if (retval == DW_DLV_NO_ENTRY) {
		fprintf(stderr, "Error: expected subprogram DIE to have a name\n");
		print_die_info(dwarf, sp_die);
		abort();
	} else {
		if (strcmp(name, call->symbol) != 0) {
			fprintf(stderr, "Error: wrong DIE found, expected '%s'\n", call->symbol);
			print_die_info(dwarf, sp_die);
			abort();
		}
		dwarf_dealloc(dwarf, name, DW_DLA_STRING);
	}

	/* print parameters and variables */
	// TODO






	dwarf_dealloc(dwarf, sp_die, DW_DLA_DIE);
	return 0;
}


int find_subprogram_by_pc(Dwarf_Debug dwarf, Dwarf_Die cu_die, Dwarf_Addr pc, Dwarf_Die *result)
{
	Dwarf_Die child, sibling;
	Dwarf_Error derr;
	int retval;

	foreach_child(dwarf, cu_die, child, sibling, retval, derr) {
		Dwarf_Half tag;
		Dwarf_Addr retpc;

		if (dwarf_tag(child, &tag, &derr) != DW_DLV_OK) {
			fprintf(stderr, "Error: at line %d, libdwarf says: %s\n",
				__LINE__, dwarf_errmsg(derr));
			abort();
		}
		if (tag != DW_TAG_subprogram) {
			continue;
		}

		/* low_pc/high_pc case */
		retval = dwarf_lowpc(child, &retpc, &derr);
		if (retval == DW_DLV_ERROR) {
			fprintf(stderr, "Error: at line %d, libdwarf says: %s\n",
				__LINE__, dwarf_errmsg(derr));
			abort();
		} else if (retval == DW_DLV_OK) {
			if (pc < retpc) {
				continue;
			}

			retval = dwarf_highpc(child, &retpc, &derr);
			if (retval == DW_DLV_ERROR) {
				fprintf(stderr, "Error: at line %d, libdwarf says: %s\n",
					__LINE__, dwarf_errmsg(derr));
				abort();
			} else if (retval == DW_DLV_OK) {
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
	if (retval == DW_DLV_ERROR) {
		fprintf(stderr, "Error: at line %d, libdwarf says: %s\n", __LINE__, dwarf_errmsg(derr));
		abort();
	}

	return -1;
}


void print_die_info(Dwarf_Debug dwarf, Dwarf_Die die)
{
	Dwarf_Half tag;
	Dwarf_Error derr;
	Dwarf_Off global_off, cu_off;
	Dwarf_Attribute *attrbuf;
	Dwarf_Signed attrcount;
	const char *name;
	int retval;

	if (dwarf_die_offsets(die, &global_off, &cu_off, &derr) != DW_DLV_OK) {
		fprintf(stderr, "Error: at line %d, libdwarf says: %s\n",
			__LINE__, dwarf_errmsg(derr));
		abort();
	}

	if (dwarf_tag(die, &tag, &derr) != DW_DLV_OK) {
		fprintf(stderr, "Error: at line %d, libdwarf says: %s\n",
			__LINE__, dwarf_errmsg(derr));
		abort();
	}

	if (dwarf_get_TAG_name(tag, &name) != DW_DLV_OK) {
		fprintf(stderr, "Error: at line %d, libdwarf says: %s\n",
			__LINE__, dwarf_errmsg(derr));
		abort();
	}

	printf("<0x%016" DW_PR_DUx "> <0x%016" DW_PR_DUx "> %s\n", global_off, cu_off, name);

	retval = dwarf_attrlist(die, &attrbuf, &attrcount, &derr);
	if (retval == DW_DLV_ERROR) {
		fprintf(stderr, "Error: at line %d, libdwarf says: %s\n",
			__LINE__, dwarf_errmsg(derr));
		abort();
	} else if (retval == DW_DLV_OK) {
		int i;

		for (i = 0; i < attrcount; i++) {
			Dwarf_Half form, at;
			const char *form_name, *attr_name;

			if (dwarf_whatform(attrbuf[i], &form, &derr) != DW_DLV_OK) {
				fprintf(stderr, "Error: at line %d, libdwarf says: %s\n",
					__LINE__, dwarf_errmsg(derr));
				abort();
			}

			if (dwarf_get_FORM_name(form, &form_name) != DW_DLV_OK) {
				fprintf(stderr, "Error: at line %d, libdwarf says: %s\n",
					__LINE__, dwarf_errmsg(derr));
				abort();
			}

			if (dwarf_whatattr(attrbuf[i], &at, &derr) != DW_DLV_OK) {
				fprintf(stderr, "Error: at line %d, libdwarf says: %s\n",
					__LINE__, dwarf_errmsg(derr));
				abort();
			}
			if (dwarf_get_AT_name(at, &attr_name) != DW_DLV_OK) {
				fprintf(stderr, "Error: at line %d, libdwarf says: %s\n",
					__LINE__, dwarf_errmsg(derr));
				abort();
			}

			printf("    %s (%s)", attr_name, form_name);

			switch (form) {
				char *retstring;
				Dwarf_Unsigned retudata;
				Dwarf_Signed retsdata;

			case DW_FORM_strp:
			case DW_FORM_string:
				if (dwarf_formstring(attrbuf[i], &retstring, &derr) != DW_DLV_OK) {
					fprintf(stderr, "Error: at line %d, libdwarf says: %s\n",
						__LINE__, dwarf_errmsg(derr));
					abort();
				}
				printf(" = %s", retstring);
				break;

			case DW_FORM_data1:
			case DW_FORM_data2:
			case DW_FORM_data4:
			case DW_FORM_data8:
				if (dwarf_formudata(attrbuf[i], &retudata, &derr) != DW_DLV_OK) {
					fprintf(stderr, "Error: at line %d, libdwarf says: %s\n",
						__LINE__, dwarf_errmsg(derr));
					abort();
				}
				if (dwarf_formsdata(attrbuf[i], &retsdata, &derr) != DW_DLV_OK) {
					fprintf(stderr, "Error: at line %d, libdwarf says: %s\n",
						__LINE__, dwarf_errmsg(derr));
					abort();
				}
				printf(" = %" DW_PR_DSd "/%" DW_PR_DUu, retudata, retsdata);
				break;
			}
			printf("\n");

			dwarf_dealloc(dwarf, attrbuf[i], DW_DLA_ATTR);
		}
		dwarf_dealloc(dwarf, attrbuf, DW_DLA_LIST);
	}
}
