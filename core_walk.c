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


int main(int argc, char *argv[])
{
	int fd;
	char *objname = argv[1];
	int retval;

	Elf *elf;
	Elf_Scn *scn;
	GElf_Shdr shdr;
	size_t shstrndx;

	Dwarf_Debug dwarf;

	if (argc != 2) {
		fprintf(stderr, "Wrong number of arguments\n");
		fprintf(stderr, "Usage: %s <core>\n", argv[0]);
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

	/* this is where it gets real */
	struct call_entry {
		unsigned long pc;
		char *symbol;
	} calltrace[] = {
		{0xffffffff8134e51d, "sysrq_handle_crash+0xd"},
		{0xffffffff8134eaa4, "__handle_sysrq+0xa4"},
		{0xffffffff81362239, "serial8250_handle_port+0x2b9"},
		{0xffffffff8136242c, "serial8250_interrupt+0x8c"},
		{0xffffffff810bd163, "handle_irq_event_percpu+0x43"},
		{0xffffffff810bd324, "handle_irq_event+0x34"},
		{0xffffffff810bfb8f, "handle_edge_irq+0x5f"},
		{0xffffffff81004085, "handle_irq+0x15"},
		{0xffffffff81003d22, "do_IRQ+0x52"},
		{0xffffffff81733d13, "common_interrupt+0x13"},
		{0xffffffff8102cbf2, "native_safe_halt+0x2"},
		{0xffffffff81009e27, "default_idle+0x47"},
		{0xffffffff81001186, "cpu_idle+0x66"},
		{0xffffffff8171d40c, "start_secondary+0x232"},
	}, *call = &calltrace[0];

	Dwarf_Arange *aranges, arange;
	Dwarf_Signed cnt;
	Dwarf_Off doff;
	Dwarf_Die die, die2;
	Dwarf_Error derr;

	retval = dwarf_get_aranges(dwarf, &aranges, &cnt, &derr);
	if (retval == DW_DLV_NO_ENTRY) {
		fprintf(stderr, "Error: \"%s\" does not contain a .debug_aranges section\n", objname);
		abort();
		/* todo: fallback to traversing all DIEs */
	} else if (retval != DW_DLV_OK) {
		fprintf(stderr, "Error: at line %d, libdwarf says: %s\n", __LINE__, dwarf_errmsg(derr));
		abort();
	}

	retval = dwarf_get_arange(aranges, cnt, call->pc, &arange, &derr);
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

	if (dwarf_offdie(dwarf, doff, &die, &derr) != DW_DLV_OK) {
		fprintf(stderr, "Error: at line %d, libdwarf says: %s\n", __LINE__, dwarf_errmsg(derr));
		abort();
	}

	retval = search_tree(dwarf, die, DW_TAG_subprogram, call->pc, &die2);
	if (retval == -1) {
		fprintf(stderr, "Error: no subprogram entry found for the following call:\n");
		fprintf(stderr, "[<%016lx>] %s\n", call->pc, call->symbol); 
		abort();
	}
	dwarf_dealloc(dwarf, die, DW_DLA_DIE);




	dwarf_finish(dwarf, NULL);
	elf_end(elf);
	close(fd);

	return EXIT_SUCCESS;
}
