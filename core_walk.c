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

int print_call_info(Dwarf_Debug dwarf, Dwarf_Arange *aranges, Dwarf_Signed
		    ar_cnt, const struct call_entry *call);
void print_die_info(Dwarf_Debug dwarf, Dwarf_Die die);
void print_attr_info(Dwarf_Debug dwarf, Dwarf_Attribute attr);
void print_locdesc(Dwarf_Debug dwarf, Dwarf_Locdesc *ld);
void print_cfi(Dwarf_Debug dwarf, const struct call_entry *call);
void print_regtable_entry(const char *regname, Dwarf_Regtable_Entry3 *entry);
void print_var_info(Dwarf_Debug dwarf, Dwarf_Die var_die);

int find_subprogram_by_pc(Dwarf_Debug dwarf, Dwarf_Die die, Dwarf_Addr pc,
			  Dwarf_Die *result);


int main(int argc, char *argv[])
{
	int fd, i;
	char *objname = argv[1];
	struct call_entry calltrace[] = {
		/* bogus entry, good test of location descriptions */
		{0xffffffff811e11cc, "isofs_fill_super", 2396},
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

	for (i = 0;
	     i < ARRAY_SIZE(calltrace) && print_call_info(
		     dwarf, aranges, ar_cnt, &calltrace[i]) == 0;
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


int print_call_info(Dwarf_Debug dwarf, Dwarf_Arange *aranges,
		    Dwarf_Signed ar_cnt, const struct call_entry *call)
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

	printf("Call frame information\n");
	print_cfi(dwarf, call);

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
		print_attr_info(dwarf, attrbuf[i]);
		dwarf_dealloc(dwarf, attrbuf[i], DW_DLA_ATTR);
	}
	dwarf_dealloc(dwarf, attrbuf, DW_DLA_LIST);
}


void print_attr_info(Dwarf_Debug dwarf, Dwarf_Attribute attr)
{
	Dwarf_Half at, form;
	const char *attr_name, *form_name;

	dwarf_whatattr(attr, &at, NULL);
	dwarf_get_AT_name(at, &attr_name);
	dwarf_whatform(attr, &form, NULL);
	dwarf_get_FORM_name(form, &form_name);

	printf("    %s (%s)", attr_name, form_name);

	switch(at) {
		Dwarf_Locdesc **llbufs;
		Dwarf_Signed retsdata;
		Dwarf_Unsigned retudata;
		int i;

	case DW_AT_location:
	case DW_AT_frame_base:
		if (dwarf_loclist_n(attr, &llbufs, &retsdata, NULL) !=
		    DW_DLV_OK) {
			fprintf(stderr,
				"Error: expected a location description\n");
			abort();
		}
		printf(" %" DW_PR_DSd " location descriptions:\n", retsdata);
		for (i = 0; i < retsdata; i++) {
			print_locdesc(dwarf, llbufs[i]);
			dwarf_dealloc(dwarf, llbufs[i]->ld_s, DW_DLA_LOC_BLOCK);
			dwarf_dealloc(dwarf, llbufs[i], DW_DLA_LOCDESC);
		}
		dwarf_dealloc(dwarf, llbufs, DW_DLA_LIST);
		break;
	
	case DW_AT_language:
		dwarf_formudata(attr, &retudata, NULL);
		printf(" = 0x%" DW_PR_DUx "\n", retudata);
		break;

	case DW_AT_decl_file:
	case DW_AT_decl_line:
		dwarf_formudata(attr, &retudata, NULL);
		printf(" = %" DW_PR_DUu "\n", retudata);
		break;

	default:
		switch (form) {
			char *retstring;
			Dwarf_Off retoffset;
			Dwarf_Bool retflag;
			Dwarf_Addr retaddr;
			Dwarf_Half addr_size;

		case DW_FORM_strp:
		case DW_FORM_string:
			dwarf_formstring(attr, &retstring, NULL);
			printf(" = %s", retstring);
			break;

		case DW_FORM_ref1:
		case DW_FORM_ref2:
		case DW_FORM_ref4:
		case DW_FORM_ref8:
			dwarf_formref(attr, &retoffset, NULL);
			printf(" = <DIE at CU offset 0x%" DW_PR_DUx">",
			       retoffset);
			break;

		case DW_FORM_data1:
		case DW_FORM_data2:
		case DW_FORM_data4:
		case DW_FORM_data8:
			dwarf_formsdata(attr, &retsdata, NULL);
			dwarf_formudata(attr, &retudata, NULL);
			printf(" = %" DW_PR_DSd "/%" DW_PR_DUu, retsdata,
			       retudata);
			break;

		case DW_FORM_flag:
			dwarf_formflag(attr, &retflag, NULL);
			printf(" = %s", retflag ? "True" : "False");
			break;

		case DW_FORM_addr:
			dwarf_formaddr(attr, &retaddr, NULL);
			dwarf_get_address_size(dwarf, &addr_size, NULL);
			printf(" = 0x%0*" DW_PR_DUx, 2 * (int) addr_size,
			       retaddr);
			break;
		}
		printf("\n");
	}
}


const char *register_abbrev[] = {
	[0] = "%rax",
	[1] = "%rdx",
	[2] = "%rcx",
	[3] = "%rbx",
	[4] = "%rsi",
	[5] = "%rdi",
	[6] = "%rbp",
	[7] = "%rsp",
	[8] = "%r8",
	[9] = "%r9",
	[10] = "%r10",
	[11] = "%r11",
	[12] = "%r12",
	[13] = "%r13",
	[14] = "%r14",
	[15] = "%r15",
	[16] = "retaddr",
};


void print_locdesc(Dwarf_Debug dwarf, Dwarf_Locdesc *ld)
{
	int i;
	const char *indent;
	Dwarf_Half addr_size;

	dwarf_get_address_size(dwarf, &addr_size, NULL);

	if (ld->ld_from_loclist) {
		printf("        [0x%2$0*1$" DW_PR_DUx ", 0x%3$0*1$" DW_PR_DUx "[\n",
		       2 * (int) addr_size, ld->ld_lopc, ld->ld_hipc);
		indent = "            ";
	} else {
		indent = "        ";
	}

	for (i = 0; i < ld->ld_cents; i++) {
		Dwarf_Small op = ld->ld_s[i].lr_atom;
		Dwarf_Unsigned arg1 = ld->ld_s[i].lr_number,
			       arg2 = ld->ld_s[i].lr_number2;
		const char *op_name;

		dwarf_get_OP_name(op, &op_name);
		printf("%s%s", indent, op_name);

		if (op >= DW_OP_reg0 && op <= DW_OP_reg15) {
			printf("() # %s", register_abbrev[op - DW_OP_reg0]);
		} else if (op >= DW_OP_breg0 && op <= DW_OP_breg15) {
			printf("(%+" DW_PR_DSd ") # %s0x%lx(%s)",
			       arg1, (Dwarf_Signed) arg1 < 0 ? "-" : "",
			       labs(arg1), register_abbrev[op - DW_OP_breg0]);
		} else if (op == DW_OP_stack_value) {
			printf("()");
		} else if (op == DW_OP_fbreg) {
			printf("(%+" DW_PR_DSd ")", ld->ld_s[i].lr_number);
		} else if (op >= DW_OP_lit0 && op <= DW_OP_lit31) {
			printf("() # %u", op - DW_OP_lit0);
		} else if (op == DW_OP_addr) {
			printf("(0x%0*" DW_PR_DUx ")",
			       2 * (int) addr_size, arg1);
		} else if (op == DW_OP_piece) {
			printf("(%" DW_PR_DUu ")", arg1);
		} else if (op == DW_OP_bit_piece) {
			printf("(%" DW_PR_DUu ", %" DW_PR_DUu ")", arg1,
			       arg2);
		} else if (op >= DW_OP_const1u && op <= DW_OP_consts) {
			if (op % 2 == 0) {
				printf("(%1$" DW_PR_DUu ") # %1$" DW_PR_DUu,
				       arg1);
			} else {
				printf("(%1$" DW_PR_DSd ") # %1$" DW_PR_DSd,
				       (Dwarf_Signed) arg1);
			}
		} else {
			printf(" ? ");
		}

		printf("\n");
	}
}


void print_cfi(Dwarf_Debug dwarf, const struct call_entry *call)
{
	Dwarf_Cie *cie_list;
	Dwarf_Fde *fde_list, fde;
	Dwarf_Signed cie_count, fde_count;
	Dwarf_Addr lopc, hipc, row_pc;
	Dwarf_Regtable3 reg_table;
	Dwarf_Half addr_size;
	int width, i;

	if (dwarf_get_fde_list_eh(dwarf, &cie_list, &cie_count, &fde_list,
				  &fde_count, NULL) != DW_DLV_OK) {
		fprintf(stderr,
			"Error: could not retrieve FDE list from eh_frame section\n");
		abort();
	}

	dwarf_get_fde_at_pc(fde_list, call->pc, &fde, &lopc, &hipc, NULL);

	reg_table.rt3_reg_table_size = ARRAY_SIZE(register_abbrev);
	reg_table.rt3_rules = malloc(sizeof(Dwarf_Regtable_Entry3) *
				     reg_table.rt3_reg_table_size);
	dwarf_get_fde_info_for_all_regs3(fde, call->pc, &reg_table, &row_pc,
					 NULL);

	dwarf_get_address_size(dwarf, &addr_size, NULL);
	width = 2 * (int) addr_size;
	printf("at pc = 0x%0*lx\n", width, call->pc);
	printf("    FDE low pc = 0x%0*" DW_PR_DUx "\n", width, lopc);
	printf("    FDE high pc = 0x%0*" DW_PR_DUx "\n", width, hipc);
	printf("    regtable row low pc = 0x%0*" DW_PR_DUx "\n", width,
	       row_pc);
	printf("    value of register in previous frame:\n");
	print_regtable_entry("CFA", &reg_table.rt3_cfa_rule);
	for (i = 0; i < reg_table.rt3_reg_table_size; i++) {
		print_regtable_entry(register_abbrev[i],
				     &reg_table.rt3_rules[i]);
	}

	free(reg_table.rt3_rules);
	dwarf_fde_cie_list_dealloc(dwarf, cie_list, cie_count, fde_list,
				   fde_count);
}


void print_regtable_entry(const char *regname, Dwarf_Regtable_Entry3 *entry)
{
	/* register rule type name */
	const char *rr_type_name[] = {
#define name_entry(macro) [macro] = #macro
		name_entry(DW_EXPR_OFFSET),
		name_entry(DW_EXPR_VAL_OFFSET),
		name_entry(DW_EXPR_EXPRESSION),
		name_entry(DW_EXPR_VAL_EXPRESSION),
	};

	printf("        [%7s] ", regname);
	switch (entry->dw_value_type) {
	case DW_EXPR_OFFSET:
		if (entry->dw_regnum == DW_FRAME_UNDEFINED_VAL) {
			printf("undefined\n");
		} else if (entry->dw_regnum == DW_FRAME_SAME_VAL) {
			printf("same value/not preserved\n");
		} else if (entry->dw_offset_relevant) {
			const char *basereg;

			if (entry->dw_regnum == DW_FRAME_CFA_COL3) {
				basereg = "CFA";
			} else {
				if (entry->dw_regnum >
				    ARRAY_SIZE(register_abbrev)) {
					fprintf(stderr,
						"Error: register number out of bounds (%u)\n",
						entry->dw_regnum);
					abort();
				}
				basereg = register_abbrev[entry->dw_regnum];
			}
			printf("%" DW_PR_DSd "(%s)\n",
			       entry->dw_offset_or_block_len, basereg);
		} else {
			if (entry->dw_regnum > ARRAY_SIZE(register_abbrev)) {
				fprintf(stderr,
					"Error: register number out of bounds (%u)\n",
					entry->dw_regnum);
				abort();
			}
			printf("(%%%s)\n", register_abbrev[entry->dw_regnum]);
		}
		break;
	default:
		if (entry->dw_value_type > ARRAY_SIZE(rr_type_name)) {
			fprintf(stderr,
				"Error: register rule type out of bounds (%u)\n",
				entry->dw_value_type);
			abort();
		}
		printf("%s ?\n", rr_type_name[entry->dw_value_type]);
	}
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

enum locations {
	LOC_REG,
	LOC_MEM,
	LOC_IMM,
};

const char* location_names[] = {
	[LOC_REG] = "register",
	[LOC_MEM] = "memory",
	[LOC_IMM] = "constant",
};

struct type_info {
	struct list_head repr;
	struct type_atom *start;
	unsigned int repeat;
	enum formats format;
	Dwarf_Unsigned size;
	enum locations loctype;
	union {
		char *string;
		Dwarf_Unsigned udata;
	} value;
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
		.indir_nb = 0,
	};
	struct type_atom *atom;
	int retval;

	if (dwarf_attr(var_die, DW_AT_const_value, &attr, NULL) == DW_DLV_OK) {
		Dwarf_Half form;

		type.loctype = LOC_IMM;

		dwarf_whatform(attr, &form, NULL);
		switch (form) {
			const char *form_name;

		case DW_FORM_strp:
		case DW_FORM_string:
			dwarf_formstring(attr, &type.value.string, NULL);
			break;

		case DW_FORM_data1:
		case DW_FORM_data2:
		case DW_FORM_data4:
		case DW_FORM_data8:
			dwarf_formudata(attr, &type.value.udata, NULL);
			break;

		default:
			dwarf_get_FORM_name(form, &form_name);
			fprintf(stderr,
				"Error: unsupported const_value form \"%s\", please extend the code.\n",
				form_name);
			print_die_info(dwarf, var_die);
			abort();
		}
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
	printf("location: %s, repeat: %u, indir_nb: %u, format: %s, size: %" DW_PR_DUu "\n",
	       location_names[type.loctype], type.repeat, type.indir_nb,
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
