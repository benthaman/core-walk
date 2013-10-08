#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <libelf.h>
#include <gelf.h>


int main(int argc, char *argv[])
{
	int fd;
	Elf *e;
	Elf_Scn *scn;
	GElf_Shdr shdr;
	size_t shstrndx;

	if (argc != 2) {
		errx(EXIT_FAILURE, "usage: %s <core>", argv[0]);
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
		errx(EXIT_FAILURE, "ELF library initialization failed: %s", elf_errmsg(-1));
	}

	if ((fd = open(argv[1], O_RDONLY, 0)) == -1) {
		err(EXIT_FAILURE, "open \"%s\" failed", argv[1]);
	}

	if ((e = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
		errx(EXIT_FAILURE, "elf_begin() failed: %s", elf_errmsg(-1));
	}

	if (elf_kind(e) != ELF_K_ELF) {
		errx(EXIT_FAILURE, "%s is not an ELF object.", argv[1]);
	}

	if (elf_getshdrstrndx(e, &shstrndx) != 0) {
		errx(EXIT_FAILURE, "elf_getshdrstrndx() failed: %s", elf_errmsg(-1));
	}

	scn = NULL;
	for (scn = NULL; (scn = elf_nextscn(e, scn)) != NULL;) {
		char *name;

		if (gelf_getshdr(scn, &shdr) != &shdr) {
			errx(EXIT_FAILURE, "gelf_getshdr() failed: %s", elf_errmsg(-1));
		}

		if ((name = elf_strptr(e, shstrndx, shdr.sh_name)) == NULL) {
			errx(EXIT_FAILURE, "elf_strptr() failed: %s", elf_errmsg(-1));
		}

		printf("section %zd: %s\n", elf_ndxscn(scn), name);
	}

	elf_end(e);
	close(fd);

	exit(EXIT_SUCCESS);
}
