// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <elf.h>
#include <stdlib.h>
#include <string.h>

#include "drgn.h"
#include "symbol.h"
#include "util.h"

LIBDRGN_PUBLIC void drgn_symbol_destroy(struct drgn_symbol *sym)
{
	if (sym && sym->name_owned)
		/* Cast here is necessary - we want symbol users to
		 * never modify sym->name, but when we own the name,
		 * we must modify it by freeing it. */
		free((char *)sym->name);
	free(sym);
}

LIBDRGN_PUBLIC void drgn_symbols_destroy(struct drgn_symbol **syms,
					 size_t count)
{
	for (size_t i = 0; i < count; i++)
		drgn_symbol_destroy(syms[i]);
	free(syms);
}

void drgn_symbol_from_elf(const char *name, uint64_t address,
			  const GElf_Sym *elf_sym, struct drgn_symbol *ret)
{
	ret->name = name;
	ret->name_owned = false;
	ret->address = address;
	ret->size = elf_sym->st_size;
	int binding = GELF_ST_BIND(elf_sym->st_info);
	if (binding <= STB_WEAK || binding == STB_GNU_UNIQUE)
		ret->binding = binding + 1;
	else
		ret->binding = DRGN_SYMBOL_BINDING_UNKNOWN;
	int type = GELF_ST_TYPE(elf_sym->st_info);
	if (type <= STT_TLS || type == STT_GNU_IFUNC)
		ret->kind = type;
	else
		ret->kind = DRGN_SYMBOL_KIND_UNKNOWN;
}

LIBDRGN_PUBLIC const char *drgn_symbol_name(struct drgn_symbol *sym)
{
	return sym->name;
}

LIBDRGN_PUBLIC uint64_t drgn_symbol_address(struct drgn_symbol *sym)
{
	return sym->address;
}

LIBDRGN_PUBLIC uint64_t drgn_symbol_size(struct drgn_symbol *sym)
{
	return sym->size;
}


LIBDRGN_PUBLIC enum drgn_symbol_binding
drgn_symbol_binding(struct drgn_symbol *sym)
{
	return sym->binding;
}

LIBDRGN_PUBLIC enum drgn_symbol_kind drgn_symbol_kind(struct drgn_symbol *sym)
{
	return sym->kind;
}

LIBDRGN_PUBLIC bool drgn_symbol_eq(struct drgn_symbol *a, struct drgn_symbol *b)
{
	return (strcmp(a->name, b->name) == 0 && a->address == b->address &&
		a->size == b->size && a->binding == b->binding &&
		a->kind == b->kind);
}

DEFINE_VECTOR_FUNCTIONS(symbolp_vector);

LIBDRGN_PUBLIC struct drgn_error *
drgn_symbol_result_builder_add(struct drgn_symbol_result_builder *builder,
			       struct drgn_symbol *symbol)
{
	struct drgn_error *err = NULL;

	if (builder->flags & DRGN_FIND_SYM_ONE) {
		if (builder->single)
			drgn_symbol_destroy(builder->single);
		builder->single = symbol;
	} else if (!symbolp_vector_append(&builder->vector, &symbol)) {
		err = &drgn_enomem;
	}
	return err;
}

LIBDRGN_PUBLIC size_t
drgn_symbol_result_builder_count(const struct drgn_symbol_result_builder *builder)
{
	if (builder->flags & DRGN_FIND_SYM_ONE)
		return builder->single ? 1 : 0;
	else
		return symbolp_vector_size(&builder->vector);
}

void drgn_symbol_result_builder_init(struct drgn_symbol_result_builder *builder, int flags)
{
	memset(builder, 0, sizeof(*builder));
	builder->flags = flags;
	if (!(builder->flags & DRGN_FIND_SYM_ONE))
		symbolp_vector_init(&builder->vector);
}
void drgn_symbol_result_builder_destroy(struct drgn_symbol_result_builder *builder)
{
	if (builder->flags & DRGN_FIND_SYM_ONE) {
		drgn_symbol_destroy(builder->single);
	} else {
		vector_for_each(symbolp_vector, symbolp, &builder->vector)
			drgn_symbol_destroy(*symbolp);
		symbolp_vector_deinit(&builder->vector);
	}
}

struct drgn_symbol *
drgn_symbol_result_builder_single(struct drgn_symbol_result_builder *builder)
{
	return builder->single;
}

/** Return array result */
void drgn_symbol_result_builder_array(struct drgn_symbol_result_builder *builder,
				      struct drgn_symbol ***syms_ret, size_t *count_ret)
{
	symbolp_vector_steal(&builder->vector, syms_ret, count_ret);
}
