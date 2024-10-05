// Copyright (c) 2022 Oracle and/or its affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

#include "btf.h"
#include "drgn.h"
#include "lazy_object.h"
#include "memory_reader.h"
#include "log.h"
#include "platform.h"
#include "program.h"
#include "symbol.h"
#include "type.h"

const char *kind_names[NR_BTF_KINDS] = {
	[BTF_KIND_UNKN] = "UNKN",
	[BTF_KIND_INT] = "INT",
	[BTF_KIND_PTR] = "PTR",
	[BTF_KIND_ARRAY] = "ARRAY",
	[BTF_KIND_STRUCT] = "STRUCT",
	[BTF_KIND_UNION] = "UNION",
	[BTF_KIND_ENUM] = "ENUM",
	[BTF_KIND_FWD] = "FWD",
	[BTF_KIND_TYPEDEF] = "TYPEDEF",
	[BTF_KIND_VOLATILE] = "VOLATILE",
	[BTF_KIND_CONST] = "CONST",
	[BTF_KIND_RESTRICT] = "RESTRICT",
	[BTF_KIND_FUNC] = "FUNC",
	[BTF_KIND_FUNC_PROTO] = "FUNC_PROTO",
	[BTF_KIND_VAR] = "VAR",
	[BTF_KIND_DATASEC] = "DATASEC",
	[BTF_KIND_FLOAT] = "FLOAT",
	[BTF_KIND_DECL_TAG] = "DECL_TAG",
	[BTF_KIND_TYPE_TAG] = "TYPE_TAG",
	[BTF_KIND_ENUM64] = "ENUM64",
};

DEFINE_VECTOR(type_vector, struct btf_type *);

// Structures to efficiently map a string name to a list of candidate type
// entries. Each name entry is 16 bytes and it can represent either:
// 1. A type with a given name (e.g. a typedef foo, or struct foo)
// 2. A function or variable with a given name
//    In the case of variables, "addr" gets populated by the DATASEC.
// 3. An enumerator, in which case type_id points to the enum type, "val" gets
//    populated by the enumerator value, and is_enum is set to 1.
struct name_entry {
	union {
		uint64_t addr;
		uint64_t index;
	};
	uint32_t type_id;
	uint16_t unused; // will store a reference to the module BTF
	uint8_t kind;
	unsigned int is_enum : 1;

	// For variables: set to 1 if the address resolved via DATASEC
	unsigned int is_present : 1;
};
DEFINE_VECTOR(namelist, struct name_entry);
DEFINE_HASH_MAP(name_map, const char *, struct namelist,
		c_string_key_hash_pair, c_string_key_eq);

struct drgn_prog_btf {
	struct drgn_program *prog;

	/**
	 * Length of the BTF buffer in bytes.
	 */
	size_t len;

	/**
	 * Points to the beginning of the BTF buffer.
	 */
	union {
		void *ptr;
		struct btf_header *hdr;
	};

	/**
	 * Pointer within the buffer to the "type" section.
	 */
	union {
		void *type;
		struct btf_type *tp;
	};

	/**
	 * Pointer within the buffer to the "strings" section.
	 */
	char *str;

	/**
	 * Array allowing us to map BTF type_id indexes to their location within
	 * the "type" section. This could certainly be compressed or optimized,
	 * but for now it is fine.
	 */
	struct type_vector index;
	struct name_map htab;

	/**
	 * Array which caches the result of drgn_btf_type_create().
	 */
	struct drgn_type **cache;

	int refcount; // counts number of registrations
	struct drgn_type_finder_ops tfind;
	struct drgn_object_finder_ops ofind;
};

static inline uint32_t btf_kind(uint32_t info)
{
	return (info & 0x1F000000) >> 24;
}

static inline uint16_t btf_vlen(uint32_t info)
{
	return info & 0xFFFF;
}

static inline uint32_t btf_kind_flag(uint32_t info)
{
	return info & (1 << 31);
}

/**
 * Return the next btf_type entry after this one. In order to do this we must
 * add the offset of any supplemental data which follows this entry.
 */
static struct btf_type *btf_next(struct btf_type *tp)
{
	uintptr_t next = (uintptr_t)&tp[1];

	switch (btf_kind(tp->info)) {
	case BTF_KIND_INT:
		next += sizeof(uint32_t);
		break;

	case BTF_KIND_ARRAY:
		next += sizeof(struct btf_array);
		break;

	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
		next += btf_vlen(tp->info) * sizeof(struct btf_member);
		break;

	case BTF_KIND_ENUM:
		next += btf_vlen(tp->info) * sizeof(struct btf_enum);
		break;

	case BTF_KIND_FUNC_PROTO:
		next += btf_vlen(tp->info) * sizeof(struct btf_param);
		break;

	case BTF_KIND_VAR:
		next += sizeof(struct btf_var);
		break;

	case BTF_KIND_DATASEC:
		next += btf_vlen(tp->info) * sizeof(struct btf_var_secinfo);
		break;

	case BTF_KIND_DECL_TAG:
		next += sizeof(struct btf_decl_tag);
		break;

	case BTF_KIND_ENUM64:
		next += btf_vlen(tp->info) * sizeof(struct btf_enum64);
		break;

	case BTF_KIND_PTR:
	case BTF_KIND_FWD:
	case BTF_KIND_TYPEDEF:
	case BTF_KIND_VOLATILE:
	case BTF_KIND_CONST:
	case BTF_KIND_RESTRICT:
	case BTF_KIND_FUNC:
	case BTF_KIND_FLOAT:
	case BTF_KIND_TYPE_TAG:
		break; // no extra data

	default:
		UNREACHABLE();
	}
	return (struct btf_type *)next;
}

/**
 * Return true if this type pointer is past the end of the BTF type buffer.
 */
static inline bool btf_type_end(struct drgn_prog_btf *bf, struct btf_type *tp)
{
	return ((void *)tp - bf->type) >= bf->hdr->type_len;
}

/**
 * Given an offset, return a string from the BTF string section.
 */
static const char *btf_str(struct drgn_prog_btf *bf, uint32_t off)
{
	assert(off < bf->hdr->str_len);
	return (const char *)&bf->str[off];
}

static bool index_name(struct drgn_prog_btf *bf, const char *name,
		       struct name_entry *value)
{
	struct hash_pair hp = name_map_hash(&name);
	struct name_map_iterator it =
		name_map_search_hashed(&bf->htab, &name, hp);
	if (it.entry && !namelist_append(&it.entry->value, value)) {
		return false;
	} else if (!it.entry) {
		struct name_map_entry entry;
		entry.key = name;
		namelist_init(&entry.value);
		if (!namelist_append(&entry.value, value) ||
		    name_map_insert_searched(&bf->htab, &entry, hp, NULL) == -1) {
			namelist_deinit(&entry.value);
			return false;
		}
	}
	return true;
}

static bool fixup_var(struct drgn_prog_btf *bf, const char *name,
		      uint32_t type_id, uint64_t addr)
{
	struct hash_pair hp = name_map_hash(&name);
	struct name_map_iterator it =
		name_map_search_hashed(&bf->htab, &name, hp);
	if (it.entry) {
		struct namelist *l = &it.entry->value;
		for (uint32_t i = 0; i < namelist_size(l); i++) {
			struct name_entry *e = namelist_at(l, i);
			if (e->type_id == type_id) {
				e->addr = addr;
				e->is_present = 1;
				return true;
			}
		}
	}
	return false;
}

static char *section_symbol_name(const char *name)
{
	if (strcmp(name, ".data..percpu") == 0)
		return strdup("__per_cpu_start");
	else if (strcmp(name, ".data") == 0)
		return strdup("_sdata");
	else if (strcmp(name, ".bss") == 0)
		return strdup("__bss_start");
	else if (strcmp(name, ".brk") == 0)
		return strdup("_brk_start");

	char *new = malloc(strlen(name) + sizeof("__start_"));
	if (!new)
		return NULL;

	strcpy(new, "__start_");
	int out = sizeof("__start_") - 1;
	int in = 0;
	while (name[in] == '.')
		in++;
	while (name[in]) {
		if (name[in] == '.')
			new[out] = '_';
		else
			new[out] = name[in];
		out++;
		in++;
	}
	new[out] = '\0';
	return new;
}

static struct drgn_error *find_section_base(struct drgn_program *prog,
					    const char *name,
					    uint64_t *ret)
{
	struct drgn_error *err;

	_cleanup_free_ char *section = section_symbol_name(name);
	if (!section)
		return &drgn_enomem;

	_cleanup_symbol_ struct drgn_symbol *sym = NULL;
	err = drgn_program_find_symbol_by_name(prog, section, &sym);
	if (err)
		return err;

	*ret = sym->address;
	return NULL;
}

/**
 * Index the BTF data for quick access by type ID.
 */
static struct drgn_error *drgn_btf_index(struct drgn_prog_btf *bf)
{
	struct btf_type *tp;
	for (tp = bf->tp; !btf_type_end(bf, tp); tp = btf_next(tp)) {
		uint32_t type_id = type_vector_size(&bf->index);
		if (!type_vector_append(&bf->index, &tp))
			return &drgn_enomem;

		const char *name = btf_str(bf, tp->name_off);
		struct name_entry value = {};
		value.kind = btf_kind(tp->info);
		value.type_id = type_id;

		// First, insert the name->type mapping into the hash.
		// Don't index BTF_KIND_DATASEC names: they aren't real
		// types.
		if (name && name[0] && value.kind != BTF_KIND_DATASEC
		    && !index_name(bf, name, &value))
			return &drgn_enomem;

		// Next, index the enumerators, if relevant.
		if (value.kind == BTF_KIND_ENUM || value.kind == BTF_KIND_ENUM64) {
			size_t count = btf_vlen(tp->info);
			uint32_t *entries = (uint32_t *)&tp[1];
			size_t scale = value.kind == BTF_KIND_ENUM ? 2 : 3;
			value.is_enum = 1;
			for (uint32_t i = 0; i < count; i++) {
				value.index = i;
				const char *enumname = btf_str(bf, entries[i * scale]);
				if (!index_name(bf, enumname, &value))
					return &drgn_enomem;
			}
		} else if (value.kind == BTF_KIND_DATASEC) {
			struct btf_var_secinfo *si = (struct btf_var_secinfo *)&tp[1];
			size_t count = btf_vlen(tp->info);
			uint64_t base;
			struct drgn_error *err =
				find_section_base(bf->prog, name, &base);

			// Not all sections base addresses will be found with a
			// corresponding symbol. Set a heuristic that it will be
			// an error if it is not an "init" section, or if the
			// section contains fewer than 10 variables.
			if (err == &drgn_not_found &&
				(count < 10 || strstr(name, "init")))
				continue;

			for (uint32_t i = 0; i < count; i++) {
				// We need the variable name to do the hash lookup
				struct btf_type *var = *type_vector_at(&bf->index, si[i].type);
				const char *varname = btf_str(bf, var->name_off);
				if (!fixup_var(bf, varname, si[i].type, base + si[i].offset))
					return drgn_error_format(
						DRGN_ERROR_OTHER,
						"cannot find variable from DATASEC '%s' (id: %u) (section '%s')",
						varname, si[i].type, name);
			}
		}
	}

	/*
	struct name_map_iterator it = name_map_first(&bf->htab);
	printf("BTF NAME INDEX\n");
	while (it.entry) {
		printf(" => \"%s\"\n", it.entry->key);
		for (int i = 0; i < namelist_size(&it.entry->value); i++) {
			struct name_entry *e = namelist_at(&it.entry->value, i);
			if (e->is_enum)
				printf("    [%06u] ENUM member\n", e->type_id);
			else
				printf("    [%06u] %s\n", e->type_id, kind_names[e->kind]);
			if (i > 20) {
				printf("    ... (%d more)\n", i - 20);
				break;
			}
		}
		it = name_map_next(it);
	}
	*/
	return NULL;
}

static bool kind_match(uint64_t drgn_flags, struct btf_type *tp)
{
	int kind = btf_kind(tp->info);
	uint32_t int_info;
	switch (kind) {
	case BTF_KIND_INT:
		int_info = *(uint32_t *)(tp + 1);
		if (BTF_INT_BOOL & int_info)
			return drgn_flags & (1 << DRGN_TYPE_BOOL);
		else
			return drgn_flags & (1 << DRGN_TYPE_INT);
	case BTF_KIND_PTR:
		return drgn_flags & (1 << DRGN_TYPE_POINTER);
	case BTF_KIND_ARRAY:
		return drgn_flags & (1 << DRGN_TYPE_ARRAY);
	case BTF_KIND_STRUCT:
		return drgn_flags & (1 << DRGN_TYPE_STRUCT);
	case BTF_KIND_UNION:
		return drgn_flags & (1 << DRGN_TYPE_UNION);
	case BTF_KIND_ENUM:
	case BTF_KIND_ENUM64:
		return drgn_flags & (1 << DRGN_TYPE_ENUM);
	case BTF_KIND_TYPEDEF:
		return drgn_flags & (1 << DRGN_TYPE_TYPEDEF);
	default:
		return false;
	}
}

/**
 * Follow the linked list of BTF qualifiers, combining them into a single
 * drgn_qualifiers, ending at the first non-qualifier type entry.
 * @param idx Starting index, which may be a qualifier
 * @param[out] ret Location to store the index of the first non-qualifier
 * @returns drgn_qualifiers with all relevant bits set
 */
static enum drgn_qualifiers
drgn_btf_resolve_qualifiers(struct drgn_prog_btf *bf, uint32_t idx,
			    uint32_t *ret)
{
	enum drgn_qualifiers qual = 0;

	while (idx) {
		struct btf_type *tp = *type_vector_at(&bf->index, idx);
		switch (btf_kind(tp->info)) {
		case BTF_KIND_CONST:
			qual |= DRGN_QUALIFIER_CONST;
			break;
		case BTF_KIND_RESTRICT:
			qual |= DRGN_QUALIFIER_RESTRICT;
			break;
		case BTF_KIND_VOLATILE:
			qual |= DRGN_QUALIFIER_VOLATILE;
			break;
		default:
			goto out;
		}
		idx = tp->type;
	}
out:
	*ret = idx;
	return qual;
}

/**
 * Helper for struct layouts. Given a type index, find the concrete type it
 * corresponds to. If it is an integer type kind, use the encoded bit size and
 * offest information to augment the values which were passed into this
 * function. Otherwise, leaves the values unmodified.
 * @param idx Index of a compound type member
 * @param[out] offset_ret Caller passes in a pointer to the currently computed
 *   offset. This may be adjusted by an integer type's BTF_INT_OFFSET value.
 * @param[out] bit_size_ret Caller passes in a pointer to the bit_size. This is
 *   normally set to zero. If the member is an integer type kind, then the bit
 *   size is overwritten by the value contained in BTF_INT_BITS.
 * @return NULL on success. Could fail if the member's type kind in invalid.
 */
static struct drgn_error *
drgn_btf_bit_field_size(struct drgn_prog_btf *bf, uint32_t idx,
			uint64_t *offset_ret, uint64_t *bit_size_ret)
{
	uint32_t val;
	for (;;) {
		struct btf_type *tp = *type_vector_at(&bf->index, idx);
		switch (btf_kind(tp->info)) {
		/* Skip qualifiers and typedefs to get to concrete types */
		case BTF_KIND_CONST:
		case BTF_KIND_RESTRICT:
		case BTF_KIND_VOLATILE:
		case BTF_KIND_TYPEDEF:
			idx = tp->type;
			break;
		case BTF_KIND_INT:
			val = *(uint32_t *)&tp[1];
			if (BTF_INT_OFFSET(val)) {
				*offset_ret += BTF_INT_OFFSET(val);
			}
			*bit_size_ret = BTF_INT_BITS(val);
			return NULL;
		case BTF_KIND_PTR:
		case BTF_KIND_ARRAY:
		case BTF_KIND_FLOAT:
		case BTF_KIND_STRUCT:
		case BTF_KIND_UNION:
		case BTF_KIND_ENUM:
		case BTF_KIND_FUNC_PROTO:
			return NULL;
		default:
			return drgn_error_create(
				DRGN_ERROR_OTHER,
				"invalid BTF type, looking for sized"
			);
		}
	}
}

static struct drgn_error *
drgn_btf_type_create(struct drgn_prog_btf *bf, uint32_t idx,
		     struct drgn_qualified_type *ret);
static struct drgn_error *
drgn_type_from_btf(uint64_t flags, const char *name,
		   size_t name_len, const char *filename,
		   void *arg, struct drgn_qualified_type *ret);

static struct drgn_error *
drgn_int_type_from_btf(struct drgn_prog_btf *bf, struct btf_type *tp,
		       struct drgn_type **ret)
{
	uint32_t info;
	bool _signed, is_bool;
	const char *name = btf_str(bf, tp->name_off);

	info = *(uint32_t *)(tp + 1);
	if (BTF_INT_OFFSET(info))
		return drgn_error_create(
			DRGN_ERROR_OTHER,
			"int encoding at non-zero offset not supported"
		);
	_signed = BTF_INT_SIGNED & BTF_INT_ENCODING(info);
	is_bool = BTF_INT_BOOL & BTF_INT_ENCODING(info);
	if (is_bool)
		return drgn_bool_type_create(bf->prog, name, tp->size,
					     DRGN_PROGRAM_ENDIAN,
					     &drgn_language_c, ret);
	else
		return drgn_int_type_create(bf->prog, name, tp->size, _signed,
					    DRGN_PROGRAM_ENDIAN,
					    &drgn_language_c, ret);
}

static struct drgn_error *
drgn_pointer_type_from_btf(struct drgn_prog_btf *bf, struct btf_type *tp,
			   struct drgn_type **ret)
{
	struct drgn_qualified_type pointed;
	struct drgn_error *err = NULL;

	err = drgn_btf_type_create(bf, tp->type, &pointed);

	if (err)
		return err;

	// TODO: pointer size could probably be determined in a more robust way
	int pointer_size = drgn_platform_is_64_bit(&bf->prog->platform) ? 8 : 4;
	return drgn_pointer_type_create(bf->prog, pointed, pointer_size,
					DRGN_PROGRAM_ENDIAN, &drgn_language_c,
					ret);
}

static struct drgn_error *
drgn_typedef_type_from_btf(struct drgn_prog_btf *bf, struct btf_type *tp,
			   struct drgn_type **ret)
{
	struct drgn_qualified_type aliased;
	struct drgn_error *err;
	const char *name = btf_str(bf, tp->name_off);

	err = drgn_btf_type_create(bf, tp->type, &aliased);
	if (err)
		return err;

	return drgn_typedef_type_create(bf->prog, name, aliased,
					&drgn_language_c, ret);
}

struct drgn_btf_member_thunk_arg {
	struct btf_member *member;
	struct drgn_prog_btf *bf;
	uint64_t bit_field_size;
};

static struct drgn_error *
drgn_btf_member_thunk_fn(struct drgn_object *res, void *arg_)
{
	struct drgn_btf_member_thunk_arg *arg = arg_;
	struct drgn_error *err;

	if (res) {
		struct drgn_qualified_type qualified_type;
		err = drgn_btf_type_create(arg->bf, arg->member->type,
					   &qualified_type);
		if (err)
			return err;
		err = drgn_object_set_absent(res, qualified_type,
					     DRGN_ABSENCE_REASON_OTHER,
					     arg->bit_field_size);
		if (err)
			return err;
	}
	free(arg);
	return NULL;
}

static struct drgn_error *
drgn_compound_type_from_btf(struct drgn_prog_btf *bf, struct btf_type *tp,
			    struct drgn_type **ret)
{
	struct drgn_compound_type_builder builder;
	struct btf_member *members = (struct btf_member *)&tp[1];
	size_t vlen = btf_vlen(tp->info);
	enum drgn_type_kind kind = DRGN_TYPE_STRUCT;
	bool flag_bitfield_size_in_offset = btf_kind_flag(tp->info);
	struct drgn_error *err;
	const char *tag = NULL;

	if (btf_kind(tp->info) == BTF_KIND_UNION)
		kind = DRGN_TYPE_UNION;

	if (tp->name_off)
		tag = btf_str(bf, tp->name_off);

	drgn_compound_type_builder_init(&builder, bf->prog, kind);
	for (size_t i = 0; i < vlen; i++) {
		struct drgn_btf_member_thunk_arg *thunk_arg =
			malloc(sizeof(*thunk_arg));
		uint64_t bit_offset;
		const char *name = NULL;
		if (!thunk_arg) {
			err = &drgn_enomem;
			goto out;
		}
		thunk_arg->member = &members[i];
		thunk_arg->bf = bf;
		thunk_arg->bit_field_size = 0;
		if (flag_bitfield_size_in_offset) {
			bit_offset = BTF_MEMBER_BIT_OFFSET(members[i].offset);
			thunk_arg->bit_field_size =
				BTF_MEMBER_BITFIELD_SIZE(members[i].offset);
		} else {
			bit_offset = members[i].offset;
			err = drgn_btf_bit_field_size(bf, members[i].type,
						      &bit_offset,
						      &thunk_arg->bit_field_size);
			if (err)
				goto out;
		}
		if (members[i].name_off)
			name = btf_str(bf, members[i].name_off);

		union drgn_lazy_object member_object;
		drgn_lazy_object_init_thunk(&member_object, bf->prog,
					    drgn_btf_member_thunk_fn, thunk_arg);

		err = drgn_compound_type_builder_add_member(&builder,
							    &member_object,
							    name, bit_offset);
		if (err) {
			drgn_lazy_object_deinit(&member_object);
			goto out;
		}
	}
	err = drgn_compound_type_create(&builder, tag, tp->size, true,
					&drgn_language_c, ret);
	if (!err)
		return NULL;
out:
	drgn_compound_type_builder_deinit(&builder);
	return err;
}

static struct drgn_error *
drgn_array_type_from_btf(struct drgn_prog_btf *bf, struct btf_type *tp,
			 struct drgn_type **ret)
{
	struct btf_array *arr = (struct btf_array *)&tp[1];
	struct drgn_error *err;
	struct drgn_qualified_type qt;

	err = drgn_btf_type_create(bf, arr->type, &qt);
	if (err)
		return err;

	if (arr->nelems)
		return drgn_array_type_create(bf->prog, qt, arr->nelems,
					      &drgn_language_c, ret);
	else
		return drgn_incomplete_array_type_create(bf->prog, qt,
							 &drgn_language_c, ret);
}

static struct drgn_error *
compatible_int(struct drgn_program *prog, bool signed_, uint64_t size, struct drgn_type **ret)
{
	// drgn won't allow an anonymous type, but BTF doesn't give us the
	// underlying type ID for an enum. So we need to make one up, and we
	// need to invent a name for it. Since BTF is kernel-specific, we'll use
	// the "{su}{8,16,32,64}" names. However, in reality, those are typedefs
	// in the kernel. This shouldn't really cause confusion, since you can't
	// lookup these integers by name.
	static const char *names[] = {
		"u8", "u16", "u32", "u64", "s8", "s16", "s32", "s64",
	};
	int name_index = signed_ ? 4 : 0;
	switch (size) {
	case 1:
		name_index += 0;
		break;
	case 2:
		name_index += 1;
		break;
	case 4:
		name_index += 2;
		break;
	case 8:
		name_index += 3;
		break;
	default:
		return drgn_error_format(
			DRGN_ERROR_OTHER, "invalid BTF enum size: %" PRIu64, size);
	}
	return drgn_int_type_create(prog, names[name_index], size, signed_, DRGN_PROGRAM_ENDIAN,
				    &drgn_language_c, ret);
}

static struct drgn_error *
drgn_enum_type_from_btf(struct drgn_prog_btf *bf, struct btf_type *tp,
			struct drgn_type **ret)
{
	struct drgn_error *err;
	struct drgn_enum_type_builder builder;
	const char *name = NULL;
	size_t count = btf_vlen(tp->info);
	bool signed_ = BTF_INFO_KFLAG(tp->info);
	struct drgn_type *type;

	if (tp->name_off)
		name = btf_str(bf, tp->name_off);

	if (!count)
		/* no enumerators, incomplete type */
		return drgn_incomplete_enum_type_create(bf->prog, name,
							&drgn_language_c, ret);

	drgn_enum_type_builder_init(&builder, bf->prog);
	struct btf_enum *enum32 = (struct btf_enum *)&tp[1];
	struct btf_enum64 *enum64 = (struct btf_enum64 *)&tp[1];
	bool is_enum64 = btf_kind(tp->info) == BTF_KIND_ENUM64;
	for (size_t i = 0; i < count; i++) {
		const char *mname;
		union {uint64_t u; int64_t s; } val;
		if (is_enum64) {
			mname = btf_str(bf, enum64[i].name_off);
			// Sign extension is already done, just assemble this
			// into the unsigned integer field and let the union
			// reinterpret it as necessary.
			val.u = (uint64_t)enum64[i].val_hi32 << 32;
			val.u |= (uint64_t)enum64[i].val_lo32;
		} else {
			mname = btf_str(bf, enum32[i].name_off);
			// For a signed value, do sign extension. For unsigned
			// values, don't.
			if (signed_)
				val.s = enum32[i].val;
			else
				val.u = enum32[i].val;
		}
		if (signed_)
			err = drgn_enum_type_builder_add_signed(&builder,
								mname,
								val.s);
		else
			err = drgn_enum_type_builder_add_unsigned(&builder,
								  mname,
								  val.u);
		if (err)
			goto out;
	}
	err = compatible_int(bf->prog, signed_, tp->size, &type);
	if (err)
		goto out;

	err = drgn_enum_type_create(&builder, name, type,
				    &drgn_language_c, ret);
	if (!err)
		return NULL;
out:
	drgn_enum_type_builder_deinit(&builder);
	return err;
}

struct drgn_btf_param_thunk_arg {
	struct btf_param *param;
	struct drgn_prog_btf *bf;
};

static struct drgn_error *
drgn_btf_param_thunk_fn(struct drgn_object *res, void *arg_)
{
	struct drgn_btf_param_thunk_arg *arg = arg_;
	struct drgn_error *err;

	if (res) {
		struct drgn_qualified_type qualified_type;

		err = drgn_btf_type_create(arg->bf, arg->param->type,
					   &qualified_type);
		if (err)
			return err;

		err = drgn_object_set_absent(res, qualified_type,
					     DRGN_ABSENCE_REASON_OTHER, 0);
		if (err)
			return err;
	}
	free(arg);
	return NULL;
}

static struct drgn_error *
drgn_func_proto_type_from_btf(struct drgn_prog_btf *bf, struct btf_type *tp,
			      struct drgn_type **ret)
{
	struct drgn_error *err = NULL;
	struct drgn_function_type_builder builder;
	bool is_variadic = false;
	struct drgn_qualified_type return_type;
	size_t num_params = btf_vlen(tp->info);
	struct btf_param *params = (struct btf_param *)&tp[1];

	err = drgn_btf_type_create(bf, tp->type, &return_type);
	if (err)
		return err;

	drgn_function_type_builder_init(&builder, bf->prog);
	for (size_t i = 0; i < num_params; i++) {
		const char *name = NULL;
		union drgn_lazy_object param_object;
		struct drgn_btf_param_thunk_arg *arg;

		if (i + 1 == num_params && !params[i].name_off
		    && !params[i].type) {
			is_variadic = true;
			break;
		}
		name = btf_str(bf, params[i].name_off);

		arg = malloc(sizeof(*arg));
		if (!arg) {
			err = &drgn_enomem;
			goto out;
		}
		arg->bf = bf;
		arg->param = &params[i];
		drgn_lazy_object_init_thunk(&param_object, bf->prog,
					    drgn_btf_param_thunk_fn, arg);
		err = drgn_function_type_builder_add_parameter(&builder,
							       &param_object,
							       name);
		if (err) {
			free(arg);
			goto out;
		}
	}
	err = drgn_function_type_create(&builder, return_type, is_variadic,
					&drgn_language_c, ret);
	if (!err)
		return NULL;
out:
	drgn_function_type_builder_deinit(&builder);
	return err;
}

/**
 * Create a BTF type given its index within the the type buffer.
 *
 * This is the main workhorse function for loading BTF types into drgn. It
 * assumes you've already looked up the name for a type and resolved it into a
 * type_id / idx.
 *
 * All struct drgn_type created by this function are cached, but qualifiers are
 * not, since they are trivial to resolve each time.
 *
 * @param bf Pointer to BTF registry
 * @param idx Index of type in the type section
 * @param[out] ret On success, set to the qualified type
 * @returns NULL on success, or an error pointer
 */
static struct drgn_error *
drgn_btf_type_create(struct drgn_prog_btf *bf, uint32_t idx,
		     struct drgn_qualified_type *ret)
{
	struct drgn_error *err;
	enum drgn_qualifiers qual = drgn_btf_resolve_qualifiers(bf, idx, &idx);
	struct btf_type *tp = *type_vector_at(&bf->index, idx);

	if (bf->cache[idx]) {
		ret->qualifiers = qual;
		ret->type = bf->cache[idx];
		return NULL;
	}

	if (idx == 0) {
		ret->type = drgn_void_type(bf->prog, &drgn_language_c);
		ret->qualifiers = qual;
		bf->cache[idx] = ret->type;
		return NULL;
	}

	switch (btf_kind(tp->info)) {
	case BTF_KIND_INT:
		err = drgn_int_type_from_btf(bf, tp, &ret->type);
		break;
	case BTF_KIND_PTR:
		err = drgn_pointer_type_from_btf(bf, tp, &ret->type);
		break;
	case BTF_KIND_TYPEDEF:
		err = drgn_typedef_type_from_btf(bf, tp, &ret->type);
		break;
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
		err = drgn_compound_type_from_btf(bf, tp, &ret->type);
		break;
	case BTF_KIND_ARRAY:
		err = drgn_array_type_from_btf(bf, tp, &ret->type);
		break;
	case BTF_KIND_ENUM:
		err = drgn_enum_type_from_btf(bf, tp, &ret->type);
		break;
	case BTF_KIND_FUNC_PROTO:
		err = drgn_func_proto_type_from_btf(bf, tp, &ret->type);
		break;
	default:
		return &drgn_not_found;
	}
	if (!err) {
		ret->qualifiers = qual;
		bf->cache[idx] = ret->type;
	}
	return err;
}

/**
 * The drgn type finder for BTF.
 *
 * In order to lookup a type by name, we translate the type kind into a BTF type
 * kind, search for a type entry of the same name and kind, and then use the
 * general purpose drgn_btf_type_create() function to do the heavy lifting.
 * Since BTF encodes no information about compilation units or source filenames,
 * we always ignore @a filename.
 *
 * @param flags Bits set for each type kind drgn may want
 * @param name Type name to search
 * @param name_len Length of @a name (not including nul terminator)
 * @param filename Source filename of type (ignored)
 * @param arg Pointer to struct drgn_prog_btf of this program.
 * @param ret Output a qualified type
 * @returns NULL on success. On error, an appropriate struct drgn_error.
 */
static struct drgn_error *
drgn_type_from_btf(uint64_t flags, const char *name,
		   size_t name_len, const char *filename,
		   void *arg, struct drgn_qualified_type *ret)
{
	struct drgn_prog_btf *bf = arg;

	_cleanup_free_ char *name_copy = strndup(name, name_len);
	struct name_map_iterator it =
		name_map_search(&bf->htab, (const char **)&name_copy);
	if (!it.entry)
		return &drgn_not_found;

	struct namelist *l = &it.entry->value;
	for (int i = 0; i < type_vector_size(&bf->index); i++) {
		struct name_entry *entry = namelist_at(l, i);
		struct btf_type *tp = *type_vector_at(&bf->index, entry->type_id);

		if (!tp->name_off)
			continue;
		if (!kind_match(flags, tp))
			continue;

		return drgn_btf_type_create(bf, entry->type_id, ret);
	}
	return &drgn_not_found;
}

static struct drgn_error *
make_constant(struct drgn_prog_btf *bf, struct name_entry *entry,
	      struct drgn_object *ret)
{
	struct drgn_qualified_type qt;
	struct btf_type *tp = *type_vector_at(&bf->index, entry->type_id);
	union {uint64_t u; int64_t s; } val;
	bool signed_;

	size_t count = btf_vlen(tp->info);
	signed_ = BTF_INFO_KFLAG(tp->info);
	if (btf_kind(tp->info) == BTF_KIND_ENUM) {
		struct btf_enum *enum32 = (struct btf_enum *)&tp[1];
		if (signed_)
			val.s = enum32[entry->index].val;
		else
			val.u = enum32[entry->index].val;
	} else if (btf_kind(tp->info) == BTF_KIND_ENUM64) {
		struct btf_enum64 *enum64 = (struct btf_enum64 *)&tp[1];
		val.u = (uint64_t)enum64[entry->index].val_hi32 << 32;
		val.u |= (uint64_t)enum64[entry->index].val_lo32;
	} else {
		assert(false);
	}
	struct drgn_error *err = drgn_btf_type_create(bf, entry->type_id, &qt);
	if (err)
		return err;
	if (signed_)
		return drgn_object_set_signed(ret, qt, val.s, 0);
	else
		return drgn_object_set_unsigned(ret, qt, val.u, 0);
}

static struct drgn_error *
make_function(struct drgn_prog_btf *bf, const char *name, struct name_entry *entry,
	      struct drgn_object *ret)
{
	struct btf_type *tp = *type_vector_at(&bf->index, entry->type_id);

	_cleanup_symbol_ struct drgn_symbol *sym = NULL;
	struct drgn_error *err =
		drgn_program_find_symbol_by_name(bf->prog, name, &sym);
	if (err)
		return err;

	// TODO: is this check necessary?
	if (sym->kind != DRGN_SYMBOL_KIND_FUNC)
		return &drgn_not_found;

	struct drgn_qualified_type qt;
	err = drgn_btf_type_create(bf, tp->type, &qt);
	if (err) {
		return err;
	}
	return drgn_object_set_reference(ret, qt, sym->address, 0, 0);
}

static struct drgn_error *
make_variable(struct drgn_prog_btf *bf, const char *name, struct name_entry *entry,
	      struct drgn_object *ret)
{

	if (!entry->is_present)
		return drgn_error_format(DRGN_ERROR_OTHER,
					 "address information for \"%s\" is not present in a BTF DATASEC",
					 name);

	struct btf_type *tp = *type_vector_at(&bf->index, entry->type_id);
	struct drgn_qualified_type qt;
	struct drgn_error *err = drgn_btf_type_create(bf, tp->type, &qt);
	if (err)
		return err;
	return drgn_object_set_reference(ret, qt, entry->addr, 0, 0);
}

static struct drgn_error *drgn_btf_object_find(
	const char *name, size_t name_len, const char *filename,
	enum drgn_find_object_flags flags, void *arg, struct drgn_object *ret)
{
	struct drgn_prog_btf *bf = arg;
	struct drgn_program *prog = bf->prog;
	_cleanup_free_ char *name_copy = strndup(name, name_len);
	struct name_map_iterator it =
		name_map_search(&bf->htab, (const char **)&name_copy);
	if (!it.entry)
		return &drgn_not_found;

	struct namelist *l = &it.entry->value;
	for (int i = 0; i < namelist_size(l); i++) {
		struct name_entry *entry = namelist_at(l, i);
		if (entry->is_enum && (flags & DRGN_FIND_OBJECT_CONSTANT)) {
			return make_constant(bf, entry, ret);
		} else if (entry->kind == BTF_KIND_VAR &&
			   (flags & DRGN_FIND_OBJECT_VARIABLE)) {
			return make_variable(bf, name, entry, ret);
		} else if (entry->kind == BTF_KIND_FUNC &&
			   (flags & DRGN_FIND_OBJECT_FUNCTION)) {
			return make_function(bf, name, entry, ret);
		}
	}
	return &drgn_not_found;
}

static void drgn_btf_destroy(struct drgn_prog_btf *bf)
{
	// The name map values are a dynamically allocated vector of entries,
	// free them before deinit.
	struct name_map_iterator it = name_map_first(&bf->htab);
	while (it.entry) {
		namelist_deinit(&it.entry->value);
		it = name_map_next(it);
	}
	name_map_deinit(&bf->htab);
	free(bf->cache);
	free(bf->ptr);
	type_vector_deinit(&bf->index);
	free(bf);
}

static void drgn_btf_decref(void *arg)
{
	struct drgn_prog_btf *bf = arg;
	if (--bf->refcount)
		return;
	drgn_btf_destroy(bf);
}

/**
 * Initialize BTF type finders, given the address and length of the BTF section
 * within the program.
 */
static struct drgn_error *
drgn_btf_init(struct drgn_program *prog, uint64_t start, uint64_t bytes)
{
	struct drgn_prog_btf *pbtf;
	struct drgn_error *err = NULL;
	struct btf_type *tp = NULL;

	pbtf = calloc(1, sizeof(*pbtf));
	if (!pbtf) {
		err = &drgn_enomem;
		goto out_free;
	}

	pbtf->tfind.destroy = drgn_btf_decref;
	pbtf->tfind.find = drgn_type_from_btf;
	pbtf->ofind.destroy = drgn_btf_decref;
	pbtf->ofind.find = drgn_btf_object_find;
	type_vector_init(&pbtf->index);

	/* Insert NULL entry at index 0 for the void type */
	if (!type_vector_append(&pbtf->index, &tp)) {
		err = &drgn_enomem;
		goto out_free;
	}

	pbtf->ptr = malloc(bytes);
	if (!pbtf->ptr) {
		err = &drgn_enomem;
		goto out_free;
	}

	err = drgn_memory_reader_read(&prog->reader, pbtf->ptr, start, bytes,
				      false);
	if (err)
		goto out_free;


	if (pbtf->hdr->magic != BTF_MAGIC) {
		err = drgn_error_create(DRGN_ERROR_OTHER,
					"BTF header magic incorrect");
		goto out_free;
	}
	if (pbtf->hdr->hdr_len != sizeof(*pbtf->hdr)) {
		err = drgn_error_create(DRGN_ERROR_OTHER,
					"BTF header size mismatch");
		goto out_free;
	}
	if (pbtf->hdr->str_off + pbtf->hdr->str_len > bytes ||
	    pbtf->hdr->type_off + pbtf->hdr->type_len > bytes) {
		err = drgn_error_create(DRGN_ERROR_OTHER,
					"BTF offsets out of bounds");
		goto out_free;
	}
	pbtf->type = pbtf->ptr + pbtf->hdr->hdr_len + pbtf->hdr->type_off;
	pbtf->str = pbtf->ptr + pbtf->hdr->hdr_len + pbtf->hdr->str_off;
	pbtf->prog = prog;
	name_map_init(&pbtf->htab);
	err = drgn_btf_index(pbtf);
	if (err)
		goto out_free;

	pbtf->cache = calloc(type_vector_size(&pbtf->index), sizeof(pbtf->cache));
	if (!pbtf->cache) {
		err = &drgn_enomem;
		goto out_free;
	}

	err = drgn_program_register_type_finder(prog, "btf", &pbtf->tfind, pbtf,
						DRGN_HANDLER_REGISTER_ENABLE_LAST);
	if (err)
		goto out_free;
	pbtf->refcount++;

	err = drgn_program_register_object_finder(prog, "btf", &pbtf->ofind, pbtf,
						  DRGN_HANDLER_REGISTER_ENABLE_LAST);
	if (err)
		// Rare, but if we fail to register the object finder, after
		// already registering the type finder, then we're stuck.
		// We cannot unregister the type finder. The type finder's
		// destroy() callback will free the CTF info eventually, but in
		// the meantime we're in an in-between state. Log a warning.
		drgn_error_log_warning(prog, err, "BTF: failed to register object finder,"
				       "but type finder is already attached");
	else
		pbtf->refcount++;
	return NULL;
out_free:
	drgn_btf_destroy(pbtf);
	return err;
}

struct drgn_error *
drgn_program_load_btf(struct drgn_program *prog)
{
	_cleanup_symbol_ struct drgn_symbol *start = NULL, *stop = NULL;
	struct drgn_error *err =
		drgn_program_find_symbol_by_name(prog, "__start_BTF", &start);
	if (err)
		return err;

	err = drgn_program_find_symbol_by_name(prog, "__stop_BTF", &stop);
	if (err)
		return err;

	return drgn_btf_init(prog, start->address, stop->address - start->address);
}
