// Copyright (c) 2022 Oracle and/or its affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

#include "btf.h"
#include "drgn.h"
#include "lazy_object.h"
#include "memory_reader.h"
#include "program.h"
#include "symbol.h"

DEFINE_VECTOR(type_vector, struct btf_type *);

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

	/**
	 * Array which caches the result of drgn_btf_type_create().
	 */
	struct drgn_type **cache;
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
	void *next = (void *)tp + sizeof(struct btf_type);

	switch (btf_kind(tp->info)) {
	case BTF_KIND_INT:
		return next + sizeof(uint32_t);

	case BTF_KIND_ARRAY:
		return next + sizeof(struct btf_array);

	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
		return next + btf_vlen(tp->info) * sizeof(struct btf_member);

	case BTF_KIND_ENUM:
		return next + btf_vlen(tp->info) * sizeof(struct btf_enum);

	case BTF_KIND_FUNC_PROTO:
		return next + btf_vlen(tp->info) * sizeof(struct btf_param);

	case BTF_KIND_VAR:
		return next + sizeof(struct btf_var);

	case BTF_KIND_DATASEC:
		return next + btf_vlen(tp->info) * sizeof(struct btf_var_secinfo);

	case BTF_KIND_DECL_TAG:
		return next + sizeof(struct btf_decl_tag);

	case BTF_KIND_PTR:
	case BTF_KIND_FWD:
	case BTF_KIND_TYPEDEF:
	case BTF_KIND_VOLATILE:
	case BTF_KIND_CONST:
	case BTF_KIND_RESTRICT:
	case BTF_KIND_FUNC:
	case BTF_KIND_FLOAT:
	case BTF_KIND_TYPE_TAG:
		return next;

	default:
		UNREACHABLE();
	}
}

/**
 * Return true if this type pointer is past the end of the BTF type buffer.
 */
static inline bool btf_type_end(struct drgn_prog_btf *bf, struct btf_type *tp)
{
	return ((void *)tp - bf->type) >= bf->hdr->type_len;
}

/**
 * Index the BTF data for quick access by type ID.
 */
static struct drgn_error *drgn_btf_index(struct drgn_prog_btf *bf)
{
	struct btf_type *tp;
	for (tp = bf->tp; !btf_type_end(bf, tp); tp = btf_next(tp))
		if (!type_vector_append(&bf->index, &tp))
			return &drgn_enomem;
	return NULL;
}

/**
 * Given an offset, return a string from the BTF string section.
 */
const char *btf_str(struct drgn_prog_btf *bf, uint32_t off)
{
	assert(off < bf->hdr->str_len);
	return (const char *)&bf->str[off];
}

/**
 * Perform a linear search of the BTF type section for a type of given name and
 * kind.
 */
static uint32_t drgn_btf_lookup(struct drgn_prog_btf *bf, const char *name,
				size_t name_len, int desired_btf_kind)
{
	struct btf_type *tp;
	for (uint32_t i = 1; i < bf->index.size; i++) {
		tp = bf->index.data[i];
		if (btf_kind(tp->info) == desired_btf_kind &&
		    tp->name_off) {
			const char *bs = btf_str(bf, tp->name_off);
			if (strncmp(btf_str(bf, tp->name_off), name, name_len) == 0
			    && !bs[name_len])
				return i;
		}
	}
	return 0; /* void anyway */
}

static uint32_t drgn_btf_lookup_def(struct drgn_prog_btf *bf, const char *name,
				    size_t name_len)
{
	struct btf_type *tp;
	for (uint32_t i = 1; i < bf->index.size; i++) {
		tp = bf->index.data[i];
		int kind = btf_kind(tp->info);
		if ((kind == BTF_KIND_VAR || kind == BTF_KIND_FUNC) &&
		    tp->name_off) {
			const char *bs = btf_str(bf, tp->name_off);
			if (strncmp(btf_str(bf, tp->name_off), name, name_len) == 0
			    && !bs[name_len])
				return i;
		}
	}
	return 0; /* void anyway */
}

static uint32_t drgn_btf_lookup_enumval(struct drgn_prog_btf *bf, const char *name,
					size_t name_len, uint32_t *enumerator_ret)
{
	struct btf_type *tp;
	for (uint32_t i = 1; i < bf->index.size; i++) {
		tp = bf->index.data[i];
		if (btf_kind(tp->info) != BTF_KIND_ENUM)
			continue;
		struct btf_enum *enum_ = (struct btf_enum *)&tp[1];
		size_t count = btf_vlen(tp->info);
		for (uint32_t j = 0; j < count; j++) {
			const char *enumerator_name = btf_str(bf, enum_[j].name_off);
			if (strncmp(enumerator_name, name, name_len) == 0
			    && !enumerator_name[name_len]) {
				*enumerator_ret = j;
				return i;
			}
		}
	}
	return 0;
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
		struct btf_type *tp = bf->index.data[idx];
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
		struct btf_type *tp = bf->index.data[idx];
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
drgn_type_from_btf(enum drgn_type_kind kind, const char *name,
		   size_t name_len, const char *filename,
		   void *arg, struct drgn_qualified_type *ret);

static struct drgn_error *
drgn_int_type_from_btf(struct drgn_prog_btf *bf, struct btf_type *tp,
		       struct drgn_type **ret)
{
	uint32_t info;
	bool _signed, is_bool;
	struct drgn_error *rv;
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

	// TODO can't hardcode 8
	return drgn_pointer_type_create(bf->prog, pointed, 8,
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
drgn_enum_type_from_btf(struct drgn_prog_btf *bf, struct btf_type *tp,
			struct drgn_type **ret)
{
	struct btf_enum *enum_ = (struct btf_enum *)&tp[1];
	struct drgn_error *err;
	struct drgn_enum_type_builder builder;
	const char *name = NULL;
	struct drgn_qualified_type compatible_type;
	size_t count = btf_vlen(tp->info);

	if (tp->name_off)
		name = btf_str(bf, tp->name_off);

	if (!count)
		/* no enumerators, incomplete type */
		return drgn_incomplete_enum_type_create(bf->prog, name,
							&drgn_language_c, ret);

	// TODO: need 4-byte signed integer
	err = drgn_type_from_btf(DRGN_TYPE_INT, "int", 3, NULL, bf,
				 &compatible_type);
	if (err)
		return err;

	drgn_enum_type_builder_init(&builder, bf->prog);
	for (size_t i = 0; i < count; i++) {
		const char *mname = btf_str(bf, enum_[i].name_off);
		err = drgn_enum_type_builder_add_signed(&builder, mname,
							enum_[i].val);
		if (err)
			goto out;
	}
	err = drgn_enum_type_create(&builder, name, compatible_type.type,
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

		err = drgn_object_set_absent(res, qualified_type, 0);
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
	struct btf_type *tp = bf->index.data[idx];

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
 * Translate drgn's type kind enumeration into a constant used by BTF. For any
 * value which doesn't have a direct correspondence, return -1.
 * @param kind drgn type kind
 * @returns BTF type kind
 */
static int drgn_btf_kind(enum drgn_type_kind kind)
{
	switch (kind) {
	case DRGN_TYPE_INT:
	case DRGN_TYPE_BOOL:
		return BTF_KIND_INT;
	case DRGN_TYPE_TYPEDEF:
		return BTF_KIND_TYPEDEF;
	case DRGN_TYPE_STRUCT:
		return BTF_KIND_STRUCT;
	case DRGN_TYPE_UNION:
		return BTF_KIND_UNION;
	case DRGN_TYPE_POINTER:
		return BTF_KIND_PTR;
	case DRGN_TYPE_ARRAY:
		return BTF_KIND_ARRAY;
	case DRGN_TYPE_ENUM:
		return BTF_KIND_ENUM;
	case DRGN_TYPE_FUNCTION:
		return BTF_KIND_FUNC;
	default:
		return -1;
	}
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
 * @param kind The drgn type kind to search
 * @param name Type name to search
 * @param name_len Length of @a name (not including nul terminator)
 * @param filename Source filename of type (ignored)
 * @param arg Pointer to struct drgn_prog_btf of this program.
 * @param ret Output a qualified type
 * @returns NULL on success. On error, an appropriate struct drgn_error.
 */
static struct drgn_error *
drgn_type_from_btf(enum drgn_type_kind kind, const char *name,
		   size_t name_len, const char *filename,
		   void *arg, struct drgn_qualified_type *ret)
{
	uint32_t idx;
	struct drgn_prog_btf *bf = arg;
	int btf_kind = drgn_btf_kind(kind);

	if (btf_kind < 0)
		return &drgn_not_found;

	idx = drgn_btf_lookup(bf, name, name_len, btf_kind);
	if (!idx)
		return &drgn_not_found;

	return drgn_btf_type_create(bf, idx, ret);
}

/**
 * Initialize BTF type finders, given the address and length of the BTF section
 * within the program.
 */
struct drgn_error *drgn_btf_init(struct drgn_program *prog, uint64_t start,
				 uint64_t bytes)
{
	struct drgn_prog_btf *pbtf;
	struct drgn_error *err = NULL;
	struct btf_type *tp = NULL;

	pbtf = calloc(1, sizeof(*pbtf));
	if (!pbtf) {
		err = &drgn_enomem;
		goto out_free;
	}

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
	err = drgn_btf_index(pbtf);
	if (err)
		goto out_free;

	pbtf->cache = calloc(pbtf->index.size, sizeof(pbtf->cache));
	if (!pbtf->cache) {
		err = &drgn_enomem;
		goto out_free;
	}

	err = drgn_program_add_type_finder(prog, drgn_type_from_btf, pbtf);
	if (err)
		goto out_free;
	prog->btf = pbtf;
	return err;
out_free:
	free(pbtf->cache);
	free(pbtf->ptr);
	type_vector_deinit(&pbtf->index);
	free(pbtf);
	return err;
}

enum kallsyms_address_strategy {
	/** Address is simply the value of kallsyms_addresses[i] */
	KALLSYMS_ABSOLUTE,
	/** Address is kallsyms_offsets[i] + kallsyms_relative_base */
	KALLSYMS_BASE_RELATIVE,
	/** Positive address is absolute, negative is base relative */
	KALLSYMS_HYBRID,
};

struct kallsyms_registry {
	struct drgn_program *prog;
	enum kallsyms_address_strategy strategy;

	uint32_t num_syms;
	uint8_t *names;
	char *token_table;
	uint16_t *token_index;

	union {
		uint32_t *offsets;
		uint64_t *addresses;
	};
	uint64_t relative_base;
};

static const unsigned int KALLSYMS_MAX_LEN = 128;

static struct drgn_error *
kallsyms_copy_tables(struct kallsyms_registry *kr, struct vmcoreinfo *vi)
{
	struct drgn_error *err;
	const size_t token_index_size = (UINT8_MAX + 1) * sizeof(uint16_t);
	uint64_t last_token;
	size_t token_table_size, names_idx;
	char data;
	uint8_t len;

	// Read num_syms from vmcore
	//printf("Try reading num_syms from 0x%lx...\n", vi->kallsyms_num_syms);
	err = drgn_program_read_u32(kr->prog,
				    vi->kallsyms_num_syms,
				    false, &kr->num_syms);
	if (err)
		return err;
	//printf("num_syms = %u\n", kr->num_syms);

	// Read the constant-sized token_index table (256 entries)
	kr->token_index = malloc(token_index_size);
	if (!kr->token_index)
		return &drgn_enomem;
	err = drgn_program_read_memory(kr->prog, kr->token_index,
				       vi->kallsyms_token_index,
				       token_index_size, false);
	if (err)
		goto out;
	//printf("Read the token_index!\n");

	/*
	 * Find the end of the last token, so we get the overall length of
	 * token_table. Then copy the token_table into host memory.
	 */
	last_token = vi->kallsyms_token_table + kr->token_index[UINT8_MAX];
	do {
		err = drgn_program_read_u8(kr->prog, last_token, false,
					   (uint8_t *)&data);
		if (err)
			goto out;

		last_token++;
	} while (data);
	token_table_size = last_token - vi->kallsyms_token_table + 1;
	kr->token_table = malloc(token_table_size);
	if (!kr->token_table) {
		err = &drgn_enomem;
		goto out;
	}
	err = drgn_program_read_memory(kr->prog, kr->token_table,
				       vi->kallsyms_token_table,
				       token_table_size, false);
	if (err)
		goto out;
	//printf("Read the token_table (size %lu)\n", token_table_size);

	/* Now find the end of the names array by skipping through it, then copy
	 * that into host memory. */
	names_idx = 0;
	for (size_t i = 0; i < kr->num_syms; i++) {
		err = drgn_program_read_u8(kr->prog,
					   vi->kallsyms_names + names_idx,
					   false, &len);
		if (err)
			goto out;
		names_idx += len + 1;
	}
	kr->names = malloc(names_idx);
	if (!kr->names) {
		err = &drgn_enomem;
		goto out;
	}
	err = drgn_program_read_memory(kr->prog, kr->names,
				       vi->kallsyms_names,
				       names_idx, false);
	if (err)
		goto out;
	//printf("Read the names array (size %lu)!\n", names_idx);
	return NULL;
out:
	free(kr->token_table);
	free(kr->token_index);
	return err;
}

unsigned int
kallsyms_expand_symbol(struct kallsyms_registry *kr, unsigned int offset,
		       char *result, size_t maxlen, char *kind_ret)
{
	uint8_t *data = &kr->names[offset];
	unsigned int len = *data;
	bool skipped_first = false;

	offset += len + 1;
	data += 1;
	while (len) {
		char *token_ptr = &kr->token_table[kr->token_index[*data]];
		while (*token_ptr) {
			if (skipped_first) {
				if (maxlen <= 1)
					goto tail;
				*result = *token_ptr;
				result++;
				maxlen--;
			} else {
				if (kind_ret)
					*kind_ret = *token_ptr;
				skipped_first = true;
			}
			token_ptr++;
		}

		data++;
		len--;
	}

tail:
	*result = '\0';
	return offset;
}

static int
drgn_kallsyms_lookup(struct kallsyms_registry *kr, const char *name)
{
	char buf[KALLSYMS_MAX_LEN + 1];
	unsigned int off = 0;
	for (int i = 0; i < kr->num_syms; i++) {
		off = kallsyms_expand_symbol(kr, off, buf, sizeof(buf), NULL);
		if (strncmp(buf, name, sizeof(buf)) == 0)
			return i;
	}
	return -1;
}

static uint64_t
drgn_kallsyms_address_by(struct kallsyms_registry *kr, unsigned int offset,
			 enum kallsyms_address_strategy strategy)
{
	int32_t val;
	switch (strategy) {
	case KALLSYMS_ABSOLUTE:
		return kr->addresses[offset];
	case KALLSYMS_BASE_RELATIVE:
		return kr->relative_base + kr->offsets[offset];
	case KALLSYMS_HYBRID:
		val = (int32_t)kr->offsets[offset];
		if (val >= 0)
			return val;
		else
			return kr->relative_base - 1 - val;
	}
}

static uint64_t
drgn_kallsyms_address(struct kallsyms_registry *kr, unsigned int offset)
{
	return drgn_kallsyms_address_by(kr, offset, kr->strategy);
}

void drgn_kallsyms_deinit(struct kallsyms_registry *kr)
{
	free(kr->addresses);
	free(kr->names);
	free(kr->token_table);
	free(kr->token_index);
	free(kr);
}

struct drgn_error *drgn_kallsyms_load_btf(struct drgn_program *prog)
{
	struct kallsyms_registry *kr = prog->kallsyms;
	int index = drgn_kallsyms_lookup(kr, "__start_BTF");
	uint64_t start, end;
	if (index < 0) {
		return &drgn_not_found;
	}
	start = drgn_kallsyms_address(kr, index);
	index = drgn_kallsyms_lookup(kr, "__stop_BTF");
	if (index < 0) {
		return &drgn_not_found;
	}
	end = drgn_kallsyms_address(kr, index);
	//printf("__start_BTF=0x%lx, __stop_BTF=0x%lx\n", start, end);
	return drgn_btf_init(prog, start, end - start);
}

struct drgn_error *drgn_kallsyms_btf_finder(
	const char *name, size_t name_len, const char *filename,
	enum drgn_find_object_flags flags, void *arg, struct drgn_object *ret)
{
	struct drgn_error *err;
	struct drgn_program *prog = arg;
	struct drgn_prog_btf *bf = prog->btf;
	struct kallsyms_registry *kr = prog->kallsyms;
	uint32_t type_id = 0;
	struct drgn_qualified_type qualified_type;
	struct btf_type *tp;

	if (flags == DRGN_FIND_OBJECT_CONSTANT)
		goto check_enum;

	/*
	 * Search for variables or functions. These are of type VAR or FUNC in
	 * the BTF, they will have a name and their "type" field will point to
	 * the actual type of the var/func. We will find the corresponding
	 * symbol's address and construct an object in that way.
	 */
	type_id = drgn_btf_lookup_def(bf, name, name_len);
	if (!type_id)
		goto check_enum;

	int symbol_idx = drgn_kallsyms_lookup(kr, name);
	if (symbol_idx < 0)
		goto check_enum;
	uint64_t symbol_address = drgn_kallsyms_address(kr, symbol_idx);

	tp = bf->index.data[type_id];
	int kind = btf_kind(tp->info);
	if ((kind == BTF_KIND_VAR) && !(flags & DRGN_FIND_OBJECT_VARIABLE)) {
		goto check_enum;
	} else if ((kind == BTF_KIND_FUNC) && !(flags & DRGN_FIND_OBJECT_FUNCTION)) {
		goto check_enum;
	}

	err = drgn_btf_type_create(bf, tp->type, &qualified_type);
	if (err) {
		return err;
	}
	return drgn_object_set_reference(ret, qualified_type, symbol_address, 0, 0);

check_enum:
	/*
	 * Search for enumerators. These need a special search case because they
	 * are held within the "btf_enum" struct inside of each BTF enum entry.
	 * If we find a match, we can directly use the found type, and construct
	 * a value object instead of a reference.
	 */
	if (flags & DRGN_FIND_OBJECT_CONSTANT) {
		// First, we need to search for enumerators with this name.
		uint32_t enumerator;
		type_id = drgn_btf_lookup_enumval(bf, name, name_len, &enumerator);
		if (type_id) {
			printf("Found type_id=%u, enumerator=%u\n", type_id, enumerator);
			tp = bf->index.data[type_id];
			struct btf_enum *enum_ = (struct btf_enum *)&tp[1];
			err = drgn_btf_type_create(bf, type_id, &qualified_type);
			if (err)
				return err;
			return drgn_object_set_signed(ret, qualified_type, enum_[enumerator].val, 0);
		}
	}
	return &drgn_not_found;
}

void drgn_symbol_from_kallsyms(struct kallsyms_registry *kr, int index,
			       int offset, struct drgn_symbol *ret)
{
	char buf[KALLSYMS_MAX_LEN + 1];
	uint32_t btf_idx;
	struct drgn_prog_btf *bf = kr->prog->btf;
	struct btf_type *tp;
	kallsyms_expand_symbol(kr, offset, buf, sizeof(buf), NULL);
	ret->name = strdup(buf);
	ret->name_owned = true;
	ret->address = drgn_kallsyms_address(kr, index);
	ret->size = drgn_kallsyms_address(kr, index + 1) - ret->address;
	ret->binding = DRGN_SYMBOL_BINDING_GLOBAL;

	btf_idx = drgn_btf_lookup_def(bf, buf, strlen(buf));
	if (btf_idx) {
		tp = bf->index.data[btf_idx];
		int kind = btf_kind(tp->info);
		if (kind == BTF_KIND_FUNC)
			ret->kind = DRGN_SYMBOL_KIND_FUNC;
		else if (kind == BTF_KIND_VAR)
			ret->kind = DRGN_SYMBOL_KIND_OBJECT;
		else
			ret->kind = DRGN_SYMBOL_KIND_UNKNOWN;
	} else {
		ret->kind = DRGN_SYMBOL_KIND_UNKNOWN;
	}
}

bool drgn_kallsyms_lookup_address(struct kallsyms_registry *kr, uint64_t address,
				  struct drgn_symbol *ret)
{
	uint64_t begin = drgn_kallsyms_address(kr, 0);
	uint64_t end = drgn_kallsyms_address(kr, kr->num_syms - 1);
	int index = -1;
	int offset = 0;

	/* NB: technically, the end is a symbol too, with some size, and so
	 * using the end address here means that we could miss looking up an
	 * address within the last symbol's range. The kernel handles this by
	 * looking for the end of the section to use as the last address.
	 *
	 * We don't bother doing that here. The last symbol is likely just a
	 * marker (like _etext) or something else, and this code explicitly
	 * ignores it. This could be a mistake.
	 */
	if (address < begin || address > end)
		return false;

	for (int i = 1; i < kr->num_syms; i++) {
		uint64_t sym_addr = drgn_kallsyms_address(kr, i);
		if (address < sym_addr) {
			index = i - 1;
			break;
		}
		offset += kr->names[offset] + 1;
	}

	if (index == -1)
		return false;

	drgn_symbol_from_kallsyms(kr, index, offset, ret);
	return true;
}

struct drgn_error *drgn_kallsyms_init(struct drgn_program *prog,
				      struct vmcoreinfo *vi)
{
	//struct vmcoreinfo *vi = &prog->vmcoreinfo;
	struct drgn_error *err;
	struct kallsyms_registry *kr;

	if (!(vi->kallsyms_names && vi->kallsyms_token_table
	      && vi->kallsyms_token_index && vi->kallsyms_num_syms))
		return NULL;

	kr = calloc(1, sizeof(*kr));
	if (!kr)
		return &drgn_enomem;

	kr->prog = prog;
	err = kallsyms_copy_tables(kr, vi);
	if (err)
		goto out;

	if (vi->kallsyms_addresses) {
		printf("Found kallsyms_addresses, we must be KALLSYMS_ABSOLUTE\n");
		kr->strategy = KALLSYMS_ABSOLUTE;
		kr->addresses = malloc(kr->num_syms * sizeof(uint64_t));
		if (!kr->addresses) {
			err = &drgn_enomem;
			goto out;
		}
		err = drgn_program_read_memory(prog, kr->addresses,
					       vi->kallsyms_addresses,
					       kr->num_syms * sizeof(uint64_t),
					       false);
		if (err)
			goto out;
	} else if (vi->kallsyms_offsets && vi->kallsyms_relative_base
		   && vi->_stext) {
		//printf("Found kallsyms_offsets etc, loading offsets and determining strategy...\n");
		kr->offsets = malloc(kr->num_syms * sizeof(uint32_t));
		if (!kr->offsets) {
			err = &drgn_enomem;
			goto out;
		}
		err = drgn_program_read_memory(prog, kr->offsets,
					       vi->kallsyms_offsets,
					       kr->num_syms * sizeof(uint32_t),
					       false);
		if (err)
			goto out;
		err = drgn_program_read_u64(prog, vi->kallsyms_relative_base,
					    false, &kr->relative_base);
		if (err)
			goto out;

		/* Could be relative or hybrid, to test, let's read an address
		 * in both ways. Search for _stext
		 */
		int stext_index = drgn_kallsyms_lookup(kr, "_stext");
		if (stext_index < 0) {
			err = drgn_error_create(
				DRGN_ERROR_OTHER,
				"Could not find _stext symbol in kallsyms");
			goto out;
		}
		//printf("_stext_index=%d\n", stext_index);
		if (drgn_kallsyms_address_by(kr, stext_index, KALLSYMS_BASE_RELATIVE) == vi->_stext) {
			kr->strategy = KALLSYMS_BASE_RELATIVE;
		} else if (drgn_kallsyms_address_by(kr, stext_index, KALLSYMS_HYBRID) == vi->_stext) {
			kr->strategy = KALLSYMS_HYBRID;
		} else {
			err = drgn_error_create(
				DRGN_ERROR_OTHER,
				"Could not correctly compute _stext address");
			goto out;
		}
		//printf("Determined strategy %d\n", kr->strategy);
	} else {
		goto out;
	}
	prog->kallsyms = kr;
	return NULL;
out:
	drgn_kallsyms_deinit(kr);
	return err;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_load_internal_info(struct drgn_program *prog, struct vmcoreinfo *vi)
{
	struct drgn_error *err = drgn_kallsyms_init(prog, vi);
	if (err)
		return err;
	err = drgn_kallsyms_load_btf(prog);
	if (err)
		return err;
	return drgn_program_add_object_finder(prog, &drgn_kallsyms_btf_finder, prog);
}
