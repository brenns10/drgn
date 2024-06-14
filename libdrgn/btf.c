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
static const char *btf_str(struct drgn_prog_btf *bf, uint32_t off)
{
	assert(off < bf->hdr->str_len);
	return (const char *)&bf->str[off];
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
 * Perform a linear search of the BTF type section for a type of given name and
 * kind.
 */
static uint32_t drgn_btf_lookup(struct drgn_prog_btf *bf, const char *name,
				size_t name_len, uint64_t drgn_flags)
{
	struct btf_type *tp;
	for (uint32_t i = 1; i < type_vector_size(&bf->index); i++) {
		tp = *type_vector_at(&bf->index, i);

		if (!tp->name_off)
			continue;
		if (!kind_match(drgn_flags, tp))
			continue;

		const char *bs = btf_str(bf, tp->name_off);
		if (strncmp(bs, name, name_len) != 0 || bs[name_len])
			continue;
		return i;
	}
	return 0; /* void anyway */
}

static uint32_t drgn_btf_lookup_def(struct drgn_prog_btf *bf, const char *name,
				    size_t name_len)
{
	struct btf_type *tp;
	for (uint32_t i = 1; i < type_vector_size(&bf->index); i++) {
		tp = *type_vector_at(&bf->index, i);
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
	uint32_t idx;
	struct drgn_prog_btf *bf = arg;

	idx = drgn_btf_lookup(bf, name, name_len, flags);
	if (!idx)
		return &drgn_not_found;

	return drgn_btf_type_create(bf, idx, ret);
}

static struct drgn_error *
drgn_btf_lookup_enumval(struct drgn_prog_btf *bf, const char *name,
			size_t name_len, struct drgn_object *ret)
{
	struct drgn_qualified_type qt;
	struct drgn_error *err;
	uint32_t tid;
	struct btf_type *tp;
	union {uint64_t u; int64_t s; } val;
	bool signed_;

	for (tid = 1; tid < type_vector_size(&bf->index); tid++) {
		tp = *type_vector_at(&bf->index, tid);
		size_t count = btf_vlen(tp->info);
		signed_ = BTF_INFO_KFLAG(tp->info);
		if (btf_kind(tp->info) == BTF_KIND_ENUM) {
			struct btf_enum *enum32 = (struct btf_enum *)&tp[1];
			for (uint32_t j = 0; j < count; j++) {
				const char *s = btf_str(bf, enum32[j].name_off);
				if (strncmp(s, name, name_len) == 0 && !s[name_len]) {
					if (signed_)
						val.s = enum32[j].val;
					else
						val.u = enum32[j].val;
					goto found;
				}
			}
		}
		else if (btf_kind(tp->info) == BTF_KIND_ENUM64) {
			struct btf_enum64 *enum64 = (struct btf_enum64 *)&tp[1];
			for (uint32_t j = 0; j < count; j++) {
				const char *s = btf_str(bf, enum64[j].name_off);
				if (strncmp(s, name, name_len) == 0 && !s[name_len]) {
					val.u = (uint64_t)enum64[j].val_hi32 << 32;
					val.u |= (uint64_t)enum64[j].val_lo32;
					goto found;
				}
			}
		}
	}
	return &drgn_not_found;

found:
	err = drgn_btf_type_create(bf, tid, &qt);
	if (err)
		return err;
	if (signed_)
		return drgn_object_set_signed(ret, qt, val.s, 0);
	else
		return drgn_object_set_unsigned(ret, qt, val.u, 0);
}

static struct drgn_error *drgn_btf_object_find(
	const char *name, size_t name_len, const char *filename,
	enum drgn_find_object_flags flags, void *arg, struct drgn_object *ret)
{
	struct drgn_prog_btf *bf = arg;
	struct drgn_program *prog = bf->prog;
	_cleanup_symbol_ struct drgn_symbol *sym = NULL;

	if (flags == DRGN_FIND_OBJECT_CONSTANT)
		goto check_enum;

	/*
	 * Search for variables or functions. These are of type VAR or FUNC in
	 * the BTF, they will have a name and their "type" field will point to
	 * the actual type of the var/func. We will find the corresponding
	 * symbol's address and construct an object in that way.
	 */
	uint32_t type_id = drgn_btf_lookup_def(bf, name, name_len);
	if (!type_id)
		goto check_enum;

	struct drgn_error *err =
		drgn_program_find_symbol_by_name(prog, name, &sym);
	if (err)
		return err;

	struct btf_type *tp = *type_vector_at(&bf->index, type_id);
	int kind = btf_kind(tp->info);
	if ((kind == BTF_KIND_VAR) && !(flags & DRGN_FIND_OBJECT_VARIABLE)) {
		goto check_enum;
	} else if ((kind == BTF_KIND_FUNC) && !(flags & DRGN_FIND_OBJECT_FUNCTION)) {
		goto check_enum;
	}

	struct drgn_qualified_type qualified_type;
	err = drgn_btf_type_create(bf, tp->type, &qualified_type);
	if (err) {
		return err;
	}
	return drgn_object_set_reference(ret, qualified_type, sym->address, 0, 0);

check_enum:
	/*
	 * Search for enumerators. These need a special search case because they
	 * are held within the "btf_enum" struct inside of each BTF enum entry.
	 * If we find a match, we can directly use the found type, and construct
	 * a value object instead of a reference.
	 */
	if (flags & DRGN_FIND_OBJECT_CONSTANT)
		return drgn_btf_lookup_enumval(bf, name, name_len, ret);
	return &drgn_not_found;
}

static void drgn_btf_destroy(struct drgn_prog_btf *bf)
{
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
