// Copyright (c) 2023 Oracle and/or its affiliates
// SPDX-License-Identifier: LGPL-2.1-or-later
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>

#include <ctf.h>
#include <ctf-api.h>

#include "drgn.h"
#include "drgn_ctf.h"
#include "lazy_object.h"
#include "program.h"
#include "type.h"

static struct drgn_error *
drgn_type_from_ctf_id(struct drgn_ctf_info *info, ctf_dict_t *dict,
                      ctf_id_t id, struct drgn_qualified_type *ret,
                      bool in_bitfield);

static struct drgn_error *
drgn_type_from_ctf(uint64_t kinds, const char *name,
		   size_t name_len, const char *filename,
		   void *arg, struct drgn_qualified_type *ret);

static struct drgn_error *
drgn_ctf_lookup_by_name(struct drgn_ctf_info *info, ctf_dict_t *dict, const char *name,
			uint64_t want_kinds, ctf_id_t *id_ret, ctf_dict_t **dict_ret);

static inline int get_ctf_errno(ctf_dict_t *dict)
{
	/*
	 * On some libctf versions, if an error is set on the parent dict, the
	 * child dict will still return 0 in ctf_errno. To avoid this, wrap
	 * ctf_errno() and verify.
	 */
	 int err = ctf_errno(dict);
	 ctf_dict_t *parent = ctf_parent_dict(dict);
	 if (!err && parent)
		 err = ctf_errno(parent);
	 return err;
}

static struct drgn_error *drgn_error_ctf(int err)
{
	return drgn_error_format(DRGN_ERROR_OTHER, "Internal CTF error: %s", ctf_errmsg(err));
}

static struct drgn_error *
drgn_integer_from_ctf(struct drgn_ctf_info *info, ctf_dict_t *dict,
                      ctf_id_t id, struct drgn_qualified_type *ret,
                      bool in_bitfield)
{
	ctf_encoding_t enc;
	bool _signed, is_bool, type_in_bitfield;
	const char *name;
	uint64_t size_bytes = ctf_type_size(dict, id);
	assert(ctf_type_encoding(dict, id, &enc) == 0);

	type_in_bitfield = enc.cte_offset || (enc.cte_bits != size_bytes * 8);

	if (type_in_bitfield) {
		if (!in_bitfield)
			return drgn_error_create(
				DRGN_ERROR_OTHER,
				"Integer with bitfield info outside compound type"
			);
		if (size_bytes * 8 < enc.cte_bits)
			return drgn_error_create(
				DRGN_ERROR_OTHER,
				"Integer whose bitfield size is greater than byte size"
			);
	}

	_signed = enc.cte_format & CTF_INT_SIGNED;
	is_bool = enc.cte_format & CTF_INT_BOOL;
	name = ctf_type_name_raw(dict, id);
	if (enc.cte_bits == 0) {
		ret->type = drgn_void_type(info->prog, &drgn_language_c);
	} else if (is_bool) {
		return drgn_bool_type_create(info->prog, name, size_bytes,
		                             DRGN_PROGRAM_ENDIAN,
					     &drgn_language_c, &ret->type);
	} else {
		return drgn_int_type_create(info->prog, name, size_bytes,
		                            _signed, DRGN_PROGRAM_ENDIAN,
					    &drgn_language_c, &ret->type);
	}
	return NULL;
}

static struct drgn_error *
drgn_float_from_ctf(struct drgn_ctf_info *info, ctf_dict_t *dict,
                    ctf_id_t id, struct drgn_qualified_type *ret,
                    bool in_bitfield)
{
	ctf_encoding_t enc;
	const char *name;
	bool type_in_bitfield;
	size_t size_bytes = ctf_type_size(dict, id);

	assert(ctf_type_encoding(dict, id, &enc) == 0);
	name = ctf_type_name_raw(dict, id);

	type_in_bitfield = enc.cte_offset || (enc.cte_bits != size_bytes * 8);
	if (type_in_bitfield) {
		if (!in_bitfield)
			return drgn_error_create(
				DRGN_ERROR_OTHER,
				"Float with bitfield info outside compound type"
			);
		if (size_bytes * 8 < enc.cte_bits)
			return drgn_error_create(
				DRGN_ERROR_OTHER,
				"Float whose bitfield size is greater than byte size"
			);
	}
	if (enc.cte_format != CTF_FP_DOUBLE && enc.cte_format != CTF_FP_SINGLE
	    && enc.cte_format != CTF_FP_LDOUBLE)
		return drgn_error_format(
			DRGN_ERROR_NOT_IMPLEMENTED,
			"CTF floating point format %d is not implemented",
			enc.cte_format
		);

	return drgn_float_type_create(info->prog, name, size_bytes,
				      DRGN_PROGRAM_ENDIAN, &drgn_language_c,
				      &ret->type);
}

static struct drgn_error *
drgn_typedef_from_ctf(struct drgn_ctf_info *info, ctf_dict_t *dict,
                      ctf_id_t id, struct drgn_qualified_type *ret,
		      bool in_bitfield)
{
	struct drgn_qualified_type aliased;
	struct drgn_error *err;
	const char *name;
	ctf_id_t aliased_id;

	name = ctf_type_name_raw(dict, id);
	aliased_id = ctf_type_reference(dict, id);
	if (!name || !name[0]) {
		/*
		 * An empty raw name field is wrong: typedefs must have
		 * a name, that's their reason to exist.
		 * This is an indicator that this is not really a typedef, it's
		 * a SLICE posing as a typdef. Re-grab the name and ID based on
		 * that assumption.
		 */
		name = ctf_type_name_raw(dict, aliased_id);
		aliased_id = ctf_type_reference(dict, aliased_id);
	}

	err = drgn_type_from_ctf_id(info, dict, aliased_id, &aliased, in_bitfield);
	if (err)
		return err;

	return drgn_typedef_type_create(info->prog, name, aliased,
					&drgn_language_c, &ret->type);
}

static struct drgn_error *
drgn_pointer_from_ctf(struct drgn_ctf_info *info, ctf_dict_t *dict,
                      ctf_id_t id, struct drgn_qualified_type *ret)
{
	struct drgn_qualified_type aliased;
	struct drgn_error *err;
	ctf_id_t aliased_id;

	aliased_id = ctf_type_reference(dict, id);

	err = drgn_type_from_ctf_id(info, dict, aliased_id, &aliased, false);
	if (err)
		return err;

	ssize_t size = ctf_type_size(dict, id);
	if (size < 0)
		return drgn_error_ctf(get_ctf_errno(dict));

	return drgn_pointer_type_create(info->prog, aliased, size,
	                                DRGN_PROGRAM_ENDIAN, &drgn_language_c,
	                                &ret->type);
}

struct drgn_ctf_enum_visit_arg {
	struct drgn_enum_type_builder *builder;
	struct drgn_error *err;
};

static int drgn_ctf_enum_visit(const char *name, int val, void *arg)
{
	struct drgn_ctf_enum_visit_arg *visit = arg;
	visit->err = drgn_enum_type_builder_add_signed(visit->builder, name, val);
	return visit->err ? -1 : 0;
}

static struct drgn_error *
drgn_enum_from_ctf(struct drgn_ctf_info *info, ctf_dict_t *dict,
                   ctf_id_t id, struct drgn_qualified_type *ret)
{
	struct drgn_enum_type_builder builder;
	struct drgn_ctf_enum_visit_arg arg;
	const char *name;
	struct drgn_qualified_type compatible_type;

	name = ctf_type_name_raw(dict, id);
	if (name && !name[0])
		name = NULL;

	arg.err = drgn_program_find_primitive_type(info->prog, DRGN_C_TYPE_INT,
						   &compatible_type.type);
	if (arg.err)
		return arg.err;

	drgn_enum_type_builder_init(&builder, info->prog);

	if (ctf_type_kind(dict, id) == CTF_K_FORWARD)
		return drgn_enum_type_create(&builder, name, compatible_type.type,
		                             &drgn_language_c, &ret->type);

	arg.builder = &builder;
	if (ctf_enum_iter(dict, id, drgn_ctf_enum_visit, &arg) != 0) {
		if (!arg.err)
			arg.err = drgn_error_ctf(get_ctf_errno(dict));
		goto out;
	}
	arg.err = drgn_enum_type_create(&builder, name, compatible_type.type,
				    &drgn_language_c, &ret->type);
	if (!arg.err)
		return NULL;
out:
	drgn_enum_type_builder_deinit(&builder);
	return arg.err;
}

static struct drgn_error *
drgn_array_from_ctf(struct drgn_ctf_info *info, ctf_dict_t *dict,
                    ctf_id_t id, struct drgn_qualified_type *ret)
{
	struct drgn_qualified_type etype;
	struct drgn_error *err;
	ctf_arinfo_t arinfo;

	ctf_array_info(dict, id, &arinfo);

	err = drgn_type_from_ctf_id(info, dict, arinfo.ctr_contents, &etype, false);
	if (err)
		return err;

	/*
	 * According to pg. 16 of CTFv3 Specification: cta_index: "If this is a
	 * variable-length aray, the index type ID will be 0 (but the actual
	 * index type of this array is probably int)."
	 *
	 * cta_nelems: The number of array elements. 0 for VLAs, and also for
	 * the historical variety of VLA which has explicit zero dimensions
	 * (which will have a nonzero cta_index.)
	 *
	 * In Linux, there are cases where explicit zero-length arrays exist,
	 * such as "struct zone_padding". These are not intended to be used as
	 * VLAs, they are intended to be used for the cache-line padding
	 * attributes. So the "historical variety" of VLA cannot be detected by
	 * testing nelems: zero is a valid array length. Use ctr_index here to
	 * ensure that we define these explicit zero-length arrays as such.
	 * Otherwise, drgn will complain about an incomplete array type in the
	 * middle of a struct.
	 */
	if (arinfo.ctr_index)
		return drgn_array_type_create(info->prog, etype, arinfo.ctr_nelems,
		                              &drgn_language_c, &ret->type);
	else
		return drgn_incomplete_array_type_create(info->prog, etype,
		                                         &drgn_language_c,
		                                         &ret->type);
}

struct drgn_ctf_thunk_arg {
	struct drgn_ctf_info *info;
	ctf_dict_t *dict;
	ctf_id_t id;
	uint64_t bit_field_size;
};

static struct drgn_error *drgn_ctf_thunk(struct drgn_object *res, void *void_arg)
{
	struct drgn_ctf_thunk_arg *arg = void_arg;
	struct drgn_qualified_type type;
	struct drgn_error *err = NULL;

	/*
	 * Thunks are a bit confusing. As far as I understand, this call needs
	 * to handle three cases:
	 * 1. res == NULL: in this case, we are being deinitialized, so free the
	 *    arg.
	 * 2(a). res != NULL, and we do not encounter an error evaluating the
	 *       thunk: we won't get called again, so the arg should get freed
	 *       as well.
	 * 2(b). res != NULL, and we encounter an error. In this case, we need
	 *       to preserve the arg, because drgn will re-initialize the lazy
	 *       object. If we free the arg on failure, then we run the risk of
	 *       either a UAF if the evaluation is retried, or a double free if
	 *       the the deinitializer gets called.
	 */

	if (res) {
		err = drgn_type_from_ctf_id(arg->info, arg->dict,
		                            arg->id, &type, (bool)arg->bit_field_size);
		if (!err)
			err = drgn_object_set_absent(res, type, arg->bit_field_size);

		if (!err)
			free(arg);  /* Case 2(a) */
	} else {
		free(arg);  /* Case 1 */
	}

	return err;
}

static struct drgn_error *
drgn_function_from_ctf(struct drgn_ctf_info *info, ctf_dict_t *dict,
                       ctf_id_t id, struct drgn_qualified_type *ret)
{
	struct drgn_function_type_builder builder;
	struct drgn_qualified_type qt;
	struct drgn_error *err;
	ctf_funcinfo_t funcinfo;
	ctf_id_t *argtypes;
	bool variadic = false;

	//printf("Create function type for id %lu\n", id);

	ctf_func_type_info(dict, id, &funcinfo);
	argtypes = calloc(funcinfo.ctc_argc, sizeof(*argtypes));
	if (!argtypes)
		return &drgn_enomem;
	ctf_func_type_args(dict, id, funcinfo.ctc_argc, argtypes);

	drgn_function_type_builder_init(&builder, info->prog);

	err = drgn_type_from_ctf_id(info, dict, funcinfo.ctc_return, &qt, false);
	if (err)
		goto out;

	for (size_t i = 0; i < funcinfo.ctc_argc; i++) {
		union drgn_lazy_object param;
		struct drgn_ctf_thunk_arg *arg;

		if (argtypes[i] == 0 && i + 1 == funcinfo.ctc_argc) {
			variadic = true;
			break;
		}

		arg = calloc(1, sizeof(*arg));
		if (!arg) {
			err = &drgn_enomem;
			goto out;
		}
		arg->info = info;
		arg->dict = dict;
		arg->id = argtypes[i];
		drgn_lazy_object_init_thunk(&param, info->prog, drgn_ctf_thunk, arg);
		err = drgn_function_type_builder_add_parameter(&builder, &param, NULL);
		//printf("add param index %lu id %lu\n", i, argtypes[i]);
		if (err) {
			drgn_lazy_object_deinit(&param);
			goto out;
		}
	}
	free(argtypes);
	argtypes = NULL;

	err = drgn_type_from_ctf_id(info, dict, funcinfo.ctc_return, ret, false);
	if (err)
		goto out;
	err = drgn_function_type_create(&builder, qt, variadic, &drgn_language_c, &ret->type);
	if (!err)
		return NULL;
out:
	drgn_function_type_builder_deinit(&builder);
	free(argtypes);
	return err;
}

struct compound_member_visit_arg {
	struct drgn_compound_type_builder *builder;
	struct drgn_ctf_info *info;
	ctf_dict_t *dict;
	struct drgn_error *err;
};

static int compound_member_visit(const char *name, ctf_id_t membtype, unsigned long offset,
                                 void *void_arg)
{
	union drgn_lazy_object obj;
	struct compound_member_visit_arg *arg = void_arg;
	struct drgn_ctf_thunk_arg *thunk_arg = calloc(1, sizeof(*thunk_arg));
	ctf_id_t resolved;
	ctf_encoding_t enc;
	bool has_encoding = false;

	//printf("Compound member %s id %lu\n", name, membtype);
	thunk_arg->dict = arg->dict;
	thunk_arg->info = arg->info;
	thunk_arg->id = membtype;
	thunk_arg->bit_field_size = 0;
	drgn_lazy_object_init_thunk(&obj, arg->info->prog, drgn_ctf_thunk, thunk_arg);

	/* libctf gives us 0-length name for anonymous members, but drgn prefers
	 * NULL. 0-length name seems to be legal, but inaccessible for the API. */
	if (name[0] == '\0')
		name = NULL;

	/*
	 * CTF has some really frustrating semantics regarding compound members
	 * and bit fields. Hopefully this explains what this code is doing.
	 *
	 * (1) Bit field offset can be specified as part of the compound member
	 * (see the signature of this function). However, for some reason, the
	 * bit field size is not represented this way.
	 *
	 * (2) Bit field offset, along with bit field size, can be specified as
	 * part of integer/float "encoding" field. This has a key disadvantage:
	 * the underlying integer type (e.g. unsigned int) and any typedefs +
	 * qualifiers, needs to be duplicated for each unique encoding seen in a
	 * bit field. This not only wastes space, but also creates quite
	 * confusing CTF data (multiple ints, floats, typedefs with the same
	 * name).
	 *
	 * (3) Since the solution in #2 is pretty sub-optimal, there is a CTF
	 * type kind, CTF_K_SLICE. This is essentially a type which references
	 * another type, and modifies its encoding. This means that you could
	 * have something like this:
	 *    STRUCT
	 *      member "foo" offset 0 bits
	 *        SLICE (encoding: offset 4 bits, size 1 bit)
	 *          TYPEDEF "u64" -> TYPEDEF "__u64"
	 *            INTEGER "unsigned long long int" (offset 0, size 64 bits)
	 *
	 * Comapred to (2), there is a new type ID for the SLICE type, but the
	 * TYPEDEF and INTEGER types there are unmodified - they are the base
	 * type IDs, with no duplication. This seems great, right?
	 *
	 * Unfortunately, libctf's API denies the existence of a SLICE type.
	 * When you look up the type kind for a SLICE, it simply looks at the
	 * referenced type and returns that type's kind. This is frustrating,
	 * because it means that secretly, any type could be a slice modifying
	 * the encoding of a target type -- and you have no way to detect it,
	 * because libctf refuses to admit that the type is indeed a SLICE.
	 *
	 * To add to all of this, we are actually forced to deal with CTF data
	 * that is generated using approach (2) -- generated by a program called
	 * dwarf2ctf, and approach (3) -- generated by GCC. So our solution
	 * needs to handle both cases gracefully.
	 *
	 * The approach is as follows: try to get the integer encoding from the
	 * member type ID, regardless of whether it looks like an integer. This
	 * handles the possibility that we're looking at a slice. Failing that,
	 * try to resolve to the type ID, and if it's an integer or float, then
	 * grab the encoding from that. Finally, regardless of whether the
	 * encoding information came from a slice or the target, we use the
	 * offset and bit size. We still need to detect whether the type **IS**
	 * a bitfield, which we do by checking whether the bit size == 8 * byte
	 * size. If so, we set the bit_field_size parameter to inform drgn's
	 * type system.
	 */
	resolved = ctf_type_resolve(arg->dict, membtype);
	if (ctf_type_encoding(arg->dict, membtype, &enc) == 0) {
		/*
		 * We're either looking at a SLICE type, or we're looking at a
		 * raw base INTEGER with no intermediate qualifiers or typedefs.
		 * Either way, use the encoding.
		 */
		has_encoding = true;

		/*
		 * This must have been a base INTEGER or FLOAT, since resolving
		 * failed. Set resolved to the original type ID so we can use it
		 * to detect the byte size below.
		 */
		if (resolved == CTF_ERR)
			resolved = membtype;
	} else if (resolved != CTF_ERR) {
		/*
		 * Check for the base type being INTEGER / FLOAT and if so, use
		 * the encoding. This would be the old-fashioned approach (2).
		 */
		int kind = ctf_type_kind(arg->dict, resolved);
		if ((kind == CTF_K_INTEGER || kind == CTF_K_FLOAT)
		    && ctf_type_encoding(arg->dict, resolved, &enc) == 0)
			has_encoding = true;
	}

	if (has_encoding) {
		/*
		 * The encoded offset augments the offset we already have. The
		 * encoded bit field size may need to be used, if it conflicts
		 * with the byte size of the type.
		 */
		size_t bytes = ctf_type_size(arg->dict, resolved);
		if (enc.cte_bits != bytes * 8)
			thunk_arg->bit_field_size = enc.cte_bits;
		offset += enc.cte_offset;
	}

	arg->err = drgn_compound_type_builder_add_member(arg->builder, &obj, name, offset);
	if (arg->err) {
		drgn_lazy_object_deinit(&obj); /* frees thunk_arg */
		return -1;
	} else {
		return 0;
	}
}

static struct drgn_error *
drgn_compound_type_from_ctf(enum drgn_type_kind kind, struct drgn_ctf_info *info, ctf_dict_t *dict,
                            ctf_id_t id, struct drgn_qualified_type *ret)
{
	struct drgn_compound_type_builder builder;
	struct drgn_error *err;
	struct compound_member_visit_arg arg;
	const char *tag;
	ssize_t size;

	tag = ctf_type_name_raw(dict, id);
	if (tag && !*tag)
		tag = NULL;

	drgn_compound_type_builder_init(&builder, info->prog, kind);

	/*
	 * We may be called with a kind of CTF_K_FORWARD which means an incomplete
	 * struct / union.
	 */
	if (ctf_type_kind(dict, id) == CTF_K_FORWARD)
		return drgn_compound_type_create(&builder, tag, 0, false,
		                                 &drgn_language_c, &ret->type);

	/* Don't ask for the size until after checking for forward declared types. */
	size = ctf_type_size(dict, id);
	if (size < 0 ) {
		err = drgn_error_ctf(get_ctf_errno(dict));
		goto out;
	}


	arg.builder = &builder;
	arg.info = info;
	arg.dict = dict;
	arg.err = NULL;
	if (ctf_member_iter(dict, id, compound_member_visit, &arg) == -1) {
		if (arg.err)
			err = arg.err;
		else
			err = drgn_error_ctf(get_ctf_errno(dict));
		goto out;
	}

	err = drgn_compound_type_create(&builder, tag, size, true,
	                                &drgn_language_c, &ret->type);
	if (!err) {
		//printf("Successfully created compound type %s\n", tag);
		return NULL;
	}
out:
	drgn_compound_type_builder_deinit(&builder);
	return err;
}

static struct drgn_error *
drgn_forward_from_ctf(struct drgn_ctf_info *info, ctf_dict_t *dict,
                      ctf_id_t id, struct drgn_qualified_type *ret)
{
	int ctf_kind = ctf_type_kind_forwarded(dict, id);
	const char *name = ctf_type_name_raw(dict, id);
	struct drgn_error *err;

	if (name && !*name)
		name = NULL;

	/*
	 * TODO: A forward declared type could be duplicated in several modules.
	 * In general, we can't really know which module to look in, this is a
	 * difficult problem to solve. For now, an easy answer is to just use
	 * the first available option.
	 */
	if (name) {
		err = drgn_ctf_lookup_by_name(info, NULL, name, (1ULL << ctf_kind),
					      &id, &dict);

		if (err)
			return err;
	}

	/*
	 * Now, either we have found an underlying definition, or we still have
	 * the forwarded type ID. Either way, we can construct the (maybe
	 * absent) type from this ID.
	 */
	switch (ctf_kind) {
		case CTF_K_ENUM:
			return drgn_enum_from_ctf(info, dict, id, ret);
		case CTF_K_STRUCT:
			return drgn_compound_type_from_ctf(DRGN_TYPE_STRUCT, info, dict, id, ret);
		case CTF_K_UNION:
			return drgn_compound_type_from_ctf(DRGN_TYPE_UNION, info, dict, id, ret);
		default:
			return drgn_error_format(DRGN_ERROR_OTHER, "Forwarded CTF type id %lu, kind %d, is not enum, struct, or union", id, ctf_kind);
	}
}

static struct drgn_error *
drgn_type_from_ctf_id(struct drgn_ctf_info *info, ctf_dict_t *dict,
                      ctf_id_t id, struct drgn_qualified_type *ret,
		      bool in_bitfield)
{
	int ctf_kind;

	ret->qualifiers = 0;
	ret->type = NULL;

again:
	ctf_kind = ctf_type_kind(dict, id);
	switch (ctf_kind) {
		case CTF_K_CONST:
			ret->qualifiers |= DRGN_QUALIFIER_CONST;
			id = ctf_type_reference(dict, id);
			goto again;
		case CTF_K_RESTRICT:
			ret->qualifiers |= DRGN_QUALIFIER_RESTRICT;
			id = ctf_type_reference(dict, id);
			goto again;
		case CTF_K_VOLATILE:
			ret->qualifiers |= DRGN_QUALIFIER_VOLATILE;
			id = ctf_type_reference(dict, id);
			goto again;
		break;
	}

	struct drgn_ctf_key key = {dict, id};
	if (ctf_type_isparent(dict, id))
		/* We should be accurate about which dict the cached type
		 * actually belongs to: otherwise, we'll cache multiple
		 * copies. */
		key.dict = info->root;
	struct hash_pair hp = drgn_ctf_type_map_hash(&key);
	struct drgn_ctf_type_map_iterator it =
		drgn_ctf_type_map_search_hashed(&info->types, &key, hp);
	if (it.entry) {
		ret->type = it.entry->value;
		return NULL;
	}

	struct drgn_error *err;
	switch (ctf_kind) {
		case CTF_K_INTEGER:
			err = drgn_integer_from_ctf(info, dict, id, ret, in_bitfield);
			break;
		case CTF_K_FLOAT:
			err = drgn_float_from_ctf(info, dict, id, ret, in_bitfield);
			break;
		case CTF_K_TYPEDEF:
			err = drgn_typedef_from_ctf(info, dict, id, ret, in_bitfield);
			break;
		case CTF_K_POINTER:
			err = drgn_pointer_from_ctf(info, dict, id, ret);
			break;
		case CTF_K_ENUM:
			err = drgn_enum_from_ctf(info, dict, id, ret);
			break;
		case CTF_K_FUNCTION:
			err = drgn_function_from_ctf(info, dict, id, ret);
			break;
		case CTF_K_ARRAY:
			err = drgn_array_from_ctf(info, dict, id, ret);
			break;
		case CTF_K_STRUCT:
			err = drgn_compound_type_from_ctf(DRGN_TYPE_STRUCT, info, dict, id, ret);
			break;
		case CTF_K_UNION:
			err = drgn_compound_type_from_ctf(DRGN_TYPE_UNION, info, dict, id, ret);
			break;
		case CTF_K_FORWARD:
			err = drgn_forward_from_ctf(info, dict, id, ret);
			break;
		default:
			return drgn_error_format(DRGN_ERROR_NOT_IMPLEMENTED, "CTF Type Kind %d is not implemented", ctf_kind);
	}
	if (err)
		return err;

	struct drgn_ctf_type_map_entry entry;
	entry.key = key;
	entry.value = ret->type;
	if (drgn_ctf_type_map_insert_searched(&info->types, &entry, hp, NULL) == -1)
		err = &drgn_enomem;
	return err;
}

static struct drgn_error *
drgn_ctf_get_dict(struct drgn_ctf_info *info, const char *name, ctf_dict_t **ret)
{
	struct hash_pair hp = drgn_ctf_dicts_hash(&name);
	struct drgn_ctf_dicts_iterator it = drgn_ctf_dicts_search_hashed(&info->dicts, &name, hp);
	if (it.entry) {
		*ret = it.entry->value;
		return NULL;
	}

	int errnum;
	const char *name_saved = strdup(name);
	struct drgn_error *err;
	if (!name_saved)
		return &drgn_enomem;

	ctf_dict_t *dict = ctf_dict_open(info->archive, name, &errnum);
	if (!dict && errnum == ECTF_ARNNAME) {
		// The common case for failure is that the dictionary name did
		// not exist, this only occurs when a dict name is passed in via
		// "drgn.type()" second argument. Return a lookup error.
		err = &drgn_not_found;
		goto out;
	} else if (!dict) {
		err = drgn_error_format(DRGN_ERROR_OTHER, "ctf_dict_open: \"%s\": %s",
					name, ctf_errmsg(errnum));
		goto out;
	}
	struct drgn_ctf_dicts_entry entry = {name_saved, dict};
	if (drgn_ctf_dicts_insert_searched(&info->dicts, &entry, hp, NULL) < 0) {
		err = &drgn_enomem;
		goto out_close;
	}
	*ret = dict;
	return NULL;
out_close:
	ctf_dict_close(dict);
out:
	free((char *)name_saved);
	return err;
}

static struct drgn_error *
drgn_ctf_lookup_by_name(struct drgn_ctf_info *info, ctf_dict_t *dict, const char *name,
			uint64_t want_kinds, ctf_id_t *id_ret, ctf_dict_t **dict_ret)
{
	struct drgn_ctf_names_iterator it = drgn_ctf_names_search(&info->names, &name);
	if (!it.entry)
		return &drgn_not_found;

	struct drgn_ctf_names_node *node;
	for (node = &it.entry->value; node; node = node->next) {
		/* When dict is provided, restrict our search to that dict, but
		 * we need to allow types from the parent dictionary too. */
		if (dict && ctf_type_ischild(node->dict, node->id)
		    && dict != node->dict)
			continue;
		int kind = ctf_type_kind(node->dict, node->id);
		if (!(want_kinds & (1ULL << kind)))
			continue;
		*id_ret = node->id;
		*dict_ret = node->dict;
		return NULL;
	}

	return &drgn_not_found;
}

static bool looks_like_filename(const char *filename)
{
	/* C filenames should contain '.' or '/' */
	return strchr(filename, '/') != NULL ||
		strchr(filename, '.') != NULL;
}

static struct drgn_error *
drgn_type_from_ctf(uint64_t kinds, const char *name,
		   size_t name_len, const char *filename,
		   void *arg, struct drgn_qualified_type *ret)
{
	ctf_dict_t *dict = NULL;
	ctf_id_t id;
	struct drgn_ctf_info *info = arg;
	struct drgn_error *err = NULL;
	uint64_t ctf_kinds = 0;

	if (kinds & (1 << DRGN_TYPE_ENUM))
		ctf_kinds |= (1 << CTF_K_ENUM);
	if (kinds & (1 << DRGN_TYPE_STRUCT))
		ctf_kinds |= (1 << CTF_K_STRUCT);
	if (kinds & (1 << DRGN_TYPE_UNION))
		ctf_kinds |= (1 << CTF_K_UNION);
	if (kinds & (1 << DRGN_TYPE_TYPEDEF))
		ctf_kinds |= (1 << CTF_K_TYPEDEF);

	/*
	 * Linux kernel CTF archives don't use filenames as dictionary names:
	 * they are named by kernel module. Userspace CTF, on the other hand,
	 * does use filenames.
	 *
	 * For the kernel, we'd like to allow users to run prog.type("name",
	 * "module") for CTF in order to restrict lookup to a given module.
	 * However, for existing code which uses filenames to disambiguate, we
	 * can't interpret these filenames as modules, since lookup will always
	 * fail, breaking existing code. So, silently ignore the filename
	 * parameter when it looks like a filename, and we're debugging the
	 * kernel.
	 */
	if (filename && !((info->prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL) &&
			  looks_like_filename(filename))) {
		err = drgn_ctf_get_dict(info, filename, &dict);
		if (err)
			return err;
	}

	_cleanup_free_ char *name_copy = strndup(name, name_len);

	err = drgn_ctf_lookup_by_name(info, dict, name_copy, ctf_kinds,
				      &id, &dict);

	if (!err)
		return drgn_type_from_ctf_id(info, dict, id, ret,
						false);
	return err;
}

static struct drgn_error *
drgn_ctf_find_var(struct drgn_ctf_info *info, const char *name, ctf_dict_t *dict,
		  uint64_t addr, struct drgn_object *ret)
{
	struct drgn_qualified_type qt = {0};
	struct drgn_error *err;
	ctf_id_t id;

	id = ctf_lookup_variable(dict, name);

	/* Technically, it could be possible for libctf to return an error
	 * other than a lookup error. Practically, this doesn't happen, and
	 * due to some bugs related to ctf_errno() with CTF lookup functions,
	 * reliably distinguishing this case is impossible. Just assume the
	 * CTF error was a lookup error.
	 */
	if (id == CTF_ERR)
		return &drgn_not_found;

	err = drgn_type_from_ctf_id(info, dict, id, &qt, NULL);
	if (err)
		return err;

	return drgn_object_set_reference(ret, qt, addr, 0, 0);
}

static struct drgn_error *
drgn_ctf_find_var_all_dicts(struct drgn_ctf_info *info, const char *name, uint64_t addr,
			    struct drgn_object *ret)
{
	struct drgn_ctf_dicts_iterator it;
	struct drgn_error *err;

	/*
	 * A reasonable assumption is that this is in vmlinux. First search it,
	 * and then the rest of the modules.
	 * TODO: can we use some smarts here? We should be able to determine
	 * which module an address is from. If we do that, we can skip directly
	 * to searching the relevant dict.
	 */
	err = drgn_ctf_find_var(info, name, info->vmlinux, addr, ret);
	if (!err || err != &drgn_not_found)
		return err;

	for (it = drgn_ctf_dicts_first(&info->dicts); it.entry; it = drgn_ctf_dicts_next(it)) {
		if (it.entry->value == info->vmlinux || it.entry->value == info->root)
			continue; /* no need to search these */
		err = drgn_ctf_find_var(info, name, it.entry->value, addr, ret);
		if (!err || err != &drgn_not_found)
			break;
	}
	return err;
}

static struct drgn_error *
drgn_ctf_find_constant(struct drgn_ctf_info *info, const char *name, ctf_dict_t *dict,
		       struct drgn_object *ret)
{
	struct drgn_ctf_enums_iterator it = drgn_ctf_enums_search(&info->enums, &name);
	struct drgn_ctf_enumnode *node = it.entry ? &it.entry->value : NULL;
	struct drgn_error *err;

	for (; node; node = node->next) {
		if (dict && node->dict != dict)
			continue;
		/* A match! Construct an object. */
		struct drgn_qualified_type qt = {0};
		err = drgn_enum_from_ctf(info, node->dict, node->id, &qt);
		if (err)
			return err;
		return drgn_object_set_signed(ret, qt, node->val, 0);
	}
	return &drgn_not_found;
}

static struct drgn_error *
drgn_ctf_find_object(const char *name, size_t name_len,
		     const char *filename,
		     enum drgn_find_object_flags flags, void *arg,
		     struct drgn_object *ret)
{
	struct drgn_error *err = NULL;
	struct drgn_ctf_info *info = arg;
	ctf_dict_t *dict = NULL;
	_cleanup_free_ char *name_copy = strndup(name, name_len);

	/*
	 * Linux kernel CTF archives don't use filenames as dictionary names:
	 * they are named by kernel module. Userspace CTF, on the other hand,
	 * does use filenames.
	 *
	 * For the kernel, we'd like to allow users to run prog.type("name",
	 * "module") for CTF in order to restrict lookup to a given module.
	 * However, for existing code which uses filenames to disambiguate, we
	 * can't interpret these filenames as modules, since lookup will always
	 * fail, breaking existing code. So, silently ignore the filename
	 * parameter when it looks like a filename, and we're debugging the
	 * kernel.
	 *
	 * TODO: in the future, filtering symbols by the given kernel module
	 * name would be helpful too.
	 */
	if (filename && !((info->prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL) &&
			  looks_like_filename(filename))) {
		err = drgn_ctf_get_dict(info, filename, &dict);
		if (err)
			return err;
	}

	if (flags & DRGN_FIND_OBJECT_CONSTANT) {
		err = drgn_ctf_find_constant(info, name_copy, NULL, ret);
		if (!err || err != &drgn_not_found)
			return err;
	}
	if (flags & (DRGN_FIND_OBJECT_VARIABLE | DRGN_FIND_OBJECT_FUNCTION)) {
		uint64_t addr;
		struct drgn_symbol *sym = NULL;
		err = drgn_program_find_symbol_by_name(info->prog, name, &sym);
		if (err)
			return err;
		addr = sym->address;
		drgn_symbol_destroy(sym);
		if (dict) {
			err = drgn_ctf_find_var(info, name_copy, dict, addr, ret);
			if (!err || err != &drgn_not_found)
				return err;
		} else {
			err = drgn_ctf_find_var_all_dicts(info, name_copy, addr, ret);
			if( !err || err != &drgn_not_found )
				return err;
		}
	}
	return &drgn_not_found;
}

struct drgn_ctf_arg {
	struct drgn_ctf_info *info;
	ctf_dict_t *dict;
	const char *dict_name;
	ctf_id_t type;
	struct drgn_error *err;
	unsigned long count;
};

static int process_enumerator(const char *name, int val, void *void_arg)
{
	struct drgn_ctf_arg *arg = void_arg;
	struct drgn_ctf_enums_iterator it;
	struct drgn_ctf_enums_entry entry;
	struct hash_pair hp;

	hp = drgn_ctf_enums_hash(&name);
	it = drgn_ctf_enums_search_hashed(&arg->info->enums, &name, hp);
	if (it.entry) {
		/* Insert at the head of the list, which means allocating a node
		 * for the current head to reside at. */
		struct drgn_ctf_enumnode *node = calloc(1, sizeof(*node));
		if (!node) {
			arg->err = &drgn_enomem;
			return -1;
		}
		*node = it.entry->value;
		it.entry->value.dict = arg->dict;
		it.entry->value.id = arg->type;
		it.entry->value.val = val;
		it.entry->value.next = node;
	} else {
		entry.key = name;
		entry.value.dict = arg->dict;
		entry.value.id = arg->type;
		entry.value.val = val;
		entry.value.next = NULL;
		if (drgn_ctf_enums_insert_searched(&arg->info->enums, &entry, hp, NULL) < 0) {
			arg->err = &drgn_enomem;
			return -1;
		}
	}
	arg->count++;
	return 0;
}

static struct drgn_error *
canonical_atom(struct drgn_ctf_info *info, const char *name, ctf_dict_t *dict, ctf_id_t id)
{
	struct drgn_ctf_names_iterator it;
	struct drgn_ctf_names_entry entry;
	struct hash_pair hp;
	int kind = ctf_type_kind(dict, id);

	/* CTF BUG: for CTF generated without slices, int/float types are
	 * duplicated when they are contained within a bitfield. While the
	 * integers & floats themselves are hidden, any typedefs pointing at
	 * them will be public, so we'll get lots of duplicates. Detect when a
	 * typedef points at a bitfield, and if so, skip it. */
	if (kind == CTF_K_TYPEDEF) {
		ctf_id_t resolved = ctf_type_resolve(dict, id);
		if (resolved != CTF_ERR) {
			ctf_encoding_t enc;
			size_t size = ctf_type_size(dict, resolved);
			if (ctf_type_encoding(dict, resolved, &enc) == 0) {
				if (enc.cte_bits != size * 8 || enc.cte_offset)
					return NULL;
			}
		}
	}

	hp = drgn_ctf_names_hash(&name);
	it = drgn_ctf_names_search_hashed(&info->names, &name, hp);
	if (it.entry) {
		struct drgn_ctf_names_node *iter = &it.entry->value;

		/* Adding to the end of the linked list is slower if there are
		 * long lists. But, it allows us to check for duplicates of the
		 * same type kind, name, and dict. */

		while (iter->next) {
			if (iter->dict == dict && ctf_type_kind(iter->dict, iter->id) == kind)
				return NULL;
			iter = iter->next;
		}
		if (iter->dict == dict && ctf_type_kind(iter->dict, iter->id) == kind)
			return NULL;

		struct drgn_ctf_names_node *node = calloc(1, sizeof(*node));
		if (!node)
			return &drgn_enomem;
		node->dict = dict;
		node->id = id;

		iter->next = node;
	} else {
		entry.key = name;
		entry.value.dict = dict;
		entry.value.id = id;
		entry.value.next = NULL;
		if (drgn_ctf_names_insert_searched(&info->names, &entry, hp, NULL) < 0)
			return &drgn_enomem;
	}
	return NULL;
}

static int process_type(ctf_id_t type, void *void_arg)
{
	struct drgn_ctf_arg *arg = void_arg;
	int kind = ctf_type_kind(arg->dict, type);
	int ret = 0;
	const char *name;
	switch (kind) {
	case CTF_K_ENUM:
		arg->type = type;
		ret = ctf_enum_iter(arg->dict, type, process_enumerator, void_arg);
		/* For CTF errors, set a drgn error immediately */
		if (ret != 0 && !arg->err) {
			arg->err = drgn_error_ctf(get_ctf_errno(arg->dict));
		}
		if (ret)
			break;

		arg->type = 0;
		fallthrough;

	case CTF_K_INTEGER:
	case CTF_K_FLOAT:
	case CTF_K_TYPEDEF:
	case CTF_K_STRUCT:
	case CTF_K_UNION:
		name = ctf_type_name_raw(arg->dict, type);
		if (name && *name) {
			arg->err = canonical_atom(arg->info, name,
						  arg->dict, type);
			ret = arg->err ? -1 : 0;
		}
		break;
	default:
		break;
	}
	return ret;
}

static int process_dict(ctf_dict_t *unused, const char *name, void *void_arg)
{
	struct drgn_ctf_arg *arg = void_arg;
	ctf_dict_t *dict;

	/* The CTF archive iterator will close the dict handle it gives us once
	 * we return. So ignore the argument and open a new handle which we will
	 * cache. */
	arg->err = drgn_ctf_get_dict(arg->info, name, &dict);
	if (arg->err)
		return -1;

	if (strcmp(name, "shared_ctf") == 0) {
		arg->info->root = dict;
	} else if (strcmp(name, "vmlinux") == 0) {
		if (arg->info->vmlinux)
			return 0; /* already visited */
		arg->info->vmlinux = dict;
	}

	arg->dict = dict;
	arg->dict_name = name;

	int ret = ctf_type_iter(dict, process_type, void_arg);
	/* For CTF errors, set a drgn error immediately */
	if (ret != 0 && !arg->err)
		arg->err = drgn_error_ctf(get_ctf_errno(dict));

	arg->dict = NULL;
	arg->dict_name = NULL;

	return ret;
}

/*
 * libctf contains an awfully convenient "ctf_open" which seems to "do what you
 * mean". Unfortunately, it is not present when you compile with -lctf-nobfd.
 * And avoiding linking to BFD can be very useful. So let's do what we need.
 */
static struct drgn_error *read_ctf_buf(const char *file, char **buf_ret, size_t *size_ret)
{
	long size, amt;
	char *buf;
	FILE *f = fopen(file, "r");

	if (!f)
		return drgn_error_create_os("Error opening CTF file", errno, file);

	if (fseek(f, 0, SEEK_END) == -1) {
		fclose(f);
		return drgn_error_create_os("Error seeking to end of CTF file", errno, file);
	}
	size = ftell(f);
	fseek(f, 0, SEEK_SET);
	buf = malloc(size + 1);
	if (!buf) {
		fclose(f);
		return &drgn_enomem;
	}
	amt = fread(buf, 1, size, f);
	if (amt != size) {
		free(buf);
		fclose(f);
		return drgn_error_create_os("Error reading CTF file", errno, file);
	}
	fclose(f);
	buf[size] = '\0';
	*buf_ret = buf;
	*size_ret = size;
	return NULL;
}

static void
drgn_ctf_enums_free_all(struct drgn_ctf_enums *enums)
{
	struct drgn_ctf_enums_iterator it = drgn_ctf_enums_first(enums);
	while (it.entry) {
		struct drgn_ctf_enumnode *node = &it.entry->value;
		node = node->next;
		while (node) {
			struct drgn_ctf_enumnode *tmp = node->next;
			free(node);
			node = tmp;
		}
	}
}

static void
drgn_ctf_names_free_all(struct drgn_ctf_names *enums)
{
	struct drgn_ctf_names_iterator it = drgn_ctf_names_first(enums);
	while (it.entry) {
		struct drgn_ctf_names_node *node = &it.entry->value;
		node = node->next;
		while (node) {
			struct drgn_ctf_names_node *tmp = node->next;
			free(node);
			node = tmp;
		}
	}
}

struct drgn_error *
drgn_program_load_ctf(struct drgn_program *prog, const char *file, struct drgn_ctf_info **ret)
{
	struct drgn_error *err;
	int errnum = 0;
	struct drgn_ctf_info *info = calloc(1, sizeof(*info));
	ctf_sect_t data = {0};
	char *ctf_contents;

	err = read_ctf_buf(file, &ctf_contents, &data.cts_size);
	if (err)
		return err;
	data.cts_data = ctf_contents;

	if (!info)
		return &drgn_enomem;

	info->prog = prog;
	info->ctf_data = ctf_contents;
	info->ctf_size = data.cts_size;
	info->archive = ctf_arc_bufopen(&data, NULL, NULL, &errnum);
	if (!info->archive) {
		free(info);
		return drgn_error_format(DRGN_ERROR_OTHER, "ctf_arc_bufopen \"%s\": %s",
					 file, ctf_errmsg(errnum));
	}
	drgn_ctf_dicts_init(&info->dicts);
	drgn_ctf_enums_init(&info->enums);
	drgn_ctf_names_init(&info->names);
	drgn_ctf_type_map_init(&info->types);

	/*
	 * libctf offers the function "ctf_lookup_by_name()" which seems like a
	 * reasonable and efficient type lookup function. However, it doesn't
	 * really suit our cases for a few reasons:
	 *
	 * 1. Name lookup requires including the tag type (enum, struct, union).
	 *    If we want to search for types of any tag type, then we must
	 *    repeat the search several times.
	 * 2. Lookups search the child dict, and then they search the parent if
	 *    the type isn't found in the child. If you want to search all
	 *    dicts, there is no shortcut method, and this means you must redo
	 *    the search in the parent dict potentially hundreds of times.
	 * 3. There is no mechanism to return several matches. CTF does
	 *    sometimes have name collisions (especially with older versions
	 *    that don't handle bitfields using slices). It seems libctf doesn't
	 *    give guarantees about which result gets returned in those cases:
	 *    it's better for us to handle it manually.
	 *
	 * For these reasons, we will iterate over every dictionary and create a
	 * map of each type name to the type ID. libctf already has the type
	 * names allocated in memory, but we must create a hash table to contain
	 * roughly 60k named elements.
	 *
	 * While we iterate over each dictionary, we will also index enumerators
	 * (libctf doesn't contain an efficient lookup mechanism for these
	 * either).
	 */
	struct drgn_ctf_arg arg = {0};
	arg.info = info;

	/* Process vmlinux first so it's at the beginning of the hash lists */
	ctf_dict_t *d = ctf_dict_open(info->archive, "vmlinux", &errnum);
	if (!d) {
		err = drgn_error_format(DRGN_ERROR_OTHER, "ctf_dict_open vmlinux: %s",
					ctf_errmsg(errnum));
		goto error;
	}
	errnum = process_dict(d, "vmlinux", &arg);

	ctf_dict_close(d);
	if (errnum != 0) {
		err = arg.err;
		goto error;
	}

	/* Now process the remaining dictionaries */
	errnum = ctf_archive_iter(info->archive, process_dict, &arg);
	if (errnum != 0) {
		if (!arg.err)
			arg.err = drgn_error_ctf(errnum);
		err = arg.err;
		goto error;
	}

	*ret = info;
	err = drgn_program_add_type_finder(prog, drgn_type_from_ctf, info);
	if (err)
		goto error;

	err = drgn_program_add_object_finder(prog, drgn_ctf_find_object, info);
	if (err)
		goto error; /* TODO: cleanup type finder? */

	return NULL;
error:
	ctf_arc_close(info->archive);
	free(info->ctf_data);
	drgn_ctf_type_map_deinit(&info->types);
	drgn_ctf_names_free_all(&info->names);
	drgn_ctf_names_deinit(&info->names);
	drgn_ctf_enums_free_all(&info->enums);
	drgn_ctf_enums_deinit(&info->enums);
	drgn_ctf_dicts_deinit(&info->dicts);
	free(info);
	return err;
}
