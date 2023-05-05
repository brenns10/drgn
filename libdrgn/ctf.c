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
drgn_type_from_ctf(enum drgn_type_kind kind, const char *name,
		   size_t name_len, const char *filename,
		   void *arg, struct drgn_qualified_type *ret);

static struct drgn_error *
format_type_name(enum drgn_type_kind kind, const char *name, size_t name_len, char **ret)
{
	int rv;
	switch (kind) {
		case DRGN_TYPE_STRUCT:
			rv = asprintf(ret, "struct %.*s", (int) name_len, name);
			break;
		case DRGN_TYPE_UNION:
			rv = asprintf(ret, "union %.*s", (int) name_len, name);
			break;
		case DRGN_TYPE_ENUM:
			rv = asprintf(ret, "enum %.*s", (int) name_len, name);
			break;
		default:
			rv = asprintf(ret, "%.*s", (int) name_len, name);
			break;
	}
	if (rv == -1)
		return &drgn_enomem;
	return NULL;
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
		return drgn_error_ctf(ctf_errno(dict));

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

	// TODO: don't lookup "int", instead build an integer type to match.
	arg.err = drgn_type_from_ctf(DRGN_TYPE_INT, "int", 3, NULL, info,
				 &compatible_type);
	if (arg.err)
		return arg.err;

	drgn_enum_type_builder_init(&builder, info->prog);

	if (ctf_type_kind(dict, id) == CTF_K_FORWARD)
		return drgn_enum_type_create(&builder, name, compatible_type.type,
		                             &drgn_language_c, &ret->type);

	arg.builder = &builder;
	if (ctf_enum_iter(dict, id, drgn_ctf_enum_visit, &arg) != 0) {
		if (!arg.err)
			arg.err = drgn_error_ctf(ctf_errno(dict));
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

	if (arinfo.ctr_nelems)
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
		err = drgn_error_ctf(ctf_errno(dict));
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
			err = drgn_error_ctf(ctf_errno(dict));
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
	char *name_copy;
	ctf_id_t fwded_id;
	enum drgn_type_kind kind;
	struct drgn_error *err;

	if (name && !*name)
		name = NULL;

	switch (ctf_kind) {
		case CTF_K_ENUM:
			kind = DRGN_TYPE_ENUM;
			break;
		case CTF_K_STRUCT:
			kind = DRGN_TYPE_STRUCT;
			break;
		case CTF_K_UNION:
			kind = DRGN_TYPE_UNION;
			break;
		default:
			return drgn_error_format(DRGN_ERROR_OTHER, "Forwarded CTF type id %lu, kind %d, is not enum, struct, or union", id, ctf_kind);
	}

	/*
	 * This type ID may be a reference to a struct which is defined in the
	 * child dictionary. This is possible when multiple structures have the
	 * same name, but different definitions. To resolve this, lookup the
	 * name in the current dictionary. This only works when the type has a
	 * name, but really, how can you have an anonymous, forward declared
	 * type?
	 */
	if (name) {
		err = format_type_name(kind, name, strlen(name), &name_copy);
		if (err)
			return err;
		fwded_id = ctf_lookup_by_name(dict, name_copy);
		if (fwded_id != CTF_ERR)
			id = fwded_id;
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

	//printf("call\n");
again:
	ctf_kind = ctf_type_kind(dict, id);
	//printf("ID %lu Kind %d\n", id, ctf_kind);
	switch (ctf_kind) {
		case CTF_K_INTEGER:
			return drgn_integer_from_ctf(info, dict, id, ret, in_bitfield);
		case CTF_K_FLOAT:
			return drgn_float_from_ctf(info, dict, id, ret, in_bitfield);
		case CTF_K_TYPEDEF:
			return drgn_typedef_from_ctf(info, dict, id, ret, in_bitfield);
		case CTF_K_POINTER:
			return drgn_pointer_from_ctf(info, dict, id, ret);
		case CTF_K_ENUM:
			return drgn_enum_from_ctf(info, dict, id, ret);
		case CTF_K_FUNCTION:
			return drgn_function_from_ctf(info, dict, id, ret);
		case CTF_K_ARRAY:
			return drgn_array_from_ctf(info, dict, id, ret);
		case CTF_K_STRUCT:
			return drgn_compound_type_from_ctf(DRGN_TYPE_STRUCT, info, dict, id, ret);
		case CTF_K_UNION:
			return drgn_compound_type_from_ctf(DRGN_TYPE_UNION, info, dict, id, ret);
		case CTF_K_FORWARD:
			return drgn_forward_from_ctf(info, dict, id, ret);
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
		default:
			return drgn_error_format(DRGN_ERROR_NOT_IMPLEMENTED, "CTF Type Kind %d is not implemented", ctf_kind);
	}
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
	if (!dict) {
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

static void find_canonical(struct drgn_ctf_info *info, const char *name,
			   ctf_dict_t *search_dict, ctf_id_t *id_ret)
{
	struct drgn_ctf_atoms_iterator it = drgn_ctf_atoms_search(&info->atoms, &name);
	struct drgn_ctf_atomnode *node = it.entry ? &it.entry->value : NULL;

	if (node && (node->dict == search_dict || node->dict == info->root)) {
		*id_ret = node->id;
	}
}


static struct drgn_error *
drgn_ctf_lookup_by_name(struct drgn_ctf_info *info, ctf_dict_t *dict, const char *name,
			ctf_id_t *id_ret, ctf_dict_t **dict_ret)
{
	ctf_id_t id = ctf_lookup_by_name(dict, name);
	int err = ctf_errno(dict);
	if (id == CTF_ERR && err == ECTF_NOTYPE) {
		return &drgn_not_found;
	} else if (id == CTF_ERR) {
		return drgn_error_ctf(ctf_errno(dict));
	}
	*id_ret = id;
	*dict_ret = dict;
	int kind = ctf_type_kind(dict, id);
	if (kind == CTF_K_INTEGER || kind == CTF_K_FLOAT) {
		/*
		 * We're looking up an integer or float by name. Unfortunately,
		 * CTF is littered with integer and float types that have the
		 * same name, but different encodings of offsets & sizes
		 * depending on the particular bit field.
		 *
		 * Most critically, the byte sizes will differ among all of
		 * these different definitions, depending on the bit field size!
		 * So a "long unsigned int" which may be 8 bytes on a platform,
		 * but which gets used in a bit field of size 31, would have a
		 * byte size of 4 returned by ctf_type_size(). If we
		 * accidentally looked up an integer type ID which is actually
		 * part of a bitfield (statistically quite likely) then we are
		 * likely to get the wrong type size when we construct the type.
		 *
		 * To avoid this, we have a hash of name to base atomic types
		 * which gets filled at initialization time.  Use that for
		 * looking up integer and float type IDs, so we can be confident
		 * that we have the crorect size.
		 */
		find_canonical(info, name, dict, id_ret);
	}
	return NULL;
}

static struct drgn_error *
drgn_ctf_find_type_name_all_dicts(struct drgn_ctf_info *info, const char *name,
				  ctf_id_t *id_ret, ctf_dict_t **dict_ret)
{
	struct drgn_error *err;

	/*
	 * First, if there's a vmlinux dict, that should have priority over
	 * module type information.
	 */
	if (info->vmlinux) {
		err = drgn_ctf_lookup_by_name(info, info->vmlinux, name, id_ret, dict_ret);
		if (err != &drgn_not_found)
			return err;
	}

	/*
	 * Finally, we search the remaining dicts, which correspond to each
	 * module. There's not actually any guarantee that every module/dict in
	 * the CTF is actually loaded by the program, so it's possible that this
	 * could return a false positive.
	 */
	struct drgn_ctf_dicts_iterator it;
	for (it = drgn_ctf_dicts_first(&info->dicts); it.entry; it = drgn_ctf_dicts_next(it)) {
		ctf_dict_t *dict = it.entry->value;
		/* Don't re-do search */
		if (dict == info->root || dict == info->vmlinux)
			continue;
		err = drgn_ctf_lookup_by_name(info, dict, name, id_ret, dict_ret);
		if (err != &drgn_not_found)
			return err;
	}
	return &drgn_not_found;
}

static struct drgn_error *
drgn_type_from_ctf(enum drgn_type_kind kind, const char *name,
		   size_t name_len, const char *filename,
		   void *arg, struct drgn_qualified_type *ret)
{
	char *name_copy;
	ctf_dict_t *dict = NULL;
	ctf_id_t id;
	struct drgn_ctf_info *info = arg;
	struct drgn_error *err = NULL;

	/*
	 * When filename is provided, we can resolve to a CTF dictionary.
	 * Otherwise, we need to search for it in all dicts.
	 */
	if (filename) {
		err = drgn_ctf_get_dict(info, filename, &dict);
		if (err)
			return err;
	}

	err = format_type_name(kind, name, name_len, &name_copy);
	if (err)
		return err;

	if (dict) {
		err = drgn_ctf_lookup_by_name(info, dict, name_copy, &id, &dict);
	} else {
		err = drgn_ctf_find_type_name_all_dicts(info, name_copy, &id, &dict);
	}
	free(name_copy);
	if (err)
		return err;
	return drgn_type_from_ctf_id(info, dict, id, ret, false);
}

struct drgn_error *
drgn_ctf_find_var(struct drgn_ctf_info *info, const char *name, ctf_dict_t *dict,
		  uint64_t addr, struct drgn_object *ret)
{
	int errnum;
	struct drgn_qualified_type qt = {0};
	struct drgn_error *err;
	ctf_id_t id;

	id = ctf_lookup_variable(dict, name);
	if (id == CTF_ERR) {
		errnum = ctf_errno(dict);
		/*
		 * Reading the libctf source code, there really shouldn't be any
		 * case where ECTF_NEXT_END is returned here... but that's exactly
		 * what I've observed. So handle both NOTYPEDAT and NEXT_END as
		 * not found errors.
		 */
		if (errnum == ECTF_NOTYPEDAT || errnum == ECTF_NEXT_END
		    || errnum == ECTF_NOTYPE)
			err = &drgn_not_found;
		else
			err = drgn_error_ctf(errnum);
		return err;
	}

	err = drgn_type_from_ctf_id(info, dict, id, &qt, NULL);
	if (err)
		return err;

	return drgn_object_set_reference(ret, qt, addr, 0, 0);
}

struct drgn_error *
drgn_ctf_find_var_all_dicts(struct drgn_ctf_info *info, const char *name, uint64_t addr,
			    struct drgn_object *ret)
{
	/* TODO: can we use some smarts here? The "vmlinux" dict gives us all
	 * the types necessary to understand modules, and the drgn improved
	 * module system (when ready) should hopefully be able to tell us which
	 * module an address belongs to.
	 */
	struct drgn_ctf_dicts_iterator it;
	struct drgn_error *err;
	for (it = drgn_ctf_dicts_first(&info->dicts); it.entry; it = drgn_ctf_dicts_next(it)) {
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
	char *name_copy;

	/*
	 * When given a filename, interpret it as a kernel module and use it as
	 * the CTF dictionary name to search. Otherwise, we'll need to search
	 * all of them.
	 * TODO: it may be better to have some way to specify a "default" CTF
	 * dictionary. When filename is not provided, we would search that dict
	 * first, and failing that, we'd search the others.
	 */
	name_copy = strndup(name, name_len);
	if (filename) {
		err = drgn_ctf_get_dict(info, filename, &dict);
		if (err)
			goto out_free;
	}

	if (flags & DRGN_FIND_OBJECT_CONSTANT) {
		err = drgn_ctf_find_constant(info, name_copy, NULL, ret);
		if (!err || err != &drgn_not_found)
			goto out_free;
	}
	if (flags & DRGN_FIND_OBJECT_VARIABLE) {
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
				goto out_free;
		} else {
			err = drgn_ctf_find_var_all_dicts(info, name_copy, addr, ret);
			if( !err || err != &drgn_not_found )
				goto out_free;
		}
	}
	err = &drgn_not_found;
out_free:
	free(name_copy);
	return err;
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
	struct drgn_ctf_atoms_iterator it;
	struct drgn_ctf_atoms_entry entry;
	struct hash_pair hp;
	ctf_encoding_t enc;
	size_t size = ctf_type_size(dict, id);
	struct drgn_error *err = NULL;

	ctf_type_encoding(dict, id, &enc);
	if (enc.cte_offset != 0 || enc.cte_bits != size * 8)
		return 0;

	hp = drgn_ctf_atoms_hash(&name);
	it = drgn_ctf_atoms_search_hashed(&info->atoms, &name, hp);
	if (it.entry) {
		if (size > it.entry->value.size
		    || (size == it.entry->value.size && id < it.entry->value.id)) {
			/*
			 * We'll consider an atom the canonical representation
			 * if it is the largest non-bitfield atom for that name.
			 * Special case, if the atom is non-bitfield and has the
			 * same size of the previous, choose the lowest ID, for
			 * the better chance that it's contained in the root
			 * dict.
			 */
			it.entry->value.dict = dict;
			it.entry->value.id = id;
			it.entry->value.size = size;
		}
	} else {
		entry.key = name;
		entry.value.dict = dict;
		entry.value.id = id;
		entry.value.size = size;
		if (drgn_ctf_atoms_insert_searched(&info->atoms, &entry, hp, NULL) < 0)
			err = &drgn_enomem;
	}
	return err;
}

static int process_type(ctf_id_t type, void *void_arg)
{
	struct drgn_ctf_arg *arg = void_arg;
	if (ctf_type_kind(arg->dict, type) == CTF_K_ENUM) {
		arg->type = type;
		int ret = ctf_enum_iter(arg->dict, type, process_enumerator, void_arg);
		/* For CTF errors, set a drgn error immediately */
		if (ret != 0 && !arg->err)
			arg->err = drgn_error_ctf(ctf_errno(arg->dict));

		arg->type = 0;
		return ret;
	} else if (ctf_type_kind(arg->dict, type) == CTF_K_INTEGER
		   || ctf_type_kind(arg->dict, type) == CTF_K_FLOAT) {
		arg->err = canonical_atom(arg->info, ctf_type_name_raw(arg->dict, type),
					  arg->dict, type);
		return arg->err ? -1 : 0;
	} else {
		return 0;
	}
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

	if (strcmp(name, "shared_ctf") == 0)
		arg->info->root = dict;
	else if (strcmp(name, "vmlinux") == 0)
		arg->info->vmlinux = dict;

	arg->dict = dict;
	arg->dict_name = name;

	int ret = ctf_type_iter(dict, process_type, void_arg);
	/* For CTF errors, set a drgn error immediately */
	if (ret != 0 && !arg->err)
		arg->err = drgn_error_ctf(ctf_errno(dict));

	arg->dict = NULL;
	arg->dict_name = NULL;

	return ret;
}

struct drgn_error *
drgn_program_load_ctf(struct drgn_program *prog, const char *file, struct drgn_ctf_info **ret)
{
	struct drgn_error *err;
	int errnum = 0;
	struct drgn_ctf_info *info = calloc(1, sizeof(*info));

	if (!info)
		return &drgn_enomem;

	info->prog = prog;
	drgn_ctf_dicts_init(&info->dicts);
	drgn_ctf_enums_init(&info->enums);
	drgn_ctf_atoms_init(&info->atoms);
	info->archive = ctf_open(file, NULL, &errnum);
	if (!info->archive) {
		drgn_ctf_dicts_deinit(&info->dicts);
		drgn_ctf_enums_deinit(&info->enums);
		drgn_ctf_atoms_deinit(&info->atoms);
		free(info);
		return drgn_error_format(DRGN_ERROR_OTHER, "ctf_open \"%s\": %s", file, ctf_errmsg(errnum));
	}

	/* While CTF offers efficient type lookup by name in most cases,
	 * enumerator names are a glaring omission here. We'd prefer to avoid
	 * a linear search of each dict, type, and enumerator for every constant
	 * lookup, which means that we'll need an index. */
	struct drgn_ctf_arg arg = {0};
	arg.info = info;
	errnum = ctf_archive_iter(info->archive, process_dict, &arg);
	if (errnum != 0) {
		if (!arg.err)
			arg.err = drgn_error_ctf(errnum);
		err = arg.err;
		goto error;
	}
	if (!info->root || !info->vmlinux) {
		err = drgn_error_format(DRGN_ERROR_OTHER,
					"CTF is missing dictionaries for: %s %s",
					info->root ? "" : "shared_ctf (root dict)",
					info->vmlinux ? "" : "vmlinux");
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
	ctf_close(info->archive);
	drgn_ctf_atoms_deinit(&info->atoms);
	drgn_ctf_enums_deinit(&info->enums);
	drgn_ctf_dicts_deinit(&info->dicts);
	free(info);
	return err;
}
