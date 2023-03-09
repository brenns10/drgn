// Copyright (c) 2023 Oracle and/or its affiliates
// SPDX-License-Identifier: LGPL-2.1-or-later
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>

#include <ctf.h>
#include <ctf-api.h>

#include "drgn_ctf.h"
#include "lazy_object.h"
#include "program.h"
#include "type.h"

struct bit_field_info {
	unsigned long bit_offset;
	uint64_t bit_field_size;
};

static struct drgn_error *
drgn_type_from_ctf_id(struct drgn_ctf_info *info, ctf_dict_t *dict,
                      ctf_id_t id, struct drgn_qualified_type *ret,
                      struct bit_field_info *bfi);

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
                      struct bit_field_info *bfi)
{
	ctf_encoding_t enc;
	bool _signed, is_bool, has_bfi;
	const char *name;
	uint64_t size_bytes;
	assert(ctf_type_encoding(dict, id, &enc) == 0);

	has_bfi = enc.cte_offset || (enc.cte_bits & 0x7);
	size_bytes = enc.cte_bits >> 3;

	if (has_bfi && !bfi) {
		return drgn_error_create(
			DRGN_ERROR_OTHER,
			"Integer with bitfield info outside compound type"
		);
	} else if (has_bfi) {
		bfi->bit_offset += enc.cte_offset;
		bfi->bit_field_size = enc.cte_bits;
		if (enc.cte_bits & 0x7) {
			size_bytes = 1 << fls(size_bytes);
		}
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
                    struct bit_field_info *bfi)
{
	ctf_encoding_t enc;
	const char *name;
	bool has_bfi;
	size_t size_bytes;

	assert(ctf_type_encoding(dict, id, &enc) == 0);
	name = ctf_type_name_raw(dict, id);

	has_bfi = enc.cte_offset || (enc.cte_bits & 0x7);
	size_bytes = enc.cte_bits >> 3;
	if (has_bfi && !bfi) {
		return drgn_error_create(
			DRGN_ERROR_OTHER,
			"Integer with bitfield info outside compound type"
		);
	} else if (has_bfi) {
		bfi->bit_offset += enc.cte_offset;
		bfi->bit_field_size = enc.cte_bits;
		if (enc.cte_bits & 0x7) {
			/* Round up to the next power of two */
			size_bytes = 1 << fls(size_bytes);
		}
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
                      ctf_id_t id, struct drgn_qualified_type *ret)
{
	struct drgn_qualified_type aliased;
	struct drgn_error *err;
	const char *name;
	ctf_id_t aliased_id;

	name = ctf_type_name_raw(dict, id);
	aliased_id = ctf_type_reference(dict, id);

	err = drgn_type_from_ctf_id(info, dict, aliased_id, &aliased, NULL);
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

	err = drgn_type_from_ctf_id(info, dict, aliased_id, &aliased, NULL);
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

	err = drgn_type_from_ctf_id(info, dict, arinfo.ctr_contents, &etype, NULL);
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
	struct bit_field_info *bfi;
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
		                            arg->id, &type, arg->bfi);
		if (!err)
			err = drgn_object_set_absent(res, type, arg->bfi ? arg->bfi->bit_field_size : 0);

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

	err = drgn_type_from_ctf_id(info, dict, funcinfo.ctc_return, &qt, NULL);
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

	err = drgn_type_from_ctf_id(info, dict, funcinfo.ctc_return, ret, NULL);
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
	struct bit_field_info bfi;
	ctf_id_t resolved;

	//printf("Compound member %s id %lu\n", name, membtype);
	thunk_arg->dict = arg->dict;
	thunk_arg->info = arg->info;
	thunk_arg->id = membtype;
	drgn_lazy_object_init_thunk(&obj, arg->info->prog, drgn_ctf_thunk, thunk_arg);

	bfi.bit_offset = 0;
	bfi.bit_field_size = 0;

	/* libctf gives us 0-length name for anonymous members, but drgn prefers
	 * NULL. 0-length name seems to be legal, but inaccessible for the API. */
	if (name[0] == '\0')
		name = NULL;

	resolved = ctf_type_resolve(arg->dict, membtype);
	if (resolved != CTF_ERR && (ctf_type_kind(arg->dict, resolved) == CTF_K_INTEGER ||
	                            ctf_type_kind(arg->dict, resolved) == CTF_K_FLOAT)) {
		/*
		 * CTF allows offset information to reside within the type entry
		 * for integers and floats. This is kinda frustrating because we
		 * don't want to greedily lookup every type in a compound type,
		 * but we do need to update our offset value when creating these
		 * members. This is our solution.
		 *
		 * We evaluate the lazy object only when we see a member whose
		 * resolved type is an integer or float, *and* when that member
		 * has an offset. That way, it updates our "offset" variable.
		 *
		 * While we could simply grab the "cte_offset" and add that to
		 * the offset info we already have, and then leave the lazy
		 * object unevaluated, that causes one major issue: we won't be
		 * able to handle error cases where an offset is provided in an
		 * integer type, but it was unexpected. By doing it this way,
		 * the "offset" checks in drgn_{integer,float}_from_ctf will
		 * properly know when it's ok to have a cte_offset value, and
		 * when it's not.
		 */
		ctf_encoding_t enc;
		ctf_type_encoding(arg->dict, resolved, &enc);
		if (enc.cte_offset || enc.cte_bits & 0x7) {
			//printf("Found member %s with offset %lu + %u\n", name, offset, enc.cte_offset);
			thunk_arg->bfi = &bfi;
			arg->err = drgn_lazy_object_evaluate(&obj);
			if (arg->err) {
				drgn_lazy_object_deinit(&obj);
				return -1;
			}
			//printf("Now offset is %lu\n", offset);
		}
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
		      struct bit_field_info *bfi)
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
			return drgn_integer_from_ctf(info, dict, id, ret, bfi);
		case CTF_K_FLOAT:
			return drgn_float_from_ctf(info, dict, id, ret, bfi);
		case CTF_K_TYPEDEF:
			return drgn_typedef_from_ctf(info, dict, id, ret);
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

static struct drgn_error *
drgn_type_from_ctf(enum drgn_type_kind kind, const char *name,
		   size_t name_len, const char *filename,
		   void *arg, struct drgn_qualified_type *ret)
{
	char *name_copy;
	ctf_dict_t *dict;
	ctf_id_t id;
	struct drgn_ctf_info *info = arg;
	int errnum;
	struct drgn_error *err;

	if (!filename)
		filename = "vmlinux";

	err = drgn_ctf_get_dict(info, filename, &dict);
	if (err) {
		return err;
	}

	//printf("drgn_type_from_ctf(%d, \"%.*s\", \"%s\")\n", kind, (int)name_len, name, filename);
	err = format_type_name(kind, name, name_len, &name_copy);
	if (err)
		return err;

	id = ctf_lookup_by_name(dict, name_copy);
	free(name_copy);

	errnum = ctf_errno(dict);
	if (id == CTF_ERR && errnum == ECTF_NOTYPE)
		return &drgn_not_found;
	else if (id == CTF_ERR)
		return drgn_error_ctf(errnum);
	return drgn_type_from_ctf_id(info, dict, id, ret, NULL);
}

struct drgn_error *
drgn_program_load_ctf(struct drgn_program *prog, const char *file, struct drgn_ctf_info **ret)
{
	int err = 0;
	struct drgn_ctf_info *info = calloc(1, sizeof(*info));

	if (!info)
		return &drgn_enomem;

	info->prog = prog;
	drgn_ctf_dicts_init(&info->dicts);
	info->archive = ctf_open(file, NULL, &err);
	if (!info->archive) {
		drgn_ctf_dicts_deinit(&info->dicts);
		free(info);
		return drgn_error_format(DRGN_ERROR_OTHER,
					 "Failed to load CTF data from \"%s\"", file);
	}

	*ret = info;
	drgn_program_add_type_finder(prog, drgn_type_from_ctf, info);
	return NULL;
}
