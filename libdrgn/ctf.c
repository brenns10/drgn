#include <assert.h>
#include <ctf.h>
#include <stdlib.h>

#include <ctf-api.h>

#include "drgn.h"
#include "lazy_object.h"
#include "program.h"
#include "kernel_info.h"
#include "type.h"

struct bit_field_info {
	unsigned long bit_offset;
	uint64_t bit_field_size;
};

static struct drgn_error *
drgn_type_from_ctf_id(struct drgn_program *prog, ctf_dict_t *dict,
                      ctf_id_t id, struct drgn_qualified_type *ret,
                      struct bit_field_info *bfi);

static struct drgn_error *
drgn_type_from_ctf(enum drgn_type_kind kind, const char *name,
		   size_t name_len, const char *filename,
		   void *arg, struct drgn_qualified_type *ret);

static struct drgn_error *drgn_error_ctf(int err)
{
	return drgn_error_format(DRGN_ERROR_OTHER, "Internal CTF error: %s", ctf_errmsg(errno));
}

static struct drgn_error *
drgn_integer_from_ctf(struct drgn_program *prog, ctf_dict_t *dict,
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
		ret->type = drgn_void_type(prog, &drgn_language_c);
	} else if (is_bool) {
		return drgn_bool_type_create(prog, name, size_bytes,
		                             DRGN_PROGRAM_ENDIAN,
					     &drgn_language_c, &ret->type);
	} else {
		return drgn_int_type_create(prog, name, size_bytes,
		                            _signed, DRGN_PROGRAM_ENDIAN,
					    &drgn_language_c, &ret->type);
	}
	return NULL;
}

static struct drgn_error *
drgn_float_from_ctf(struct drgn_program *prog, ctf_dict_t *dict,
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

	return drgn_float_type_create(prog, name, size_bytes, DRGN_PROGRAM_ENDIAN,
	                              &drgn_language_c, &ret->type);
}

static struct drgn_error *
drgn_typedef_from_ctf(struct drgn_program *prog, ctf_dict_t *dict,
                      ctf_id_t id, struct drgn_qualified_type *ret)
{
	struct drgn_qualified_type aliased;
	struct drgn_error *err;
	const char *name;
	ctf_id_t aliased_id;

	name = ctf_type_name_raw(dict, id);
	aliased_id = ctf_type_reference(dict, id);

	err = drgn_type_from_ctf_id(prog, dict, aliased_id, &aliased, NULL);
	if (err)
		return err;

	return drgn_typedef_type_create(prog, name, aliased, &drgn_language_c, &ret->type);
}

static struct drgn_error *
drgn_pointer_from_ctf(struct drgn_program *prog, ctf_dict_t *dict,
                      ctf_id_t id, struct drgn_qualified_type *ret)
{
	struct drgn_qualified_type aliased;
	struct drgn_error *err;
	ctf_id_t aliased_id;

	aliased_id = ctf_type_reference(dict, id);

	err = drgn_type_from_ctf_id(prog, dict, aliased_id, &aliased, NULL);
	if (err)
		return err;

	return drgn_pointer_type_create(prog, aliased, 8, DRGN_PROGRAM_ENDIAN,
	                                &drgn_language_c, &ret->type);
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
drgn_enum_from_ctf(struct drgn_program *prog, ctf_dict_t *dict,
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
	arg.err = drgn_type_from_ctf(DRGN_TYPE_INT, "int", 3, NULL, prog,
				 &compatible_type);
	if (arg.err)
		return arg.err;

	drgn_enum_type_builder_init(&builder, prog);

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
drgn_array_from_ctf(struct drgn_program *prog, ctf_dict_t *dict,
                    ctf_id_t id, struct drgn_qualified_type *ret)
{
	struct drgn_qualified_type etype;
	struct drgn_error *err;
	ctf_arinfo_t info;

	ctf_array_info(dict, id, &info);

	err = drgn_type_from_ctf_id(prog, dict, info.ctr_contents, &etype, NULL);
	if (err)
		return err;

	if (info.ctr_nelems)
		return drgn_array_type_create(prog, etype, info.ctr_nelems,
		                              &drgn_language_c, &ret->type);
	else
		return drgn_incomplete_array_type_create(prog, etype,
		                                         &drgn_language_c,
		                                         &ret->type);
}

struct drgn_ctf_thunk_arg {
	struct drgn_program *prog;
	ctf_dict_t *dict;
	ctf_id_t id;
	struct bit_field_info *bfi;
};

static struct drgn_error *drgn_ctf_thunk(struct drgn_object *res, void *void_arg)
{
	struct drgn_ctf_thunk_arg *arg = void_arg;
	struct drgn_qualified_type type;
	struct drgn_error *err = NULL;

	if (res) {
		//printf("thunk id %lu\n", arg->id);
		err = drgn_type_from_ctf_id(arg->prog, arg->dict,
		                            arg->id, &type, arg->bfi);
		if (!err)
			err = drgn_object_set_absent(res, type, arg->bfi ? arg->bfi->bit_field_size : 0);
	} else {
		//printf("thunk to free!\n");
	}

	free(arg);
	return err;
}

static struct drgn_error *
drgn_function_from_ctf(struct drgn_program *prog, ctf_dict_t *dict,
                       ctf_id_t id, struct drgn_qualified_type *ret)
{
	struct drgn_function_type_builder builder;
	struct drgn_qualified_type qt;
	struct drgn_error *err;
	ctf_funcinfo_t info;
	ctf_id_t *argtypes;
	bool variadic = false;

	//printf("Create function type for id %lu\n", id);

	ctf_func_type_info(dict, id, &info);
	argtypes = calloc(info.ctc_argc, sizeof(*argtypes));
	if (!argtypes)
		return &drgn_enomem;
	ctf_func_type_args(dict, id, info.ctc_argc, argtypes);

	drgn_function_type_builder_init(&builder, prog);

	err = drgn_type_from_ctf_id(prog, dict, info.ctc_return, &qt, NULL);
	if (err)
		goto out;

	for (size_t i = 0; i < info.ctc_argc; i++) {
		union drgn_lazy_object param;
		struct drgn_ctf_thunk_arg *arg;

		if (argtypes[i] == 0 && i + 1 == info.ctc_argc) {
			variadic = true;
			break;
		}

		arg = calloc(1, sizeof(*arg));
		if (!arg) {
			err = &drgn_enomem;
			goto out;
		}
		arg->prog = prog;
		arg->dict = dict;
		arg->id = argtypes[i];
		drgn_lazy_object_init_thunk(&param, prog, drgn_ctf_thunk, arg);
		err = drgn_function_type_builder_add_parameter(&builder, &param, NULL);
		//printf("add param index %lu id %lu\n", i, argtypes[i]);
		if (err) {
			drgn_lazy_object_deinit(&param);
			goto out;
		}
	}
	free(argtypes);
	argtypes = NULL;

	err = drgn_type_from_ctf_id(prog, dict, info.ctc_return, ret, NULL);
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
	struct drgn_program *prog;
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
	thunk_arg->prog = arg->prog;
	thunk_arg->id = membtype;
	drgn_lazy_object_init_thunk(&obj, arg->prog, drgn_ctf_thunk, thunk_arg);

	bfi.bit_offset = 0;
	bfi.bit_field_size = 0;

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
drgn_compound_type_from_ctf(enum drgn_type_kind kind, struct drgn_program *prog, ctf_dict_t *dict,
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

	drgn_compound_type_builder_init(&builder, prog, kind);

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
	arg.prog = prog;
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
drgn_forward_from_ctf(struct drgn_program *prog, ctf_dict_t *dict,
                      ctf_id_t id, struct drgn_qualified_type *ret)
{
	int ctf_kind = ctf_type_kind_forwarded(dict, id);
	const char *name = ctf_type_name_raw(dict, id);

	if (name && !*name)
		name = NULL;

	//printf("Forward %s\n", name);
	switch (ctf_kind) {
		case CTF_K_ENUM:
			return drgn_enum_from_ctf(prog, dict, id, ret);
		case CTF_K_STRUCT:
			return drgn_compound_type_from_ctf(DRGN_TYPE_STRUCT, prog, dict, id, ret);
		case CTF_K_UNION:
			return drgn_compound_type_from_ctf(DRGN_TYPE_UNION, prog, dict, id, ret);
		default:
			return drgn_error_format(DRGN_ERROR_OTHER, "Forwarded CTF type id %lu, kind %d, is not enum, struct, or union", id, ctf_kind);
	}
}

static struct drgn_error *
drgn_type_from_ctf_id(struct drgn_program *prog, ctf_dict_t *dict,
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
			return drgn_integer_from_ctf(prog, dict, id, ret, bfi);
		case CTF_K_FLOAT:
			return drgn_float_from_ctf(prog, dict, id, ret, bfi);
		case CTF_K_TYPEDEF:
			return drgn_typedef_from_ctf(prog, dict, id, ret);
		case CTF_K_POINTER:
			return drgn_pointer_from_ctf(prog, dict, id, ret);
		case CTF_K_ENUM:
			return drgn_enum_from_ctf(prog, dict, id, ret);
		case CTF_K_FUNCTION:
			return drgn_function_from_ctf(prog, dict, id, ret);
		case CTF_K_ARRAY:
			return drgn_array_from_ctf(prog, dict, id, ret);
		case CTF_K_STRUCT:
			return drgn_compound_type_from_ctf(DRGN_TYPE_STRUCT, prog, dict, id, ret);
		case CTF_K_UNION:
			return drgn_compound_type_from_ctf(DRGN_TYPE_UNION, prog, dict, id, ret);
		case CTF_K_FORWARD:
			return drgn_forward_from_ctf(prog, dict, id, ret);
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

static struct drgn_error *
drgn_type_from_ctf(enum drgn_type_kind kind, const char *name,
		   size_t name_len, const char *filename,
		   void *arg, struct drgn_qualified_type *ret)
{
	char *name_copy;
	ctf_dict_t *dict;
	ctf_id_t id;
	struct drgn_program *prog = arg;
	struct kernel_info *info = prog->kinfo;
	int errnum;
	struct drgn_error *err;

	//printf("drgn_type_from_ctf(%d, \"%.*s\", \"%s\")\n", kind, (int)name_len, name, filename);
	err = format_type_name(kind, name, name_len, &name_copy);
	if (err)
		return err;

	if (!filename)
		filename = "vmlinux";

	// TODO: we should open once per dict, per program. Currently leaks.
	dict = ctf_dict_open(info->ctf, filename, &errnum);
	if (!dict) {
		free(name_copy);
		return drgn_error_format(DRGN_ERROR_LOOKUP, "Could not find CTF dictionary \"%s\"", filename);
	}

	id = ctf_lookup_by_name(dict, name_copy);
	free(name_copy);

	errnum = ctf_errno(dict);
	if (id == CTF_ERR && errnum == ECTF_NOTYPE)
		return &drgn_not_found;
	else if (id == CTF_ERR)
		return drgn_error_ctf(errnum);
	return drgn_type_from_ctf_id(prog, dict, id, ret, NULL);
}

struct drgn_error *
drgn_ctf_find_object(const char *name, size_t name_len,
		     const char *filename,
		     enum drgn_find_object_flags flags, void *arg,
		     struct drgn_object *ret)
{
	struct drgn_error *err = NULL;
	struct drgn_program *prog = arg;
	struct drgn_qualified_type qt;
	ctf_archive_t *arc = prog->kinfo->ctf;
	ctf_dict_t *dict;
	ctf_id_t id;
	struct drgn_symbol *sym = NULL;
	int errnum;
	char *name_copy;
	uint64_t addr;

	printf("drgn_ctf_find_object(\"%.*s\", \"%s\", %d, ...)\n",
	       (int)name_len, name, filename, flags);

	if (!filename)
		filename = "vmlinux";

	name_copy = strndup(name, name_len);

	// TODO: we should open once per dict, per program. Currently leaks.
	dict = ctf_dict_open(arc, filename, &errnum);
	if (!dict) {
		err = drgn_error_format(DRGN_ERROR_LOOKUP, "Could not find CTF dictionary \"%s\"", filename);
		goto out_free;
	}

	err = drgn_program_find_symbol_by_name(prog, name, &sym);
	if (err)
		goto out_free;
	addr = sym->address;
	drgn_symbol_destroy(sym);
	sym = NULL;

	id = ctf_lookup_variable(dict, name_copy);
	if (id == CTF_ERR) {
		errnum = ctf_errno(dict);
		if (errnum == ECTF_NOTYPEDAT)
			err = drgn_error_create(DRGN_ERROR_LOOKUP, "not found");
		else
			err = drgn_error_ctf(ctf_errno(dict));
		goto out_free;
	}

	err = drgn_type_from_ctf_id(prog, dict, id, &qt, NULL);
	if (err)
		goto out_free;

	free(name_copy);
	err = drgn_object_set_reference(ret, qt, addr, 0, 0);
	if (err)
		return err;
	//printf("Successfully returning object, bit size %lu\n", ret->bit_size);
	return NULL;

out_free:
	free(name_copy);
	return err;
}

struct drgn_error *
drgn_program_try_load_ctf(struct drgn_program *prog)
{
	struct drgn_error *err;
	char *file = getenv("DRGN_CTF_FILE");
	int errnum = 0;
	if (!file)
		return NULL;

	printf("Attempting to load CTF from %s\n", file);

	prog->kinfo->ctf = ctf_open(file, NULL, &errnum);
	if (!prog->kinfo->ctf) {
		return drgn_error_format(DRGN_ERROR_OTHER, "Failed to load CTF data from \"%s\"", file);
	}

	err = drgn_program_add_type_finder(prog, drgn_type_from_ctf, prog);
	if (err)
		goto error;

	err = drgn_program_add_object_finder(prog, drgn_ctf_find_object, prog);
	if (err)
		goto error; /* TODO: cleanup type finder? */

	printf("Successfully loaded CTF\n");
	return NULL;
error:
	ctf_close(prog->kinfo->ctf);
	prog->kinfo->ctf = NULL;
	return err;
}
