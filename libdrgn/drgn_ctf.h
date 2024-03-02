// Copyright (c) 2023 Oracle and/or its affiliates
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * @file
 *
 * CTF type format integration
 */

#ifndef DRGN_CTF_H
#define DRGN_CTF_H

#include <ctf-api.h>

#include "hash_table.h"
#include "vector.h"

/* Contains the "ground truth" integer / float name + id */
struct drgn_ctf_names_node {
	ctf_dict_t *dict;
	ctf_id_t id;
	struct drgn_ctf_names_node *next;
};

DEFINE_HASH_MAP(drgn_ctf_names, const char *, struct drgn_ctf_names_node,
		c_string_key_hash_pair, c_string_key_eq);

struct drgn_ctf_enumnode {
	ctf_dict_t *dict;
	ctf_id_t id;
	int64_t val;
	struct drgn_ctf_enumnode *next;
};

DEFINE_HASH_MAP(drgn_ctf_enums, const char *, struct drgn_ctf_enumnode,
		c_string_key_hash_pair, c_string_key_eq);

DEFINE_HASH_MAP(drgn_ctf_dicts, const char *, ctf_dict_t *,
		c_string_key_hash_pair, c_string_key_eq);

struct drgn_ctf_key {
	ctf_dict_t *dict;
	ctf_id_t id;
};

static struct hash_pair
drgn_ctf_key_hash_pair(const struct drgn_ctf_key *key)
{
	size_t hash;
	hash = hash_combine((uintptr_t)key->dict, key->id);
	return hash_pair_from_avalanching_hash(hash);
}

static bool drgn_ctf_key_eq_func(const struct drgn_ctf_key *a, const struct drgn_ctf_key *b)
{
	return a->dict == b->dict && a->id == b->id;
}

DEFINE_HASH_MAP(drgn_ctf_type_map, struct drgn_ctf_key, struct drgn_type *,
		drgn_ctf_key_hash_pair, drgn_ctf_key_eq_func);

struct drgn_ctf_info {
	struct drgn_program *prog;
	char *ctf_data;
	size_t ctf_size;
	ctf_archive_t *archive;
	struct drgn_ctf_dicts dicts;
	struct drgn_ctf_enums enums;
	struct drgn_ctf_names names;
	struct drgn_ctf_type_map types;
	ctf_dict_t *root;
	ctf_dict_t *vmlinux;
	bool bug_reversed_array_indices;
};

struct drgn_error *
drgn_program_load_ctf(struct drgn_program *prog, const char *file, struct drgn_ctf_info **ret);

void drgn_ctf_destroy(struct drgn_ctf_info *info);

#endif // DRGN_CTF_H
