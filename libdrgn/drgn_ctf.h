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

/* Contains the "ground truth" integer / float name + id */
struct drgn_ctf_atomnode {
	ctf_dict_t *dict;
	ctf_id_t id;
	size_t size;
	struct drgn_ctf_atomnode *next;
};

DEFINE_HASH_MAP(drgn_ctf_atoms, const char *, struct drgn_ctf_atomnode,
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

struct drgn_ctf_info {
	struct drgn_program *prog;
	ctf_archive_t *archive;
	struct drgn_ctf_dicts dicts;
	struct drgn_ctf_enums enums;
	struct drgn_ctf_atoms atoms;
	ctf_dict_t *root;
	ctf_dict_t *vmlinux;
};

struct drgn_error *
drgn_program_load_ctf(struct drgn_program *prog, const char *file, struct drgn_ctf_info **ret);

#endif // DRGN_CTF_H
