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

DEFINE_HASH_MAP(drgn_ctf_dicts, const char *, ctf_dict_t *,
		c_string_key_hash_pair, c_string_key_eq);

struct drgn_ctf_info {
	struct drgn_program *prog;
	ctf_archive_t *archive;
	struct drgn_ctf_dicts dicts;
};

struct drgn_error *
drgn_program_load_ctf(struct drgn_program *prog, const char *file, struct drgn_ctf_info **ret);

#endif // DRGN_CTF_H
