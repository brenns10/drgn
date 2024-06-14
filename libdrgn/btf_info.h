#ifndef BTF_INFO_H_
#define BTF_INFO_H_

#include <stdint.h>

#include "hash_table.h"
#include "object.h"
#include "type.h"
#include "vector.h"

struct drgn_program;
struct drgn_debug_info;

/**
 * Represents an BTF item which can be indexed by name: a variable, a named
 * type, or an enumerator.
 */
struct drgn_btf_index_item {
	/** Drgn module associated with the type ID */
	struct drgn_module *module;
	union {
		/** For variables: the address of the variable */
		uint64_t addr;
		/** For enumerators: the enumerator index */
		uint64_t index;
	};
	/** The indexed type, variable type, or enumerator type */
	uint32_t type_id;
	uint8_t kind;
	unsigned int is_enum : 1;
	unsigned int is_present : 1;
};

struct drgn_btf_module_location {
	uint64_t data_addr;
	uint64_t data_len;
};

DEFINE_VECTOR_TYPE(drgn_btf_index_bucket, struct drgn_btf_index_item);
DEFINE_HASH_MAP_TYPE(drgn_btf_index, const char *, struct drgn_btf_index_bucket);
DEFINE_HASH_MAP_TYPE(drgn_btf_modules, const char *, struct drgn_btf_module_location);

/** BTF type information for the entire program */
struct drgn_btf_info {
	struct drgn_type_finder type_finder;
	struct drgn_object_finder object_finder;
	struct drgn_btf_index htab;
	struct drgn_btf_modules btf_modules;
	bool modules_searched;
};

/** BTF type information for a module */
struct drgn_module_btf_info {
	/** BTF formatted data read from the program */
	void *data;
	/** Handle from libbpf */
	struct btf *btf;
	/** Map from type ID to the drgn_type */
	struct drgn_type **cache;
	/** Cached results from searching the btf_modules list */
	uint64_t btf_data_len;
	uint64_t btf_data_addr;
};

#if WITH_BPF
void drgn_btf_info_init(struct drgn_debug_info *);
void drgn_btf_info_deinit(struct drgn_debug_info *);
void drgn_module_btf_info_deinit(struct drgn_module *);
struct drgn_error *drgn_module_load_btf(struct drgn_module *);
#else
static inline void drgn_btf_info_init(struct drgn_debug_info *dbi) {}
static inline void drgn_btf_info_deinit(struct drgn_debug_info *dbi) {}
static inline void drgn_module_btf_info_deinit(struct drgn_module *mod) {}
static inline struct drgn_error *drgn_module_load_btf(struct drgn_module *mod)
{
	return drgn_error_create(DRGN_ERROR_NOT_IMPLEMENTED,
				 "drgn was not built with libbpf support");
}
#endif
#endif // BTF_INFO_H_
