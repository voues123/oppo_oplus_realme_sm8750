/* Compatibility hooks required by SukiSU's SELinux policy editor. */
static DEFINE_MUTEX(susfs_mutex_lock_sus_type);
static DEFINE_HASHTABLE(SUS_TYPE_HLIST, 10);

struct st_susfs_sus_type_hlist {
	struct hlist_node node;
};

int susfs_add_sus_type(const char *secctx, u32 type_value)
{
	struct st_susfs_sus_type_hlist *new_entry, *tmp_entry;
	struct hlist_node *tmp_hlist_node;
	int err = 0;

	mutex_lock(&susfs_mutex_lock_sus_type);
	hash_for_each_possible_safe(SUS_TYPE_HLIST, tmp_entry, tmp_hlist_node,
			node, type_value) {
		SUSFS_LOGE("secctx '%s', type_value '%u', was added before already\n",
			secctx, type_value);
		err = -EINVAL;
		goto unlock;
	}

	new_entry = kzalloc(sizeof(*new_entry), GFP_KERNEL);
	if (!new_entry) {
		err = -ENOMEM;
		goto unlock;
	}

	hash_add_rcu(SUS_TYPE_HLIST, &new_entry->node, type_value);
unlock:
	mutex_unlock(&susfs_mutex_lock_sus_type);
	return err;
}

static DEFINE_MUTEX(susfs_mutex_lock_sus_avd_allowed_hlist);
static DEFINE_HASHTABLE(SUS_AVD_ALLOWED_HLIST, 18);

struct susfs_sus_av_rule {
	struct hlist_node node;
	u32 s_type;
	u32 t_type;
	u32 c_type;
	u32 orig_avd_allowed;
};

static inline u32 susfs_av_rule_hash(u32 s_type, u32 t_type, u16 c_type)
{
	u32 h;

	h = hash_32(s_type, 32);
	h ^= rol32(hash_32(t_type, 32), 13);
	h ^= rol32(hash_32((u32)c_type, 32), 19);
	h += h << 13;
	h ^= h >> 7;
	h += h << 17;
	h ^= h >> 5;
	return h;
}

int susfs_add_sus_avd_allowed_by_type(u32 s_type, u32 t_type, u16 c_type,
		u32 orig_avd_allowed)
{
	struct susfs_sus_av_rule *entry, *tmp_entry;
	struct hlist_node *tmp_hlist_node;
	u32 key;

	mutex_lock(&susfs_mutex_lock_sus_avd_allowed_hlist);
	entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry) {
		mutex_unlock(&susfs_mutex_lock_sus_avd_allowed_hlist);
		return -ENOMEM;
	}

	key = susfs_av_rule_hash(s_type, t_type, c_type);
	hash_for_each_possible_safe(SUS_AVD_ALLOWED_HLIST, tmp_entry,
			tmp_hlist_node, node, key) {
		if (tmp_entry->s_type == s_type && tmp_entry->t_type == t_type &&
			tmp_entry->c_type == c_type) {
			kfree(entry);
			mutex_unlock(&susfs_mutex_lock_sus_avd_allowed_hlist);
			return 0;
		}
	}

	entry->s_type = s_type;
	entry->t_type = t_type;
	entry->c_type = c_type;
	entry->orig_avd_allowed = orig_avd_allowed;
	hash_add_rcu(SUS_AVD_ALLOWED_HLIST, &entry->node, key);
	mutex_unlock(&susfs_mutex_lock_sus_avd_allowed_hlist);
	return 0;
}

