/*
 * Scheduler topology setup/handling methods
 */
#include <linux/sched.h>
#include <linux/mutex.h>

#include "sched.h"

DEFINE_MUTEX(sched_domains_mutex);

cpumask_var_t sched_domains_tmpmask; /* sched_domains_mutex */

#ifdef CONFIG_SCHED_DEBUG

static __read_mostly int sched_debug_enabled;

static int __init sched_debug_setup(char *str)
{
	sched_debug_enabled = 1;

	return 0;
}
early_param("sched_debug", sched_debug_setup);

static inline bool sched_debug(void)
{
	return sched_debug_enabled;
}

static int sched_domain_debug_one(struct sched_domain *sd, int cpu, int level,
				  struct cpumask *groupmask)
{
	struct sched_group *group = sd->groups;

	cpumask_clear(groupmask);

	printk(KERN_DEBUG "%*s domain %d: ", level, "", level);

	if (!(sd->flags & SD_LOAD_BALANCE)) {
		printk("does not load-balance\n");
		return -1;
	}

	printk(KERN_CONT "span %*pbl level %s\n",
	       cpumask_pr_args(sched_domain_span(sd)), sd->name);

	if (!cpumask_test_cpu(cpu, sched_domain_span(sd))) {
		printk(KERN_ERR "ERROR: domain->span does not contain "
				"CPU%d\n", cpu);
	}
	if (!cpumask_test_cpu(cpu, sched_group_cpus(group))) {
		printk(KERN_ERR "ERROR: domain->groups does not contain"
				" CPU%d\n", cpu);
	}

	printk(KERN_DEBUG "%*s groups:", level + 1, "");
	do {
		if (!group) {
			printk("\n");
			printk(KERN_ERR "ERROR: group is NULL\n");
			break;
		}

		if (!cpumask_weight(sched_group_cpus(group))) {
			printk(KERN_CONT "\n");
			printk(KERN_ERR "ERROR: empty group\n");
			break;
		}

		if (!(sd->flags & SD_OVERLAP) &&
		    cpumask_intersects(groupmask, sched_group_cpus(group))) {
			printk(KERN_CONT "\n");
			printk(KERN_ERR "ERROR: repeated CPUs\n");
			break;
		}

		cpumask_or(groupmask, groupmask, sched_group_cpus(group));

		printk(KERN_CONT " %*pbl",
		       cpumask_pr_args(sched_group_cpus(group)));
		if (group->sgc->capacity != SCHED_CAPACITY_SCALE) {
			printk(KERN_CONT " (cpu_capacity = %lu)",
				group->sgc->capacity);
		}

		group = group->next;
	} while (group != sd->groups);
	printk(KERN_CONT "\n");

	if (!cpumask_equal(sched_domain_span(sd), groupmask))
		printk(KERN_ERR "ERROR: groups don't span domain->span\n");

	if (sd->parent &&
	    !cpumask_subset(groupmask, sched_domain_span(sd->parent)))
		printk(KERN_ERR "ERROR: parent span is not a superset "
			"of domain->span\n");
	return 0;
}

static void sched_domain_debug(struct sched_domain *sd, int cpu)
{
	int level = 0;

	if (!sched_debug_enabled)
		return;

	if (!sd) {
		printk(KERN_DEBUG "CPU%d attaching NULL sched-domain.\n", cpu);
		return;
	}

	printk(KERN_DEBUG "CPU%d attaching sched-domain:\n", cpu);

	for (;;) {
		if (sched_domain_debug_one(sd, cpu, level, sched_domains_tmpmask))
			break;
		level++;
		sd = sd->parent;
		if (!sd)
			break;
	}
}
#else /* !CONFIG_SCHED_DEBUG */

# define sched_debug_enabled 0
# define sched_domain_debug(sd, cpu) do { } while (0)
static inline bool sched_debug(void)
{
	return false;
}
#endif /* CONFIG_SCHED_DEBUG */

static int sd_degenerate(struct sched_domain *sd)
{
	if (cpumask_weight(sched_domain_span(sd)) == 1) {
		if (sd->groups->sge)
			sd->flags &= ~SD_LOAD_BALANCE;
		else
			return 1;
	}

	/* Following flags need at least 2 groups */
	if (sd->flags & (SD_LOAD_BALANCE |
			 SD_BALANCE_NEWIDLE |
			 SD_BALANCE_FORK |
			 SD_BALANCE_EXEC |
			 SD_SHARE_CPUCAPACITY |
			 SD_ASYM_CPUCAPACITY |
			 SD_SHARE_PKG_RESOURCES |
			 SD_SHARE_POWERDOMAIN |
			 SD_SHARE_CAP_STATES)) {
		if (sd->groups != sd->groups->next)
			return 0;
	}

	/* Following flags don't use groups */
	if (sd->flags & (SD_WAKE_AFFINE))
		return 0;

	return 1;
}

static int
sd_parent_degenerate(struct sched_domain *sd, struct sched_domain *parent)
{
	unsigned long cflags = sd->flags, pflags = parent->flags;

	if (sd_degenerate(parent))
		return 1;

	if (!cpumask_equal(sched_domain_span(sd), sched_domain_span(parent)))
		return 0;

	/* Flags needing groups don't count if only 1 group in parent */
	if (parent->groups == parent->groups->next) {
		pflags &= ~(SD_LOAD_BALANCE |
				SD_BALANCE_NEWIDLE |
				SD_BALANCE_FORK |
				SD_BALANCE_EXEC |
				SD_ASYM_CPUCAPACITY |
				SD_SHARE_CPUCAPACITY |
				SD_SHARE_PKG_RESOURCES |
				SD_PREFER_SIBLING |
				SD_SHARE_POWERDOMAIN |
				SD_SHARE_CAP_STATES);
		if (parent->groups->sge) {
			parent->flags &= ~SD_LOAD_BALANCE;
			return 0;
		}
		if (nr_node_ids == 1)
			pflags &= ~SD_SERIALIZE;
	}
	if (~cflags & pflags)
		return 0;

	return 1;
}

static void free_rootdomain(struct rcu_head *rcu)
{
	struct root_domain *rd = container_of(rcu, struct root_domain, rcu);

	cpupri_cleanup(&rd->cpupri);
	cpudl_cleanup(&rd->cpudl);
	free_cpumask_var(rd->dlo_mask);
	free_cpumask_var(rd->rto_mask);
	free_cpumask_var(rd->online);
	free_cpumask_var(rd->span);
	kfree(rd);
}

void rq_attach_root(struct rq *rq, struct root_domain *rd)
{
	struct root_domain *old_rd = NULL;
	unsigned long flags;

	raw_spin_lock_irqsave(&rq->lock, flags);

	if (rq->rd) {
		old_rd = rq->rd;

		if (cpumask_test_cpu(rq->cpu, old_rd->online))
			set_rq_offline(rq);

		cpumask_clear_cpu(rq->cpu, old_rd->span);

		/*
		 * If we dont want to free the old_rd yet then
		 * set old_rd to NULL to skip the freeing later
		 * in this function:
		 */
		if (!atomic_dec_and_test(&old_rd->refcount))
			old_rd = NULL;
	}

	atomic_inc(&rd->refcount);
	rq->rd = rd;

	cpumask_set_cpu(rq->cpu, rd->span);
	if (cpumask_test_cpu(rq->cpu, cpu_active_mask))
		set_rq_online(rq);

	raw_spin_unlock_irqrestore(&rq->lock, flags);

	if (old_rd)
		call_rcu_sched(&old_rd->rcu, free_rootdomain);
}

void sched_get_rd(struct root_domain *rd)
{
	atomic_inc(&rd->refcount);
}

void sched_put_rd(struct root_domain *rd)
{
	if (!atomic_dec_and_test(&rd->refcount))
		return;

	call_rcu_sched(&rd->rcu, free_rootdomain);
}

static int init_rootdomain(struct root_domain *rd)
{
	memset(rd, 0, sizeof(*rd));

	if (!zalloc_cpumask_var(&rd->span, GFP_KERNEL))
		goto out;
	if (!zalloc_cpumask_var(&rd->online, GFP_KERNEL))
		goto free_span;
	if (!zalloc_cpumask_var(&rd->dlo_mask, GFP_KERNEL))
		goto free_online;
	if (!zalloc_cpumask_var(&rd->rto_mask, GFP_KERNEL))
		goto free_dlo_mask;

#ifdef HAVE_RT_PUSH_IPI
	rd->rto_cpu = -1;
	raw_spin_lock_init(&rd->rto_lock);
	init_irq_work(&rd->rto_push_work, rto_push_irq_work_func);
#endif

	init_dl_bw(&rd->dl_bw);
	if (cpudl_init(&rd->cpudl) != 0)
		goto free_rto_mask;

	if (cpupri_init(&rd->cpupri) != 0)
		goto free_cpudl;

	init_max_cpu_capacity(&rd->max_cpu_capacity);

	rd->max_cap_orig_cpu = rd->min_cap_orig_cpu = -1;

	return 0;

free_cpudl:
	cpudl_cleanup(&rd->cpudl);
free_rto_mask:
	free_cpumask_var(rd->rto_mask);
free_dlo_mask:
	free_cpumask_var(rd->dlo_mask);
free_online:
	free_cpumask_var(rd->online);
free_span:
	free_cpumask_var(rd->span);
out:
	return -ENOMEM;
}

/*
 * By default the system creates a single root-domain with all cpus as
 * members (mimicking the global state we have today).
 */
struct root_domain def_root_domain;

void init_defrootdomain(void)
{
	init_rootdomain(&def_root_domain);

	atomic_set(&def_root_domain.refcount, 1);
}

static struct root_domain *alloc_rootdomain(void)
{
	struct root_domain *rd;

	rd = kmalloc(sizeof(*rd), GFP_KERNEL);
	if (!rd)
		return NULL;

	if (init_rootdomain(rd) != 0) {
		kfree(rd);
		return NULL;
	}

	return rd;
}

static void free_sched_groups(struct sched_group *sg, int free_sgc)
{
	struct sched_group *tmp, *first;

	if (!sg)
		return;

	first = sg;
	do {
		tmp = sg->next;

		if (free_sgc && atomic_dec_and_test(&sg->sgc->ref))
			kfree(sg->sgc);

		kfree(sg);
		sg = tmp;
	} while (sg != first);
}

static void destroy_sched_domain(struct sched_domain *sd)
{
	/*
	 * If its an overlapping domain it has private groups, iterate and
	 * nuke them all.
	 */
	if (sd->flags & SD_OVERLAP) {
		free_sched_groups(sd->groups, 1);
	} else if (atomic_dec_and_test(&sd->groups->ref)) {
		kfree(sd->groups->sgc);
		kfree(sd->groups);
	}
	if (sd->shared && atomic_dec_and_test(&sd->shared->ref))
		kfree(sd->shared);
	kfree(sd);
}

static void destroy_sched_domains_rcu(struct rcu_head *rcu)
{
	struct sched_domain *sd = container_of(rcu, struct sched_domain, rcu);

	while (sd) {
		struct sched_domain *parent = sd->parent;
		destroy_sched_domain(sd);
		sd = parent;
	}
}

static void destroy_sched_domains(struct sched_domain *sd)
{
	if (sd)
		call_rcu(&sd->rcu, destroy_sched_domains_rcu);
}

/*
 * Keep a special pointer to the highest sched_domain that has
 * SD_SHARE_PKG_RESOURCE set (Last Level Cache Domain) for this
 * allows us to avoid some pointer chasing select_idle_sibling().
 *
 * Also keep a unique ID per domain (we use the first cpu number in
 * the cpumask of the domain), this allows us to quickly tell if
 * two cpus are in the same cache domain, see cpus_share_cache().
 */
DEFINE_PER_CPU(struct sched_domain *, sd_llc);
DEFINE_PER_CPU(int, sd_llc_size);
DEFINE_PER_CPU(int, sd_llc_id);
DEFINE_PER_CPU(struct sched_domain_shared *, sd_llc_shared);
DEFINE_PER_CPU(struct sched_domain *, sd_numa);
DEFINE_PER_CPU(struct sched_domain *, sd_asym_packing);
DEFINE_PER_CPU(struct sched_domain *, sd_asym_cpucapacity);
DEFINE_PER_CPU(struct sched_domain *, sd_ea);
DEFINE_PER_CPU(struct sched_domain *, sd_scs);

static void update_top_cache_domain(int cpu)
{
	struct sched_domain_shared *sds = NULL;
	struct sched_domain *sd;
	struct sched_domain *ea_sd = NULL;
	int id = cpu;
	int size = 1;

	sd = highest_flag_domain(cpu, SD_SHARE_PKG_RESOURCES);
	if (sd) {
		id = cpumask_first(sched_domain_span(sd));
		size = cpumask_weight(sched_domain_span(sd));
		sds = sd->shared;
	}

	rcu_assign_pointer(per_cpu(sd_llc, cpu), sd);
	per_cpu(sd_llc_size, cpu) = size;
	per_cpu(sd_llc_id, cpu) = id;
	rcu_assign_pointer(per_cpu(sd_llc_shared, cpu), sds);

	sd = lowest_flag_domain(cpu, SD_NUMA);
	rcu_assign_pointer(per_cpu(sd_numa, cpu), sd);

	sd = highest_flag_domain(cpu, SD_ASYM_PACKING);
	rcu_assign_pointer(per_cpu(sd_asym_packing, cpu), sd);

	sd = lowest_flag_domain(cpu, SD_ASYM_CPUCAPACITY);
	rcu_assign_pointer(per_cpu(sd_asym_cpucapacity, cpu), sd);

	for_each_domain(cpu, sd) {
		if (sd->groups->sge)
			ea_sd = sd;
		else
			break;
	}
	rcu_assign_pointer(per_cpu(sd_ea, cpu), ea_sd);

	sd = highest_flag_domain(cpu, SD_SHARE_CAP_STATES);
	rcu_assign_pointer(per_cpu(sd_scs, cpu), sd);
}

/*
 * Attach the domain 'sd' to 'cpu' as its base domain. Callers must
 * hold the hotplug lock.
 */
static void
cpu_attach_domain(struct sched_domain *sd, struct root_domain *rd, int cpu)
{
	struct rq *rq = cpu_rq(cpu);
	struct sched_domain *tmp;

	/* Remove the sched domains which do not contribute to scheduling. */
	for (tmp = sd; tmp; ) {
		struct sched_domain *parent = tmp->parent;
		if (!parent)
			break;

		if (sd_parent_degenerate(tmp, parent)) {
			tmp->parent = parent->parent;
			if (parent->parent)
				parent->parent->child = tmp;
			/*
			 * Transfer SD_PREFER_SIBLING down in case of a
			 * degenerate parent; the spans match for this
			 * so the property transfers.
			 */
			if (parent->flags & SD_PREFER_SIBLING)
				tmp->flags |= SD_PREFER_SIBLING;
			destroy_sched_domain(parent);
		} else
			tmp = tmp->parent;
	}

	if (sd && sd_degenerate(sd)) {
		tmp = sd;
		sd = sd->parent;
		destroy_sched_domain(tmp);
		if (sd)
			sd->child = NULL;
	}

	sched_domain_debug(sd, cpu);

	rq_attach_root(rq, rd);
	tmp = rq->sd;
	rcu_assign_pointer(rq->sd, sd);
	destroy_sched_domains(tmp);

	update_top_cache_domain(cpu);
}

/* Setup the mask of cpus configured for isolated domains */
static int __init isolated_cpu_setup(char *str)
{
	int ret;

	alloc_bootmem_cpumask_var(&cpu_isolated_map);
	ret = cpulist_parse(str, cpu_isolated_map);
	if (ret) {
		pr_err("sched: Error, all isolcpus= values must be between 0 and %d\n", nr_cpu_ids);
		return 0;
	}
	return 1;
}
__setup("isolcpus=", isolated_cpu_setup);

struct s_data {
	struct sched_domain ** __percpu sd;
	struct root_domain	*rd;
};

enum s_alloc {
	sa_rootdomain,
	sa_sd,
	sa_sd_storage,
	sa_none,
};

/*
 * Build an iteration mask that can exclude certain CPUs from the upwards
 * domain traversal.
 *
 * Only CPUs that can arrive at this group should be considered to continue
 * balancing.
 *
 * Asymmetric node setups can result in situations where the domain tree is of
 * unequal depth, make sure to skip domains that already cover the entire
 * range.
 *
 * In that case build_sched_domains() will have terminated the iteration early
 * and our sibling sd spans will be empty. Domains should always include the
 * cpu they're built on, so check that.
 *
 */
static void build_group_mask(struct sched_domain *sd, struct sched_group *sg)
{
	const struct cpumask *sg_span = sched_group_cpus(sg);
	struct sd_data *sdd = sd->private;
	struct sched_domain *sibling;
	int i;

	for_each_cpu(i, sg_span) {
		sibling = *per_cpu_ptr(sdd->sd, i);

		/*
		 * Can happen in the asymmetric case, where these siblings are
		 * unused. The mask will not be empty because those CPUs that
		 * do have the top domain _should_ span the domain.
		 */
		if (!sibling->child)
			continue;

		/* If we would not end up here, we can't continue from here */
		if (!cpumask_equal(sg_span, sched_domain_span(sibling->child)))
			continue;

		cpumask_set_cpu(i, sched_group_mask(sg));
	}

	/* We must not have empty masks here */
	WARN_ON_ONCE(cpumask_empty(sched_group_mask(sg)));
}

/*
 * Return the canonical balance cpu for this group, this is the first cpu
 * of this group that's also in the iteration mask.
 */
int group_balance_cpu(struct sched_group *sg)
{
	return cpumask_first_and(sched_group_cpus(sg), sched_group_mask(sg));
}

static int
build_overlap_sched_groups(struct sched_domain *sd, int cpu)
{
	struct sched_group *first = NULL, *last = NULL, *groups = NULL, *sg;
	const struct cpumask *span = sched_domain_span(sd);
	struct cpumask *covered = sched_domains_tmpmask;
	struct sd_data *sdd = sd->private;
	struct sched_domain *sibling;
	int i;

	cpumask_clear(covered);

	for_each_cpu_wrap(i, span, cpu) {
		struct cpumask *sg_span;

		if (cpumask_test_cpu(i, covered))
			continue;

		sibling = *per_cpu_ptr(sdd->sd, i);

		/* See the comment near build_group_mask(). */
		if (!cpumask_test_cpu(i, sched_domain_span(sibling)))
			continue;

		sg = kzalloc_node(sizeof(struct sched_group) + cpumask_size(),
				GFP_KERNEL, cpu_to_node(cpu));

		if (!sg)
			goto fail;

		sg_span = sched_group_cpus(sg);
		if (sibling->child)
			cpumask_copy(sg_span, sched_domain_span(sibling->child));
		else
			cpumask_set_cpu(i, sg_span);

		cpumask_or(covered, covered, sg_span);

		sg->sgc = *per_cpu_ptr(sdd->sgc, i);
		if (atomic_inc_return(&sg->sgc->ref) == 1)
			build_group_mask(sd, sg);

		/*
		 * Initialize sgc->capacity such that even if we mess up the
		 * domains and no possible iteration will get us here, we won't
		 * die on a /0 trap.
		 */
		sg->sgc->capacity = SCHED_CAPACITY_SCALE * cpumask_weight(sg_span);
		sg->sgc->max_capacity = SCHED_CAPACITY_SCALE;
		sg->sgc->min_capacity = SCHED_CAPACITY_SCALE;

		/*
		 * Make sure the first group of this domain contains the
		 * canonical balance cpu. Otherwise the sched_domain iteration
		 * breaks. See update_sg_lb_stats().
		 */
		if ((!groups && cpumask_test_cpu(cpu, sg_span)) ||
		    group_balance_cpu(sg) == cpu)
			groups = sg;

		if (!first)
			first = sg;
		if (last)
			last->next = sg;
		last = sg;
		last->next = first;
	}
	sd->groups = groups;

	return 0;

fail:
	free_sched_groups(first, 0);

	return -ENOMEM;
}

static int get_group(int cpu, struct sd_data *sdd, struct sched_group **sg)
{
	struct sched_domain *sd = *per_cpu_ptr(sdd->sd, cpu);
	struct sched_domain *child = sd->child;

	if (child)
		cpu = cpumask_first(sched_domain_span(child));

	if (sg) {
		*sg = *per_cpu_ptr(sdd->sg, cpu);
		(*sg)->sgc = *per_cpu_ptr(sdd->sgc, cpu);
		atomic_set(&(*sg)->sgc->ref, 1); /* for claim_allocations */
	}

	return cpu;
}

/*
 * build_sched_groups will build a circular linked list of the groups
 * covered by the given span, and will set each group's ->cpumask correctly,
 * and ->cpu_capacity to 0.
 *
 * Assumes the sched_domain tree is fully constructed
 */
static int
build_sched_groups(struct sched_domain *sd, int cpu)
{
	struct sched_group *first = NULL, *last = NULL;
	struct sd_data *sdd = sd->private;
	const struct cpumask *span = sched_domain_span(sd);
	struct cpumask *covered;
	int i;

	get_group(cpu, sdd, &sd->groups);
	atomic_inc(&sd->groups->ref);

	if (cpu != cpumask_first(span))
		return 0;

	lockdep_assert_held(&sched_domains_mutex);
	covered = sched_domains_tmpmask;

	cpumask_clear(covered);

	for_each_cpu(i, span) {
		struct sched_group *sg;
		int group, j;

		if (cpumask_test_cpu(i, covered))
			continue;

		group = get_group(i, sdd, &sg);
		cpumask_setall(sched_group_mask(sg));

		for_each_cpu(j, span) {
			if (get_group(j, sdd, NULL) != group)
				continue;

			cpumask_set_cpu(j, covered);
			cpumask_set_cpu(j, sched_group_cpus(sg));
		}

		if (!first)
			first = sg;
		if (last)
			last->next = sg;
		last = sg;
	}
	last->next = first;

	return 0;
}

/*
 * Initialize sched groups cpu_capacity.
 *
 * cpu_capacity indicates the capacity of sched group, which is used while
 * distributing the load between different sched groups in a sched domain.
 * Typically cpu_capacity for all the groups in a sched domain will be same
 * unless there are asymmetries in the topology. If there are asymmetries,
 * group having more cpu_capacity will pickup more load compared to the
 * group having less cpu_capacity.
 */
static void init_sched_groups_capacity(int cpu, struct sched_domain *sd)
{
	struct sched_group *sg = sd->groups;

	WARN_ON(!sg);

	do {
		int cpu, max_cpu = -1;

		sg->group_weight = cpumask_weight(sched_group_cpus(sg));

		if (!(sd->flags & SD_ASYM_PACKING))
			goto next;

		for_each_cpu(cpu, sched_group_cpus(sg)) {
			if (max_cpu < 0)
				max_cpu = cpu;
			else if (sched_asym_prefer(cpu, max_cpu))
				max_cpu = cpu;
		}
		sg->asym_prefer_cpu = max_cpu;

next:
		sg = sg->next;
	} while (sg != sd->groups);

	if (cpu != group_balance_cpu(sg))
		return;

	update_group_capacity(sd, cpu);
}

/*
 * Check that the per-cpu provided sd energy data is consistent for all cpus
 * within the mask.
 */
static inline void check_sched_energy_data(int cpu, sched_domain_energy_f fn,
					   const struct cpumask *cpumask)
{
	const struct sched_group_energy * const sge = fn(cpu);
	struct cpumask mask;
	int i;

	if (cpumask_weight(cpumask) <= 1)
		return;

	cpumask_xor(&mask, cpumask, get_cpu_mask(cpu));

	for_each_cpu(i, &mask) {
		const struct sched_group_energy * const e = fn(i);
		int y;

		BUG_ON(e->nr_idle_states != sge->nr_idle_states);

		for (y = 0; y < (e->nr_idle_states); y++) {
			BUG_ON(e->idle_states[y].power !=
					sge->idle_states[y].power);
		}

		BUG_ON(e->nr_cap_states != sge->nr_cap_states);

		for (y = 0; y < (e->nr_cap_states); y++) {
			BUG_ON(e->cap_states[y].cap != sge->cap_states[y].cap);
			BUG_ON(e->cap_states[y].power !=
					sge->cap_states[y].power);
		}
	}
}

static void init_sched_energy(int cpu, struct sched_domain *sd,
			      sched_domain_energy_f fn)
{
	if (!(fn && fn(cpu)))
		return;

	if (cpu != group_balance_cpu(sd->groups))
		return;

	if (sd->child && !sd->child->groups->sge) {
		pr_err("BUG: EAS setup broken for CPU%d\n", cpu);
#ifdef CONFIG_SCHED_DEBUG
		pr_err("     energy data on %s but not on %s domain\n",
			sd->name, sd->child->name);
#endif
		return;
	}

	check_sched_energy_data(cpu, fn, sched_group_cpus(sd->groups));

	sd->groups->sge = fn(cpu);
}

/*
 * Initializers for schedule domains
 * Non-inlined to reduce accumulated stack pressure in build_sched_domains()
 */

static int default_relax_domain_level = -1;
int sched_domain_level_max;

static int __init setup_relax_domain_level(char *str)
{
	if (kstrtoint(str, 0, &default_relax_domain_level))
		pr_warn("Unable to set relax_domain_level\n");

	return 1;
}
__setup("relax_domain_level=", setup_relax_domain_level);

static void set_domain_attribute(struct sched_domain *sd,
				 struct sched_domain_attr *attr)
{
	int request;

	if (!attr || attr->relax_domain_level < 0) {
		if (default_relax_domain_level < 0)
			return;
		else
			request = default_relax_domain_level;
	} else
		request = attr->relax_domain_level;
	if (request < sd->level) {
		/* turn off idle balance on this domain */
		sd->flags &= ~(SD_BALANCE_WAKE|SD_BALANCE_NEWIDLE);
	} else {
		/* turn on idle balance on this domain */
		sd->flags |= (SD_BALANCE_WAKE|SD_BALANCE_NEWIDLE);
	}
}

static void __sdt_free(const struct cpumask *cpu_map);
static int __sdt_alloc(const struct cpumask *cpu_map);

static void __free_domain_allocs(struct s_data *d, enum s_alloc what,
				 const struct cpumask *cpu_map)
{
	switch (what) {
	case sa_rootdomain:
		if (!atomic_read(&d->rd->refcount))
			free_rootdomain(&d->rd->rcu); /* fall through */
	case sa_sd:
		free_percpu(d->sd); /* fall through */
	case sa_sd_storage:
		__sdt_free(cpu_map); /* fall through */
	case sa_none:
		break;
	}
}

static enum s_alloc __visit_domain_allocation_hell(struct s_data *d,
						   const struct cpumask *cpu_map)
{
	memset(d, 0, sizeof(*d));

	if (__sdt_alloc(cpu_map))
		return sa_sd_storage;
	d->sd = alloc_percpu(struct sched_domain *);
	if (!d->sd)
		return sa_sd_storage;
	d->rd = alloc_rootdomain();
	if (!d->rd)
		return sa_sd;
	return sa_rootdomain;
}

/*
 * NULL the sd_data elements we've used to build the sched_domain and
 * sched_group structure so that the subsequent __free_domain_allocs()
 * will not free the data we're using.
 */
static void claim_allocations(int cpu, struct sched_domain *sd)
{
	struct sd_data *sdd = sd->private;

	WARN_ON_ONCE(*per_cpu_ptr(sdd->sd, cpu) != sd);
	*per_cpu_ptr(sdd->sd, cpu) = NULL;

	if (atomic_read(&(*per_cpu_ptr(sdd->sds, cpu))->ref))
		*per_cpu_ptr(sdd->sds, cpu) = NULL;

	if (atomic_read(&(*per_cpu_ptr(sdd->sg, cpu))->ref))
		*per_cpu_ptr(sdd->sg, cpu) = NULL;

	if (atomic_read(&(*per_cpu_ptr(sdd->sgc, cpu))->ref))
		*per_cpu_ptr(sdd->sgc, cpu) = NULL;
}

#ifdef CONFIG_NUMA
static int sched_domains_numa_levels;
enum numa_topology_type sched_numa_topology_type;
static int *sched_domains_numa_distance;
int sched_max_numa_distance;
static struct cpumask ***sched_domains_numa_masks;
static int sched_domains_curr_level;
#endif

/*
 * SD_flags allowed in topology descriptions.
 *
 * These flags are purely descriptive of the topology and do not prescribe
 * behaviour. Behaviour is artificial and mapped in the below sd_init()
 * function:
 *
 *   SD_SHARE_CPUCAPACITY   - describes SMT topologies
 *   SD_SHARE_PKG_RESOURCES - describes shared caches
 *   SD_NUMA                - describes NUMA topologies
 *   SD_SHARE_POWERDOMAIN   - describes shared power domain
 *   SD_SHARE_CAP_STATES    - describes shared capacity states
 *
 * Odd one out, which beside describing the topology has a quirk also
 * prescribes the desired behaviour that goes along with it:
 *
 *   SD_ASYM_PACKING        - describes SMT quirks
 */
#define TOPOLOGY_SD_FLAGS		\
	(SD_SHARE_CPUCAPACITY |		\
	 SD_SHARE_PKG_RESOURCES |	\
	 SD_NUMA |			\
	 SD_ASYM_PACKING |		\
	 SD_SHARE_POWERDOMAIN |		\
	 SD_SHARE_CAP_STATES)

static struct sched_domain *
sd_init(struct sched_domain_topology_level *tl,
	const struct cpumask *cpu_map,
	struct sched_domain *child, int dflags, int cpu)
{
	struct sd_data *sdd = &tl->data;
	struct sched_domain *sd = *per_cpu_ptr(sdd->sd, cpu);
	int sd_id, sd_weight, sd_flags = 0;

#ifdef CONFIG_NUMA
	/*
	 * Ugly hack to pass state to sd_numa_mask()...
	 */
	sched_domains_curr_level = tl->numa_level;
#endif

	sd_weight = cpumask_weight(tl->mask(cpu));

	if (tl->sd_flags)
		sd_flags = (*tl->sd_flags)();
	if (WARN_ONCE(sd_flags & ~TOPOLOGY_SD_FLAGS,
			"wrong sd_flags in topology description\n"))
		sd_flags &= ~TOPOLOGY_SD_FLAGS;

	/* Apply detected topology flags */
	sd_flags |= dflags;

	*sd = (struct sched_domain){
		.min_interval		= sd_weight,
		.max_interval		= 2*sd_weight,
		.busy_factor		= 32,
		.imbalance_pct		= 125,

		.cache_nice_tries	= 0,
		.busy_idx		= 0,
		.idle_idx		= 0,
		.newidle_idx		= 0,
		.wake_idx		= 0,
		.forkexec_idx		= 0,

		.flags			= 1*SD_LOAD_BALANCE
					| 1*SD_BALANCE_NEWIDLE
					| 1*SD_BALANCE_EXEC
					| 1*SD_BALANCE_FORK
					| 0*SD_BALANCE_WAKE
					| 1*SD_WAKE_AFFINE
					| 0*SD_SHARE_CPUCAPACITY
					| 0*SD_SHARE_PKG_RESOURCES
					| 0*SD_SERIALIZE
					| 1*SD_PREFER_SIBLING
					| 0*SD_NUMA
					| sd_flags
					,

		.last_balance		= jiffies,
		.balance_interval	= sd_weight,
		.smt_gain		= 0,
		.max_newidle_lb_cost	= 0,
		.next_decay_max_lb_cost	= jiffies,
		.child			= child,
#ifdef CONFIG_SCHED_DEBUG
		.name			= tl->name,
#endif
	};

	cpumask_and(sched_domain_span(sd), cpu_map, tl->mask(cpu));
	sd_id = cpumask_first(sched_domain_span(sd));

	/*
	 * Convert topological properties into behaviour.
	 */

	if (sd->flags & SD_ASYM_CPUCAPACITY) {
		struct sched_domain *t = sd;

		/*
		 * Don't attempt to spread across CPUs of different capacities.
		 */
		if (sd->child)
			sd->child->flags &= ~SD_PREFER_SIBLING;

		for_each_lower_domain(t)
			t->flags |= SD_BALANCE_WAKE;
	}

	if (sd->flags & SD_SHARE_CPUCAPACITY) {
		sd->imbalance_pct = 110;
		sd->smt_gain = 1178; /* ~15% */

	} else if (sd->flags & SD_SHARE_PKG_RESOURCES) {
		sd->imbalance_pct = 117;
		sd->cache_nice_tries = 1;
		sd->busy_idx = 2;

#ifdef CONFIG_NUMA
	} else if (sd->flags & SD_NUMA) {
		sd->cache_nice_tries = 2;
		sd->busy_idx = 3;
		sd->idle_idx = 2;

		sd->flags &= ~SD_PREFER_SIBLING;
		sd->flags |= SD_SERIALIZE;
		if (sched_domains_numa_distance[tl->numa_level] > RECLAIM_DISTANCE) {
			sd->flags &= ~(SD_BALANCE_EXEC |
				       SD_BALANCE_FORK |
				       SD_WAKE_AFFINE);
		}

#endif
	} else {
		sd->cache_nice_tries = 1;
		sd->busy_idx = 2;
		sd->idle_idx = 1;
	}

	sd->shared = *per_cpu_ptr(sdd->sds, sd_id);
	atomic_inc(&sd->shared->ref);

	if (sd->flags & SD_SHARE_PKG_RESOURCES)
		atomic_set(&sd->shared->nr_busy_cpus, sd_weight);

	sd->private = sdd;

	return sd;
}

/*
 * Topology list, bottom-up.
 */
static struct sched_domain_topology_level default_topology[] = {
#ifdef CONFIG_SCHED_SMT
	{ cpu_smt_mask, cpu_smt_flags, SD_INIT_NAME(SMT) },
#endif
#ifdef CONFIG_SCHED_MC
	{ cpu_coregroup_mask, cpu_core_flags, SD_INIT_NAME(MC) },
#endif
	{ cpu_cpu_mask, SD_INIT_NAME(DIE) },
	{ NULL, },
};

static struct sched_domain_topology_level *sched_domain_topology =
	default_topology;

#define for_each_sd_topology(tl)			\
	for (tl = sched_domain_topology; tl->mask; tl++)

void set_sched_topology(struct sched_domain_topology_level *tl)
{
	if (WARN_ON_ONCE(sched_smp_initialized))
		return;

	sched_domain_topology = tl;
}

#ifdef CONFIG_NUMA

static const struct cpumask *sd_numa_mask(int cpu)
{
	return sched_domains_numa_masks[sched_domains_curr_level][cpu_to_node(cpu)];
}

static void sched_numa_warn(const char *str)
{
	static int done = false;
	int i,j;

	if (done)
		return;

	done = true;

	printk(KERN_WARNING "ERROR: %s\n\n", str);

	for (i = 0; i < nr_node_ids; i++) {
		printk(KERN_WARNING "  ");
		for (j = 0; j < nr_node_ids; j++)
			printk(KERN_CONT "%02d ", node_distance(i,j));
		printk(KERN_CONT "\n");
	}
	printk(KERN_WARNING "\n");
}

bool find_numa_distance(int distance)
{
	int i;

	if (distance == node_distance(0, 0))
		return true;

	for (i = 0; i < sched_domains_numa_levels; i++) {
		if (sched_domains_numa_distance[i] == distance)
			return true;
	}

	return false;
}

/*
 * A system can have three types of NUMA topology:
 * NUMA_DIRECT: all nodes are directly connected, or not a NUMA system
 * NUMA_GLUELESS_MESH: some nodes reachable through intermediary nodes
 * NUMA_BACKPLANE: nodes can reach other nodes through a backplane
 *
 * The difference between a glueless mesh topology and a backplane
 * topology lies in whether communication between not directly
 * connected nodes goes through intermediary nodes (where programs
 * could run), or through backplane controllers. This affects
 * placement of programs.
 *
 * The type of topology can be discerned with the following tests:
 * - If the maximum distance between any nodes is 1 hop, the system
 *   is directly connected.
 * - If for two nodes A and B, located N > 1 hops away from each other,
 *   there is an intermediary node C, which is < N hops away from both
 *   nodes A and B, the system is a glueless mesh.
 */
static void init_numa_topology_type(void)
{
	int a, b, c, n;

	n = sched_max_numa_distance;

	if (sched_domains_numa_levels <= 1) {
		sched_numa_topology_type = NUMA_DIRECT;
		return;
	}

	for_each_online_node(a) {
		for_each_online_node(b) {
			/* Find two nodes furthest removed from each other. */
			if (node_distance(a, b) < n)
				continue;

			/* Is there an intermediary node between a and b? */
			for_each_online_node(c) {
				if (node_distance(a, c) < n &&
				    node_distance(b, c) < n) {
					sched_numa_topology_type =
							NUMA_GLUELESS_MESH;
					return;
				}
			}

			sched_numa_topology_type = NUMA_BACKPLANE;
			return;
		}
	}
}

static void sched_init_numa(void)
{
	int next_distance, curr_distance = node_distance(0, 0);
	struct sched_domain_topology_level *tl;
	int level = 0;
	int i, j, k;

	sched_domains_numa_distance = kzalloc(sizeof(int) * nr_node_ids, GFP_KERNEL);
	if (!sched_domains_numa_distance)
		return;

	/*
	 * O(nr_nodes^2) deduplicating selection sort -- in order to find the
	 * unique distances in the node_distance() table.
	 *
	 * Assumes node_distance(0,j) includes all distances in
	 * node_distance(i,j) in order to avoid cubic time.
	 */
	next_distance = curr_distance;
	for (i = 0; i < nr_node_ids; i++) {
		for (j = 0; j < nr_node_ids; j++) {
			for (k = 0; k < nr_node_ids; k++) {
				int distance = node_distance(i, k);

				if (distance > curr_distance &&
				    (distance < next_distance ||
				     next_distance == curr_distance))
					next_distance = distance;

				/*
				 * While not a strong assumption it would be nice to know
				 * about cases where if node A is connected to B, B is not
				 * equally connected to A.
				 */
				if (sched_debug() && node_distance(k, i) != distance)
					sched_numa_warn("Node-distance not symmetric");

				if (sched_debug() && i && !find_numa_distance(distance))
					sched_numa_warn("Node-0 not representative");
			}
			if (next_distance != curr_distance) {
				sched_domains_numa_distance[level++] = next_distance;
				sched_domains_numa_levels = level;
				curr_distance = next_distance;
			} else break;
		}

		/*
		 * In case of sched_debug() we verify the above assumption.
		 */
		if (!sched_debug())
			break;
	}

	if (!level)
		return;

	/*
	 * 'level' contains the number of unique distances, excluding the
	 * identity distance node_distance(i,i).
	 *
	 * The sched_domains_numa_distance[] array includes the actual distance
	 * numbers.
	 */

	/*
	 * Here, we should temporarily reset sched_domains_numa_levels to 0.
	 * If it fails to allocate memory for array sched_domains_numa_masks[][],
	 * the array will contain less then 'level' members. This could be
	 * dangerous when we use it to iterate array sched_domains_numa_masks[][]
	 * in other functions.
	 *
	 * We reset it to 'level' at the end of this function.
	 */
	sched_domains_numa_levels = 0;

	sched_domains_numa_masks = kzalloc(sizeof(void *) * level, GFP_KERNEL);
	if (!sched_domains_numa_masks)
		return;

	/*
	 * Now for each level, construct a mask per node which contains all
	 * cpus of nodes that are that many hops away from us.
	 */
	for (i = 0; i < level; i++) {
		sched_domains_numa_masks[i] =
			kzalloc(nr_node_ids * sizeof(void *), GFP_KERNEL);
		if (!sched_domains_numa_masks[i])
			return;

		for (j = 0; j < nr_node_ids; j++) {
			struct cpumask *mask = kzalloc(cpumask_size(), GFP_KERNEL);
			if (!mask)
				return;

			sched_domains_numa_masks[i][j] = mask;

			for_each_node(k) {
				if (node_distance(j, k) > sched_domains_numa_distance[i])
					continue;

				cpumask_or(mask, mask, cpumask_of_node(k));
			}
		}
	}

	/* Compute default topology size */
	for (i = 0; sched_domain_topology[i].mask; i++);

	tl = kzalloc((i + level + 1) *
			sizeof(struct sched_domain_topology_level), GFP_KERNEL);
	if (!tl)
		return;

	/*
	 * Copy the default topology bits..
	 */
	for (i = 0; sched_domain_topology[i].mask; i++)
		tl[i] = sched_domain_topology[i];

	/*
	 * .. and append 'j' levels of NUMA goodness.
	 */
	for (j = 0; j < level; i++, j++) {
		tl[i] = (struct sched_domain_topology_level){
			.mask = sd_numa_mask,
			.sd_flags = cpu_numa_flags,
			.flags = SDTL_OVERLAP,
			.numa_level = j,
			SD_INIT_NAME(NUMA)
		};
	}

	sched_domain_topology = tl;

	sched_domains_numa_levels = level;
	sched_max_numa_distance = sched_domains_numa_distance[level - 1];

	init_numa_topology_type();
}

void sched_domains_numa_masks_set(unsigned int cpu)
{
	int node = cpu_to_node(cpu);
	int i, j;

	for (i = 0; i < sched_domains_numa_levels; i++) {
		for (j = 0; j < nr_node_ids; j++) {
			if (node_distance(j, node) <= sched_domains_numa_distance[i])
				cpumask_set_cpu(cpu, sched_domains_numa_masks[i][j]);
		}
	}
}

static void sched_domains_numa_masks_clear(unsigned int cpu)
{
	int i, j;

	for (i = 0; i < sched_domains_numa_levels; i++) {
		for (j = 0; j < nr_node_ids; j++)
			cpumask_clear_cpu(cpu, sched_domains_numa_masks[i][j]);
	}
}

#endif /* CONFIG_NUMA */

static int __sdt_alloc(const struct cpumask *cpu_map)
{
	struct sched_domain_topology_level *tl;
	int j;

	for_each_sd_topology(tl) {
		struct sd_data *sdd = &tl->data;

		sdd->sd = alloc_percpu(struct sched_domain *);
		if (!sdd->sd)
			return -ENOMEM;

		sdd->sds = alloc_percpu(struct sched_domain_shared *);
		if (!sdd->sds)
			return -ENOMEM;

		sdd->sg = alloc_percpu(struct sched_group *);
		if (!sdd->sg)
			return -ENOMEM;

		sdd->sgc = alloc_percpu(struct sched_group_capacity *);
		if (!sdd->sgc)
			return -ENOMEM;

		for_each_cpu(j, cpu_map) {
			struct sched_domain *sd;
			struct sched_domain_shared *sds;
			struct sched_group *sg;
			struct sched_group_capacity *sgc;

			sd = kzalloc_node(sizeof(struct sched_domain) + cpumask_size(),
					GFP_KERNEL, cpu_to_node(j));
			if (!sd)
				return -ENOMEM;

			*per_cpu_ptr(sdd->sd, j) = sd;

			sds = kzalloc_node(sizeof(struct sched_domain_shared),
					GFP_KERNEL, cpu_to_node(j));
			if (!sds)
				return -ENOMEM;

			*per_cpu_ptr(sdd->sds, j) = sds;

			sg = kzalloc_node(sizeof(struct sched_group) + cpumask_size(),
					GFP_KERNEL, cpu_to_node(j));
			if (!sg)
				return -ENOMEM;

			sg->next = sg;

			*per_cpu_ptr(sdd->sg, j) = sg;

			sgc = kzalloc_node(sizeof(struct sched_group_capacity) + cpumask_size(),
					GFP_KERNEL, cpu_to_node(j));
			if (!sgc)
				return -ENOMEM;

			*per_cpu_ptr(sdd->sgc, j) = sgc;
		}
	}

	return 0;
}

static void __sdt_free(const struct cpumask *cpu_map)
{
	struct sched_domain_topology_level *tl;
	int j;

	for_each_sd_topology(tl) {
		struct sd_data *sdd = &tl->data;

		for_each_cpu(j, cpu_map) {
			struct sched_domain *sd;

			if (sdd->sd) {
				sd = *per_cpu_ptr(sdd->sd, j);
				if (sd && (sd->flags & SD_OVERLAP))
					free_sched_groups(sd->groups, 0);
				kfree(*per_cpu_ptr(sdd->sd, j));
			}

			if (sdd->sds)
				kfree(*per_cpu_ptr(sdd->sds, j));
			if (sdd->sg)
				kfree(*per_cpu_ptr(sdd->sg, j));
			if (sdd->sgc)
				kfree(*per_cpu_ptr(sdd->sgc, j));
		}
		free_percpu(sdd->sd);
		sdd->sd = NULL;
		free_percpu(sdd->sds);
		sdd->sds = NULL;
		free_percpu(sdd->sg);
		sdd->sg = NULL;
		free_percpu(sdd->sgc);
		sdd->sgc = NULL;
	}
}

struct sched_domain *build_sched_domain(struct sched_domain_topology_level *tl,
		const struct cpumask *cpu_map, struct sched_domain_attr *attr,
		struct sched_domain *child, int dflags, int cpu)
{
	struct sched_domain *sd = sd_init(tl, cpu_map, child, dflags, cpu);

	if (child) {
		sd->level = child->level + 1;
		sched_domain_level_max = max(sched_domain_level_max, sd->level);
		child->parent = sd;

		if (!cpumask_subset(sched_domain_span(child),
				    sched_domain_span(sd))) {
			pr_err("BUG: arch topology borken\n");
#ifdef CONFIG_SCHED_DEBUG
			pr_err("     the %s domain not a subset of the %s domain\n",
					child->name, sd->name);
#endif
			/* Fixup, ensure @sd has at least @child cpus. */
			cpumask_or(sched_domain_span(sd),
				   sched_domain_span(sd),
				   sched_domain_span(child));
		}

	}
	set_domain_attribute(sd, attr);

	return sd;
}

/*
 * Find the sched_domain_topology_level where all CPU capacities are visible
 * for all CPUs.
 */
static struct sched_domain_topology_level
*asym_cpu_capacity_level(const struct cpumask *cpu_map)
{
	int i, j, asym_level = 0;
	bool asym = false;
	struct sched_domain_topology_level *tl, *asym_tl = NULL;
	unsigned long cap;

	/* Is there any asymmetry? */
	cap = arch_scale_cpu_capacity(NULL, cpumask_first(cpu_map));

	for_each_cpu(i, cpu_map) {
		if (arch_scale_cpu_capacity(NULL, i) != cap) {
			asym = true;
			break;
		}
	}

	if (!asym)
		return NULL;

	/*
	 * Examine topology from all CPU's point of views to detect the lowest
	 * sched_domain_topology_level where a highest capacity CPU is visible
	 * to everyone.
	 */
	for_each_cpu(i, cpu_map) {
		unsigned long max_capacity = arch_scale_cpu_capacity(NULL, i);
		int tl_id = 0;

		for_each_sd_topology(tl) {
			if (tl_id < asym_level)
				goto next_level;

			for_each_cpu_and(j, tl->mask(i), cpu_map) {
				unsigned long capacity;

				capacity = arch_scale_cpu_capacity(NULL, j);

				if (capacity <= max_capacity)
					continue;

				max_capacity = capacity;
				asym_level = tl_id;
				asym_tl = tl;
			}
next_level:
			tl_id++;
		}
	}

	return asym_tl;
}

/*
 * Build sched domains for a given set of cpus and attach the sched domains
 * to the individual cpus
 */
static int build_sched_domains(const struct cpumask *cpu_map,
			       struct sched_domain_attr *attr)
{
	enum s_alloc alloc_state;
	struct sched_domain *sd;
	struct s_data d;
	int i, ret = -ENOMEM;
	struct sched_domain_topology_level *tl_asym;

	alloc_state = __visit_domain_allocation_hell(&d, cpu_map);
	if (alloc_state != sa_rootdomain)
		goto error;

	tl_asym = asym_cpu_capacity_level(cpu_map);

	/* Set up domains for cpus specified by the cpu_map. */
	for_each_cpu(i, cpu_map) {
		struct sched_domain_topology_level *tl;

		sd = NULL;
		for_each_sd_topology(tl) {
			int dflags = 0;

			if (tl == tl_asym)
				dflags |= SD_ASYM_CPUCAPACITY;

			sd = build_sched_domain(tl, cpu_map, attr, sd, dflags, i);
			if (tl == sched_domain_topology)
				*per_cpu_ptr(d.sd, i) = sd;
			if (tl->flags & SDTL_OVERLAP || sched_feat(FORCE_SD_OVERLAP))
				sd->flags |= SD_OVERLAP;
		}
	}

	/* Build the groups for the domains */
	for_each_cpu(i, cpu_map) {
		for (sd = *per_cpu_ptr(d.sd, i); sd; sd = sd->parent) {
			sd->span_weight = cpumask_weight(sched_domain_span(sd));
			if (sd->flags & SD_OVERLAP) {
				if (build_overlap_sched_groups(sd, i))
					goto error;
			} else {
				if (build_sched_groups(sd, i))
					goto error;
			}
		}
	}

	/* Calculate CPU capacity for physical packages and nodes */
	for (i = nr_cpumask_bits-1; i >= 0; i--) {
		struct sched_domain_topology_level *tl = sched_domain_topology;

		if (!cpumask_test_cpu(i, cpu_map))
			continue;

		for (sd = *per_cpu_ptr(d.sd, i); sd; sd = sd->parent, tl++) {
			init_sched_energy(i, sd, tl->energy);
			claim_allocations(i, sd);
			init_sched_groups_capacity(i, sd);
		}
	}

	/* Attach the domains */
	rcu_read_lock();
	for_each_cpu(i, cpu_map) {
		int max_cpu = READ_ONCE(d.rd->max_cap_orig_cpu);
		int min_cpu = READ_ONCE(d.rd->min_cap_orig_cpu);

		if ((max_cpu < 0) || (cpu_rq(i)->cpu_capacity_orig >
		    cpu_rq(max_cpu)->cpu_capacity_orig))
			WRITE_ONCE(d.rd->max_cap_orig_cpu, i);

		if ((min_cpu < 0) || (cpu_rq(i)->cpu_capacity_orig <
		    cpu_rq(min_cpu)->cpu_capacity_orig))
			WRITE_ONCE(d.rd->min_cap_orig_cpu, i);

		sd = *per_cpu_ptr(d.sd, i);

		cpu_attach_domain(sd, d.rd, i);
	}
	rcu_read_unlock();

	ret = 0;
error:
	__free_domain_allocs(&d, alloc_state, cpu_map);
	return ret;
}

static cpumask_var_t *doms_cur;	/* current sched domains */
static int ndoms_cur;		/* number of sched domains in 'doms_cur' */
static struct sched_domain_attr *dattr_cur;
				/* attribues of custom domains in 'doms_cur' */

/*
 * Special case: If a kmalloc of a doms_cur partition (array of
 * cpumask) fails, then fallback to a single sched domain,
 * as determined by the single cpumask fallback_doms.
 */
cpumask_var_t fallback_doms;

/*
 * arch_update_cpu_topology lets virtualized architectures update the
 * cpu core maps. It is supposed to return 1 if the topology changed
 * or 0 if it stayed the same.
 */
int __weak arch_update_cpu_topology(void)
{
	return 0;
}

cpumask_var_t *alloc_sched_domains(unsigned int ndoms)
{
	int i;
	cpumask_var_t *doms;

	doms = kmalloc(sizeof(*doms) * ndoms, GFP_KERNEL);
	if (!doms)
		return NULL;
	for (i = 0; i < ndoms; i++) {
		if (!alloc_cpumask_var(&doms[i], GFP_KERNEL)) {
			free_sched_domains(doms, i);
			return NULL;
		}
	}
	return doms;
}

void free_sched_domains(cpumask_var_t doms[], unsigned int ndoms)
{
	unsigned int i;
	for (i = 0; i < ndoms; i++)
		free_cpumask_var(doms[i]);
	kfree(doms);
}

/*
 * Set up scheduler domains and groups. Callers must hold the hotplug lock.
 * For now this just excludes isolated cpus, but could be used to
 * exclude other special cases in the future.
 */
int init_sched_domains(const struct cpumask *cpu_map)
{
	int err;

	arch_update_cpu_topology();
	ndoms_cur = 1;
	doms_cur = alloc_sched_domains(ndoms_cur);
	if (!doms_cur)
		doms_cur = &fallback_doms;
	cpumask_andnot(doms_cur[0], cpu_map, cpu_isolated_map);
	err = build_sched_domains(doms_cur[0], NULL);
	register_sched_domain_sysctl();

	return err;
}

/*
 * Detach sched domains from a group of cpus specified in cpu_map
 * These cpus will now be attached to the NULL domain
 */
static void detach_destroy_domains(const struct cpumask *cpu_map)
{
	int i;

	rcu_read_lock();
	for_each_cpu(i, cpu_map)
		cpu_attach_domain(NULL, &def_root_domain, i);
	rcu_read_unlock();
}

/* handle null as "default" */
static int dattrs_equal(struct sched_domain_attr *cur, int idx_cur,
			struct sched_domain_attr *new, int idx_new)
{
	struct sched_domain_attr tmp;

	/* fast path */
	if (!new && !cur)
		return 1;

	tmp = SD_ATTR_INIT;
	return !memcmp(cur ? (cur + idx_cur) : &tmp,
			new ? (new + idx_new) : &tmp,
			sizeof(struct sched_domain_attr));
}

/*
 * Partition sched domains as specified by the 'ndoms_new'
 * cpumasks in the array doms_new[] of cpumasks. This compares
 * doms_new[] to the current sched domain partitioning, doms_cur[].
 * It destroys each deleted domain and builds each new domain.
 *
 * 'doms_new' is an array of cpumask_var_t's of length 'ndoms_new'.
 * The masks don't intersect (don't overlap.) We should setup one
 * sched domain for each mask. CPUs not in any of the cpumasks will
 * not be load balanced. If the same cpumask appears both in the
 * current 'doms_cur' domains and in the new 'doms_new', we can leave
 * it as it is.
 *
 * The passed in 'doms_new' should be allocated using
 * alloc_sched_domains.  This routine takes ownership of it and will
 * free_sched_domains it when done with it. If the caller failed the
 * alloc call, then it can pass in doms_new == NULL && ndoms_new == 1,
 * and partition_sched_domains() will fallback to the single partition
 * 'fallback_doms', it also forces the domains to be rebuilt.
 *
 * If doms_new == NULL it will be replaced with cpu_online_mask.
 * ndoms_new == 0 is a special case for destroying existing domains,
 * and it will not create the default domain.
 *
 * Call with hotplug lock held
 */
void partition_sched_domains(int ndoms_new, cpumask_var_t doms_new[],
			     struct sched_domain_attr *dattr_new)
{
	int i, j, n;
	int new_topology;

	mutex_lock(&sched_domains_mutex);

	/* always unregister in case we don't destroy any domains */
	unregister_sched_domain_sysctl();

	/* Let architecture update cpu core mappings. */
	new_topology = arch_update_cpu_topology();

	n = doms_new ? ndoms_new : 0;

	/* Destroy deleted domains */
	for (i = 0; i < ndoms_cur; i++) {
		for (j = 0; j < n && !new_topology; j++) {
			if (cpumask_equal(doms_cur[i], doms_new[j])
			    && dattrs_equal(dattr_cur, i, dattr_new, j))
				goto match1;
		}
		/* no match - a current sched domain not in new doms_new[] */
		detach_destroy_domains(doms_cur[i]);
match1:
		;
	}

	n = ndoms_cur;
	if (doms_new == NULL) {
		n = 0;
		doms_new = &fallback_doms;
		cpumask_andnot(doms_new[0], cpu_active_mask, cpu_isolated_map);
		WARN_ON_ONCE(dattr_new);
	}

	/* Build new domains */
	for (i = 0; i < ndoms_new; i++) {
		for (j = 0; j < n && !new_topology; j++) {
			if (cpumask_equal(doms_new[i], doms_cur[j])
			    && dattrs_equal(dattr_new, i, dattr_cur, j))
				goto match2;
		}
		/* no match - add a new doms_new */
		build_sched_domains(doms_new[i], dattr_new ? dattr_new + i : NULL);
match2:
		;
	}

	/* Remember the new sched domains */
	if (doms_cur != &fallback_doms)
		free_sched_domains(doms_cur, ndoms_cur);
	kfree(dattr_cur);	/* kfree(NULL) is safe */
	doms_cur = doms_new;
	dattr_cur = dattr_new;
	ndoms_cur = ndoms_new;

	register_sched_domain_sysctl();

	mutex_unlock(&sched_domains_mutex);
}
