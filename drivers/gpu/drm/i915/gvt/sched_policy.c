/*
 * Copyright(c) 2011-2016 Intel Corporation. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Authors:
 *    Anhua Xu
 *    Kevin Tian <kevin.tian@intel.com>
 *
 * Contributors:
 *    Min He <min.he@intel.com>
 *    Bing Niu <bing.niu@intel.com>
 *    Zhi Wang <zhi.a.wang@intel.com>
 *
 */

#include "i915_drv.h"
#include "gvt.h"

static bool vgpu_has_pending_workload(struct intel_vgpu *vgpu)
{
	enum intel_engine_id i;
	struct intel_engine_cs *engine;

	for_each_engine(engine, vgpu->gvt->dev_priv, i) {
		if (!list_empty(workload_q_head(vgpu, i)))
			return true;
	}

	return false;
}

struct vgpu_sched_data {
	struct list_head lru_list;
	struct intel_vgpu *vgpu;

	ktime_t sched_in_time;
	ktime_t sched_out_time;
	ktime_t sched_time;
	ktime_t left_ts;
	ktime_t allocated_ts;

	struct vgpu_sched_ctl sched_ctl;
};

struct gvt_sched_data {
	struct intel_gvt *gvt;
	struct hrtimer timer;
	unsigned long period;
	struct list_head lru_runq_head;
};

static void vgpu_update_timeslice(struct intel_vgpu *pre_vgpu)
{
	ktime_t delta_ts;
	struct vgpu_sched_data *vgpu_data = pre_vgpu->sched_data;

	delta_ts = vgpu_data->sched_out_time - vgpu_data->sched_in_time;

	vgpu_data->sched_time += delta_ts;
	vgpu_data->left_ts -= delta_ts;
}

#define GVT_TS_BALANCE_PERIOD_MS 100
#define GVT_TS_BALANCE_STAGE_NUM 10

static void gvt_balance_timeslice(struct gvt_sched_data *sched_data)
{
	struct vgpu_sched_data *vgpu_data;
	struct list_head *pos;
	static uint64_t stage_check;
	int stage = stage_check++ % GVT_TS_BALANCE_STAGE_NUM;

	/* The timeslice accumulation reset at stage 0, which is
	 * allocated again without adding previous debt.
	 */
	if (stage == 0) {
		int total_weight = 0;
		ktime_t fair_timeslice;

		list_for_each(pos, &sched_data->lru_runq_head) {
			vgpu_data = container_of(pos, struct vgpu_sched_data, lru_list);
			total_weight += vgpu_data->sched_ctl.weight;
		}

		list_for_each(pos, &sched_data->lru_runq_head) {
			vgpu_data = container_of(pos, struct vgpu_sched_data, lru_list);
			fair_timeslice = ms_to_ktime(GVT_TS_BALANCE_PERIOD_MS) *
						vgpu_data->sched_ctl.weight /
						total_weight;

			vgpu_data->allocated_ts = fair_timeslice;
			vgpu_data->left_ts = vgpu_data->allocated_ts;
		}
	} else {
		list_for_each(pos, &sched_data->lru_runq_head) {
			vgpu_data = container_of(pos, struct vgpu_sched_data, lru_list);

			/* timeslice for next 100ms should add the left/debt
			 * slice of previous stages.
			 */
			vgpu_data->left_ts += vgpu_data->allocated_ts;
		}
	}
}

static void try_to_schedule_next_vgpu(struct intel_gvt *gvt)
{
	struct intel_gvt_workload_scheduler *scheduler = &gvt->scheduler;
	enum intel_engine_id i;
	struct intel_engine_cs *engine;
	struct vgpu_sched_data *vgpu_data;
	ktime_t cur_time;

	/* no target to schedule */
	if (!scheduler->next_vgpu)
		return;

	gvt_dbg_sched("try to schedule next vgpu %d\n",
			scheduler->next_vgpu->id);

	/*
	 * after the flag is set, workload dispatch thread will
	 * stop dispatching workload for current vgpu
	 */
	scheduler->need_reschedule = true;

	/* still have uncompleted workload? */
	for_each_engine(engine, gvt->dev_priv, i) {
		if (scheduler->current_workload[i]) {
			gvt_dbg_sched("still have running workload\n");
			return;
		}
	}

	cur_time = ktime_get();
	if (scheduler->current_vgpu) {
		vgpu_data = scheduler->current_vgpu->sched_data;
		vgpu_data->sched_out_time = cur_time;
		vgpu_update_timeslice(scheduler->current_vgpu);
	}
	vgpu_data = scheduler->next_vgpu->sched_data;
	vgpu_data->sched_in_time = cur_time;

	/* switch current vgpu */
	scheduler->current_vgpu = scheduler->next_vgpu;
	scheduler->next_vgpu = NULL;

	scheduler->need_reschedule = false;

	/* wake up workload dispatch thread */
	for_each_engine(engine, gvt->dev_priv, i)
		wake_up(&scheduler->waitq[i]);
}

static struct intel_vgpu *find_busy_vgpu(struct gvt_sched_data *sched_data)
{
	struct vgpu_sched_data *vgpu_data;
	struct intel_vgpu *vgpu = NULL;
	struct list_head *head = &sched_data->lru_runq_head;
	struct list_head *pos;

	/* search a vgpu with pending workload */
	list_for_each(pos, head) {

		vgpu_data = container_of(pos, struct vgpu_sched_data, lru_list);
		if (!vgpu_has_pending_workload(vgpu_data->vgpu))
			continue;

		/* Return the vGPU only if it has time slice left */
		if (vgpu_data->left_ts > 0) {
			vgpu = vgpu_data->vgpu;
			break;
		}
	}

	return vgpu;
}

/* in nanosecond */
#define GVT_DEFAULT_TIME_SLICE 1000000

static void tbs_sched_func(struct gvt_sched_data *sched_data)
{
	struct intel_gvt *gvt = sched_data->gvt;
	struct intel_gvt_workload_scheduler *scheduler = &gvt->scheduler;
	struct vgpu_sched_data *vgpu_data;
	struct intel_vgpu *vgpu = NULL;
	static uint64_t timer_check;

	if (!(timer_check++ % GVT_TS_BALANCE_PERIOD_MS))
		gvt_balance_timeslice(sched_data);

	/* no active vgpu or has already had a target */
	if (list_empty(&sched_data->lru_runq_head) || scheduler->next_vgpu)
		goto out;

	vgpu = find_busy_vgpu(sched_data);
	if (vgpu) {
		scheduler->next_vgpu = vgpu;

		/* Move the last used vGPU to the tail of lru_list */
		vgpu_data = vgpu->sched_data;
		list_del_init(&vgpu_data->lru_list);
		list_add_tail(&vgpu_data->lru_list,
				&sched_data->lru_runq_head);
	} else {
		scheduler->next_vgpu = gvt->idle_vgpu;
	}
out:
	if (scheduler->next_vgpu)
		try_to_schedule_next_vgpu(gvt);
}

void intel_gvt_schedule(struct intel_gvt *gvt)
{
	struct gvt_sched_data *sched_data = gvt->scheduler.sched_data;

	mutex_lock(&gvt->lock);
	tbs_sched_func(sched_data);
	mutex_unlock(&gvt->lock);
}

static enum hrtimer_restart tbs_timer_fn(struct hrtimer *timer_data)
{
	struct gvt_sched_data *data;

	data = container_of(timer_data, struct gvt_sched_data, timer);

	intel_gvt_request_service(data->gvt, INTEL_GVT_REQUEST_SCHED);

	hrtimer_add_expires_ns(&data->timer, data->period);

	return HRTIMER_RESTART;
}

static int tbs_sched_init(struct intel_gvt *gvt)
{
	struct intel_gvt_workload_scheduler *scheduler =
		&gvt->scheduler;

	struct gvt_sched_data *data;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	INIT_LIST_HEAD(&data->lru_runq_head);
	hrtimer_init(&data->timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS);
	data->timer.function = tbs_timer_fn;
	data->period = GVT_DEFAULT_TIME_SLICE;
	data->gvt = gvt;

	scheduler->sched_data = data;

	return 0;
}

static void tbs_sched_clean(struct intel_gvt *gvt)
{
	struct intel_gvt_workload_scheduler *scheduler =
		&gvt->scheduler;
	struct gvt_sched_data *data = scheduler->sched_data;

	hrtimer_cancel(&data->timer);

	kfree(data);
	scheduler->sched_data = NULL;
}

static int tbs_sched_init_vgpu(struct intel_vgpu *vgpu)
{
	struct vgpu_sched_data *data;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->sched_ctl.weight = vgpu->sched_ctl.weight;
	data->vgpu = vgpu;
	INIT_LIST_HEAD(&data->lru_list);

	vgpu->sched_data = data;

	return 0;
}

static void tbs_sched_clean_vgpu(struct intel_vgpu *vgpu)
{
	kfree(vgpu->sched_data);
	vgpu->sched_data = NULL;
}

static void tbs_sched_start_schedule(struct intel_vgpu *vgpu)
{
	struct gvt_sched_data *sched_data = vgpu->gvt->scheduler.sched_data;
	struct vgpu_sched_data *vgpu_data = vgpu->sched_data;

	if (!list_empty(&vgpu_data->lru_list))
		return;

	list_add_tail(&vgpu_data->lru_list, &sched_data->lru_runq_head);

	if (!hrtimer_active(&sched_data->timer))
		hrtimer_start(&sched_data->timer, ktime_add_ns(ktime_get(),
			sched_data->period), HRTIMER_MODE_ABS);
}

static void tbs_sched_stop_schedule(struct intel_vgpu *vgpu)
{
	struct vgpu_sched_data *vgpu_data = vgpu->sched_data;

	list_del_init(&vgpu_data->lru_list);
}

static struct intel_gvt_sched_policy_ops tbs_schedule_ops = {
	.init = tbs_sched_init,
	.clean = tbs_sched_clean,
	.init_vgpu = tbs_sched_init_vgpu,
	.clean_vgpu = tbs_sched_clean_vgpu,
	.start_schedule = tbs_sched_start_schedule,
	.stop_schedule = tbs_sched_stop_schedule,
};

int intel_gvt_init_sched_policy(struct intel_gvt *gvt)
{
	gvt->scheduler.sched_ops = &tbs_schedule_ops;

	return gvt->scheduler.sched_ops->init(gvt);
}

void intel_gvt_clean_sched_policy(struct intel_gvt *gvt)
{
	gvt->scheduler.sched_ops->clean(gvt);
}

int intel_vgpu_init_sched_policy(struct intel_vgpu *vgpu)
{
	return vgpu->gvt->scheduler.sched_ops->init_vgpu(vgpu);
}

void intel_vgpu_clean_sched_policy(struct intel_vgpu *vgpu)
{
	vgpu->gvt->scheduler.sched_ops->clean_vgpu(vgpu);
}

void intel_vgpu_start_schedule(struct intel_vgpu *vgpu)
{
	gvt_dbg_core("vgpu%d: start schedule\n", vgpu->id);

	vgpu->gvt->scheduler.sched_ops->start_schedule(vgpu);
}

void intel_vgpu_stop_schedule(struct intel_vgpu *vgpu)
{
	struct intel_gvt_workload_scheduler *scheduler =
		&vgpu->gvt->scheduler;

	gvt_dbg_core("vgpu%d: stop schedule\n", vgpu->id);

	scheduler->sched_ops->stop_schedule(vgpu);

	if (scheduler->next_vgpu == vgpu)
		scheduler->next_vgpu = NULL;

	if (scheduler->current_vgpu == vgpu) {
		/* stop workload dispatching */
		scheduler->need_reschedule = true;
		scheduler->current_vgpu = NULL;
	}
}
