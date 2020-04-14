/*
 *  Copyright (C) 2003 Russell King, All Rights Reserved.
 *  Copyright 2006-2007 Pierre Ossman
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/scatterlist.h>
#include <linux/dma-mapping.h>
#include <linux/version.h>
#include <linux/backing-dev.h>

#include <linux/mmc/card.h>
#include <linux/mmc/host.h>
#include <linux/sched/rt.h>

#include "queue.h"
#include "block.h"
#include "core.h"
#include "crypto.h"
#include "card.h"

#define MMC_QUEUE_BOUNCESZ	65536

/*
 * Prepare a MMC request. This just filters out odd stuff.
 */
static int mmc_prep_request(struct request_queue *q, struct request *req)
{
	struct mmc_queue *mq = q->queuedata;

	if (mq && (mmc_card_removed(mq->card) || mmc_access_rpmb(mq)))
		return BLKPREP_KILL;

	req->rq_flags |= RQF_DONTPREP;

	return BLKPREP_OK;
}

static int mmc_queue_thread(void *d)
{
	struct mmc_queue *mq = d;
	struct request_queue *q = mq->queue;
	struct mmc_context_info *cntx = &mq->card->host->context_info;
	struct sched_param scheduler_params = {0};

	if (mq->card && (mq->card->type != MMC_TYPE_SD)) {
		scheduler_params.sched_priority = 1;
		sched_setscheduler(current, SCHED_FIFO, &scheduler_params);
	}
	
	current->flags |= PF_MEMALLOC;

	down(&mq->thread_sem);
	do {
		struct request *req = NULL;

		spin_lock_irq(q->queue_lock);
		set_current_state(TASK_INTERRUPTIBLE);
		if (mq->mqrq_prev->req &&
				(mq->card && (mq->card->type == MMC_TYPE_SD) &&
				mq->card->host->pm_progress))
			req = NULL;
		else
			req = blk_fetch_request(q);

		mq->asleep = false;
		cntx->is_waiting_last_req = false;
		cntx->is_new_req = false;
		if (!req) {
			/*
			 * Dispatch queue is empty so set flags for
			 * mmc_request_fn() to wake us up.
			 */
			if (mq->mqrq_prev->req)
				cntx->is_waiting_last_req = true;
			else
				mq->asleep = true;
		}
		mq->mqrq_cur->req = req;
		spin_unlock_irq(q->queue_lock);

		if (req || mq->mqrq_prev->req) {
			bool req_is_special = mmc_req_is_special(req);

			set_current_state(TASK_RUNNING);
			mmc_blk_issue_rq(mq, req);
			cond_resched();
			if (mq->new_request) {
				mq->new_request = false;
				continue; /* fetch again */
			}

			/*
			 * Current request becomes previous request
			 * and vice versa.
			 * In case of special requests, current request
			 * has been finished. Do not assign it to previous
			 * request.
			 */
			if (req_is_special)
				mq->mqrq_cur->req = NULL;

			mq->mqrq_prev->brq.mrq.data = NULL;
			mq->mqrq_prev->req = NULL;
			swap(mq->mqrq_prev, mq->mqrq_cur);
		} else {
			if (kthread_should_stop()) {
				set_current_state(TASK_RUNNING);
				break;
			}
			up(&mq->thread_sem);
			schedule();
			down(&mq->thread_sem);
		}
	} while (1);
	up(&mq->thread_sem);

	return 0;
}

/*
 * Generic MMC request handler.  This is called for any queue on a
 * particular host.  When the host is not busy, we look for a request
 * on any queue on this host, and attempt to issue it.  This may
 * not be the queue we were asked to process.
 */
static void mmc_request_fn(struct request_queue *q)
{
	struct mmc_queue *mq = q->queuedata;
	struct request *req;
	struct mmc_context_info *cntx;

	if (!mq) {
		while ((req = blk_fetch_request(q)) != NULL) {
			req->rq_flags |= RQF_QUIET;
			__blk_end_request_all(req, BLK_STS_IOERR);
		}
		return;
	}

	cntx = &mq->card->host->context_info;

	if (cntx->is_waiting_last_req) {
		cntx->is_new_req = true;
		wake_up_interruptible(&cntx->wait);
	}

	if (mq->asleep)
		wake_up_process(mq->thread);
}

static struct scatterlist *mmc_alloc_sg(int sg_len, int *err)
{
	struct scatterlist *sg;

	sg = kmalloc_array(sg_len, sizeof(*sg), GFP_KERNEL);
	if (!sg)
		*err = -ENOMEM;
	else {
		*err = 0;
		sg_init_table(sg, sg_len);
	}

	return sg;
}

static void mmc_queue_setup_discard(struct request_queue *q,
				    struct mmc_card *card)
{
	unsigned max_discard;

	max_discard = mmc_calc_max_discard(card);
	if (!max_discard)
		return;

	queue_flag_set_unlocked(QUEUE_FLAG_DISCARD, q);
	blk_queue_max_discard_sectors(q, max_discard);
	q->limits.discard_granularity = card->pref_erase << 9;
	/* granularity must not be greater than max. discard */
	if (card->pref_erase > max_discard)
		q->limits.discard_granularity = 0;
	if (mmc_can_secure_erase_trim(card))
		queue_flag_set_unlocked(QUEUE_FLAG_SECERASE, q);
}

#ifdef CONFIG_MMC_BLOCK_BOUNCE
static bool mmc_queue_alloc_bounce_bufs(struct mmc_queue *mq,
					unsigned int bouncesz)
{
	int i;

	for (i = 0; i < mq->qdepth; i++) {
		mq->mqrq[i].bounce_buf = kmalloc(bouncesz, GFP_KERNEL);
		if (!mq->mqrq[i].bounce_buf)
			goto out_err;
	}

	return true;

out_err:
	while (--i >= 0) {
		kfree(mq->mqrq[i].bounce_buf);
		mq->mqrq[i].bounce_buf = NULL;
	}
	pr_warn("%s: unable to allocate bounce buffers\n",
		mmc_card_name(mq->card));
	return false;
}

static int mmc_queue_alloc_bounce_sgs(struct mmc_queue *mq,
				      unsigned int bouncesz)
{
	int i, ret;

	for (i = 0; i < mq->qdepth; i++) {
		mq->mqrq[i].sg = mmc_alloc_sg(1, &ret);
		if (ret)
			return ret;

		mq->mqrq[i].bounce_sg = mmc_alloc_sg(bouncesz / 512, &ret);
		if (ret)
			return ret;
	}

	return 0;
}
#endif

static int mmc_queue_alloc_sgs(struct mmc_queue *mq, int max_segs)
{
	int i, ret;

	for (i = 0; i < mq->qdepth; i++) {
		mq->mqrq[i].sg = mmc_alloc_sg(max_segs, &ret);
		if (ret)
			return ret;
	}

	return 0;
}

static void mmc_queue_req_free_bufs(struct mmc_queue_req *mqrq)
{
	kfree(mqrq->bounce_sg);
	mqrq->bounce_sg = NULL;

	kfree(mqrq->sg);
	mqrq->sg = NULL;

	kfree(mqrq->bounce_buf);
	mqrq->bounce_buf = NULL;
}

static void mmc_queue_reqs_free_bufs(struct mmc_queue *mq)
{
	int i;

	for (i = 0; i < mq->qdepth; i++)
		mmc_queue_req_free_bufs(&mq->mqrq[i]);
}

/**
 * mmc_init_queue - initialise a queue structure.
 * @mq: mmc queue
 * @card: mmc card to attach this queue
 * @lock: queue lock
 * @subname: partition subname
 *
 * Initialise a MMC card request queue.
 */
int mmc_init_queue(struct mmc_queue *mq, struct mmc_card *card,
		   spinlock_t *lock, const char *subname)
{
	struct mmc_host *host = card->host;
	u64 limit = BLK_BOUNCE_HIGH;
	bool bounce = false;
	int ret = -ENOMEM;

	if (mmc_dev(host)->dma_mask && *mmc_dev(host)->dma_mask)
		limit = (u64)dma_max_pfn(mmc_dev(host)) << PAGE_SHIFT;

	mq->card = card;
	mq->queue = blk_init_queue(mmc_request_fn, lock);
	if (!mq->queue)
		return -ENOMEM;

	mq->qdepth = 2;
	mq->mqrq = kcalloc(mq->qdepth, sizeof(struct mmc_queue_req),
			   GFP_KERNEL);
	if (!mq->mqrq)
		goto blk_cleanup;
	mq->mqrq_cur = &mq->mqrq[0];
	mq->mqrq_prev = &mq->mqrq[1];
	mq->queue->queuedata = mq;

	blk_queue_prep_rq(mq->queue, mmc_prep_request);
	queue_flag_set_unlocked(QUEUE_FLAG_NONROT, mq->queue);
	queue_flag_clear_unlocked(QUEUE_FLAG_ADD_RANDOM, mq->queue);
	if (mmc_can_erase(card))
		mmc_queue_setup_discard(mq->queue, card);

#ifdef CONFIG_MMC_BLOCK_BOUNCE
	if (host->max_segs == 1) {
		unsigned int bouncesz;

		bouncesz = MMC_QUEUE_BOUNCESZ;

		if (bouncesz > host->max_req_size)
			bouncesz = host->max_req_size;
		if (bouncesz > host->max_seg_size)
			bouncesz = host->max_seg_size;
		if (bouncesz > (host->max_blk_count * 512))
			bouncesz = host->max_blk_count * 512;

		if (bouncesz > 512 &&
		    mmc_queue_alloc_bounce_bufs(mq, bouncesz)) {
			blk_queue_bounce_limit(mq->queue, BLK_BOUNCE_ANY);
			blk_queue_max_hw_sectors(mq->queue, bouncesz / 512);
			blk_queue_max_segments(mq->queue, bouncesz / 512);
			blk_queue_max_segment_size(mq->queue, bouncesz);

			ret = mmc_queue_alloc_bounce_sgs(mq, bouncesz);
			if (ret)
				goto cleanup_queue;
			bounce = true;
		}
	}
#endif

	if (!bounce) {
		blk_queue_bounce_limit(mq->queue, limit);
		blk_queue_max_hw_sectors(mq->queue,
			min(host->max_blk_count, host->max_req_size / 512));
		blk_queue_max_segments(mq->queue, host->max_segs);
		blk_queue_max_segment_size(mq->queue, host->max_seg_size);

		ret = mmc_queue_alloc_sgs(mq, host->max_segs);
		if (ret)
			goto cleanup_queue;
	}

	sema_init(&mq->thread_sem, 1);

	mq->thread = kthread_run(mmc_queue_thread, mq, "mmcqd/%d%s",
		host->index, subname ? subname : "");

	if (mmc_card_sd(card)) {
		/* decrease max # of requests to 32. The goal of this tunning is
		 * reducing the time for draining elevator when elevator_switch
		 * function is called. It is effective for slow external sdcard.
		 */
		mq->queue->nr_requests = BLKDEV_MAX_RQ / 8;
		if (mq->queue->nr_requests < 32)
			mq->queue->nr_requests = 32;
#ifdef CONFIG_LARGE_DIRTY_BUFFER
		/* apply more throttle on external sdcard */
		mq->queue->backing_dev_info.capabilities |= BDI_CAP_STRICTLIMIT;
		bdi_set_min_ratio(&mq->queue->backing_dev_info, 30);
		bdi_set_max_ratio(&mq->queue->backing_dev_info, 60);
#endif
		pr_info("Parameters for external-sdcard: min/max_ratio: %u/%u "
			"strictlimit: on nr_requests: %lu read_ahead_kb: %lu\n",
			mq->queue->backing_dev_info.min_ratio,
			mq->queue->backing_dev_info.max_ratio,
			mq->queue->nr_requests,
			mq->queue->backing_dev_info.ra_pages * 4);
	}

	if (IS_ERR(mq->thread)) {
		ret = PTR_ERR(mq->thread);
		goto cleanup_queue;
	}

	mmc_crypto_setup_queue(host, mq->queue);
	return 0;

 cleanup_queue:
	mmc_queue_reqs_free_bufs(mq);
	kfree(mq->mqrq);
	mq->mqrq = NULL;
blk_cleanup:
	blk_cleanup_queue(mq->queue);
	return ret;
}

void mmc_cleanup_queue(struct mmc_queue *mq)
{
	struct request_queue *q = mq->queue;
	unsigned long flags;

	/* Make sure the queue isn't suspended, as that will deadlock */
	mmc_queue_resume(mq);

	/* Then terminate our worker thread */
	kthread_stop(mq->thread);

#ifdef CONFIG_LARGE_DIRTY_BUFFER
	/* Restore bdi min/max ratio before device removal */
	bdi_set_min_ratio(&mq->queue->backing_dev_info, 0);
	bdi_set_max_ratio(&mq->queue->backing_dev_info, 100);
#endif
	/* Empty the queue */
	spin_lock_irqsave(q->queue_lock, flags);
	q->queuedata = NULL;
	blk_start_queue(q);
	spin_unlock_irqrestore(q->queue_lock, flags);

	mmc_queue_reqs_free_bufs(mq);
	kfree(mq->mqrq);
	mq->mqrq = NULL;

	mq->card = NULL;
}
EXPORT_SYMBOL(mmc_cleanup_queue);

/**
 * mmc_queue_suspend - suspend a MMC request queue
 * @mq: MMC queue to suspend
 *
 * Stop the block request queue, and wait for our thread to
 * complete any outstanding requests.  This ensures that we
 * won't suspend while a request is being processed.
 */
int mmc_queue_suspend(struct mmc_queue *mq, int wait)
{
	struct request_queue *q = mq->queue;
	struct request *req;
	unsigned long flags;
	int rc = 0;

	if (!mq->suspended) {
		mq->suspended |= true;

		spin_lock_irqsave(q->queue_lock, flags);
		blk_stop_queue(q);
		spin_unlock_irqrestore(q->queue_lock, flags);
		rc = down_trylock(&mq->thread_sem);
		if (rc && !wait) {
			mq->suspended |= true;
			spin_lock_irqsave(q->queue_lock, flags);
			blk_start_queue(q);
			spin_unlock_irqrestore(q->queue_lock, flags);
			rc = -EBUSY;
		} else if (wait) {
			printk("%s: mq->flags: %x, q->queue_flags: 0x%lx, \
					q->in_flight (%d, %d) \n",
					mmc_hostname(mq->card->host), mq,
					q->queue_flags, q->in_flight[0], q->in_flight[1]);
			mutex_lock(&q->sysfs_lock);
			if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)) {
				queue_flag_set_unlocked(QUEUE_FLAG_DYING, q);
				spin_lock_irqsave(q->queue_lock, flags);
				queue_flag_set(QUEUE_FLAG_DYING, q);
			} else if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 8, 0)) {
				queue_flag_set_unlocked(QUEUE_FLAG_DEAD, q);
				spin_lock_irqsave(q->queue_lock, flags);
				queue_flag_set(QUEUE_FLAG_DEAD, q);
			}

			while ((req = blk_fetch_request(q)) != NULL) {
				req->rq_flags |= RQF_QUIET;
				__blk_end_request_all(req, -EIO);
			}

			spin_unlock_irqrestore(q->queue_lock, flags);
			mutex_unlock(&q->sysfs_lock);
			if (rc) {
				down(&mq->thread_sem);
				rc = 0;
			}
		}

	}
	return rc;
}

/**
 * mmc_queue_resume - resume a previously suspended MMC request queue
 * @mq: MMC queue to resume
 */
void mmc_queue_resume(struct mmc_queue *mq)
{
	struct request_queue *q = mq->queue;
	unsigned long flags;

	if (mq->suspended) {
		mq->suspended = false;

		up(&mq->thread_sem);

		spin_lock_irqsave(q->queue_lock, flags);
		blk_start_queue(q);
		spin_unlock_irqrestore(q->queue_lock, flags);
	}
}

/*
 * Prepare the sg list(s) to be handed of to the host driver
 */
unsigned int mmc_queue_map_sg(struct mmc_queue *mq, struct mmc_queue_req *mqrq)
{
	unsigned int sg_len;
	size_t buflen;
	struct scatterlist *sg;
	int i;

	if (!mqrq->bounce_buf)
		return blk_rq_map_sg(mq->queue, mqrq->req, mqrq->sg);

	sg_len = blk_rq_map_sg(mq->queue, mqrq->req, mqrq->bounce_sg);

	mqrq->bounce_sg_len = sg_len;

	buflen = 0;
	for_each_sg(mqrq->bounce_sg, sg, sg_len, i)
		buflen += sg->length;

	sg_init_one(mqrq->sg, mqrq->bounce_buf, buflen);

	return 1;
}

/*
 * If writing, bounce the data to the buffer before the request
 * is sent to the host driver
 */
void mmc_queue_bounce_pre(struct mmc_queue_req *mqrq)
{
	if (!mqrq->bounce_buf)
		return;

	if (rq_data_dir(mqrq->req) != WRITE)
		return;

	sg_copy_to_buffer(mqrq->bounce_sg, mqrq->bounce_sg_len,
		mqrq->bounce_buf, mqrq->sg[0].length);
}

/*
 * If reading, bounce the data from the buffer after the request
 * has been handled by the host driver
 */
void mmc_queue_bounce_post(struct mmc_queue_req *mqrq)
{
	if (!mqrq->bounce_buf)
		return;

	if (rq_data_dir(mqrq->req) != READ)
		return;

	sg_copy_from_buffer(mqrq->bounce_sg, mqrq->bounce_sg_len,
		mqrq->bounce_buf, mqrq->sg[0].length);
}
