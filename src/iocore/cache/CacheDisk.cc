/** @file

  A brief file description

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 */

#include "P_CacheDisk.h"
#include "P_CacheInternal.h"
#include "StripeSM.h"

void
CacheDisk::incrErrors(const AIOCallback *io)
{
  if (0 == this->num_errors) {
    /* This it the first read/write error on this span since ATS started.
     * Move the newly failing span from "online" to "failing" bucket. */
    ts::Metrics::Gauge::decrement(cache_rsb.span_online);
    ts::Metrics::Gauge::increment(cache_rsb.span_failing);
  }
  this->num_errors++;

  const char *opname = "unknown";
  int         opcode = io->aiocb.aio_lio_opcode;
  int         fd     = io->aiocb.aio_fildes;
  switch (io->aiocb.aio_lio_opcode) {
  case LIO_READ:
    opname = "READ";
    ts::Metrics::Counter::increment(cache_rsb.span_errors_read);
    break;
  case LIO_WRITE:
    opname = "WRITE";
    ts::Metrics::Counter::increment(cache_rsb.span_errors_write);
    break;
  default:
    break;
  }
  Warning("failed operation: %s (opcode=%d), span: %s (fd=%d)", opname, opcode, path, fd);
}

int
CacheDisk::open(char *s, off_t blocks, off_t askip, int ahw_sector_size, int fildes, bool clear)
{
  path           = ats_strdup(s);
  hw_sector_size = ahw_sector_size;
  fd             = fildes;
  skip           = askip;
  start          = skip;
  /* we can't use fractions of store blocks. */
  len                 = blocks;
  io.aiocb.aio_fildes = fd;
  io.action           = this;
  // determine header size and hence start point by successive approximation
  uint64_t l;
  for (int i = 0; i < 3; i++) {
    l = (len * STORE_BLOCK_SIZE) - (start - skip);
    if (l >= MIN_STRIPE_SIZE) {
      header_len = sizeof(DiskHeader) + (l / MIN_STRIPE_SIZE - 1) * sizeof(DiskStripeBlock);
    } else {
      header_len = sizeof(DiskHeader);
    }
    start = skip + header_len;
  }

  disk_stripes      = static_cast<DiskStripe **>(ats_calloc((l / MIN_STRIPE_SIZE + 1), sizeof(DiskStripe *)));
  header_len        = ROUND_TO_STORE_BLOCK(header_len);
  start             = skip + header_len;
  num_usable_blocks = (static_cast<off_t>(len * STORE_BLOCK_SIZE) - (start - askip)) >> STORE_BLOCK_SHIFT;

  header = static_cast<DiskHeader *>(ats_memalign(ats_pagesize(), header_len));
  memset(header, 0, header_len);

  // traffic server was asked to clear the cache, i.e., auto clear cache flag is set
  if (clear) {
    if (read_only_p) {
      fprintf(stderr, "Could not read disk header for disk %s", path);
      SET_DISK_BAD(this);
      SET_HANDLER(&CacheDisk::openDone);
      return openDone(EVENT_IMMEDIATE, nullptr);
    } else {
      SET_HANDLER(&CacheDisk::clearDone);
      return clearDisk();
    }
  }

  // read disk header
  SET_HANDLER(&CacheDisk::openStart);
  io.aiocb.aio_offset = skip;
  io.aiocb.aio_buf    = reinterpret_cast<char *>(header);
  io.aiocb.aio_nbytes = header_len;
  io.thread           = AIO_CALLBACK_THREAD_ANY;
  ink_aio_read(&io);
  return 0;
}

CacheDisk::~CacheDisk()
{
  if (path) {
    ats_free(path);
    for (int i = 0; i < static_cast<int>(header->num_volumes); i++) {
      DiskStripeBlockQueue *q = nullptr;
      while (disk_stripes[i] && (q = (disk_stripes[i]->dpb_queue.pop()))) {
        delete q;
      }
    }
    ats_free(disk_stripes);
    free(header);
  }
  if (free_blocks) {
    DiskStripeBlockQueue *q = nullptr;
    while ((q = (free_blocks->dpb_queue.pop()))) {
      delete q;
    }
  }
}

int
CacheDisk::clearDisk()
{
  delete_all_volumes();

  io.aiocb.aio_offset = skip;
  io.aiocb.aio_buf    = header;
  io.aiocb.aio_nbytes = header_len;
  io.thread           = AIO_CALLBACK_THREAD_ANY;
  ink_aio_write(&io);
  return 0;
}

int
CacheDisk::clearDone(int event, void * /* data ATS_UNUSED */)
{
  ink_assert(event == AIO_EVENT_DONE);

  if (!io.ok()) {
    Warning("Could not clear disk header for disk %s: declaring disk bad", path);
    incrErrors(&io);
    SET_DISK_BAD(this);
  }
  //  update_header();

  SET_HANDLER(&CacheDisk::openDone);
  return openDone(EVENT_IMMEDIATE, nullptr);
}

int
CacheDisk::openStart(int event, void * /* data ATS_UNUSED */)
{
  ink_assert(event == AIO_EVENT_DONE);

  if (!io.ok()) {
    Warning("could not read disk header for disk %s: declaring disk bad", path);

    // the header could have random values by the AIO read error
    memset(header, 0, header_len);

    incrErrors(&io);
    SET_DISK_BAD(this);
    SET_HANDLER(&CacheDisk::openDone);
    return openDone(EVENT_IMMEDIATE, nullptr);
  }

  if (header->magic != DISK_HEADER_MAGIC || header->num_blocks != static_cast<uint64_t>(len)) {
    uint64_t delta_3_2 = skip - (skip >> STORE_BLOCK_SHIFT); // block count change from 3.2
    if (static_cast<uint64_t>(len) == header->num_blocks + delta_3_2) {
      header->num_blocks += delta_3_2;
      // Only recover the space if there is a single stripe on this disk. The stripe space allocation logic can fail if
      // there is any difference at all in splitting the disk into stripes. The problem is we can add only to the last
      // stripe, because otherwise the stripe offsets are wrong. But if the stripes didn't split evenly and the last
      // stripe isn't the short one, the split will be different this time.
      // Further - the size is encoded in to the disk hash so if the size changes, the data is effectively lost anyway.
      // So no space recovery.
      //      if (header->num_diskvol_blks == 1)
      //        header->vol_info[0].len += delta_3_2;
    } else if (read_only_p) {
      fprintf(stderr, "Disk header is different than expected for disk %s", path);
      SET_DISK_BAD(this);
      SET_HANDLER(&CacheDisk::openDone);
      return EVENT_DONE;
    } else {
      Warning("disk header different for disk %s: clearing the disk", path);
      SET_HANDLER(&CacheDisk::clearDone);
      clearDisk();
      return EVENT_DONE;
    }
  }

  cleared = 0;
  /* populate disk_vols */
  update_header();

  SET_HANDLER(&CacheDisk::openDone);
  return openDone(EVENT_IMMEDIATE, nullptr);
}

int
CacheDisk::openDone(int /* event ATS_UNUSED */, void * /* data ATS_UNUSED */)
{
  if (cacheProcessor.start_done) {
    SET_HANDLER(&CacheDisk::syncDone);
    cacheProcessor.diskInitialized();
    return EVENT_DONE;
  } else {
    eventProcessor.schedule_in(this, HRTIME_MSECONDS(5), ET_CALL);
    return EVENT_CONT;
  }
}

int
CacheDisk::sync()
{
  io.aiocb.aio_offset = skip;
  io.aiocb.aio_buf    = header;
  io.aiocb.aio_nbytes = header_len;
  io.thread           = AIO_CALLBACK_THREAD_ANY;
  ink_aio_write(&io);
  return 0;
}

int
CacheDisk::syncDone(int event, void * /* data ATS_UNUSED */)
{
  ink_assert(event == AIO_EVENT_DONE);

  if (!io.ok()) {
    Warning("Error writing disk header for disk %s:disk bad", path);
    incrErrors(&io);
    SET_DISK_BAD(this);
    return EVENT_DONE;
  }

  return EVENT_DONE;
}

/* size is in store blocks */
DiskStripeBlock *
CacheDisk::create_volume(int number, off_t size_in_blocks, CacheType scheme)
{
  if (size_in_blocks == 0) {
    return nullptr;
  }

  DiskStripeBlockQueue *q             = free_blocks->dpb_queue.head;
  DiskStripeBlockQueue *closest_match = q;

  if (!q) {
    return nullptr;
  }

  off_t max_blocks = MAX_STRIPE_SIZE >> STORE_BLOCK_SHIFT;
  size_in_blocks   = (size_in_blocks <= max_blocks) ? size_in_blocks : max_blocks;

  int blocks_per_vol = STORE_BLOCKS_PER_STRIPE;
  //  ink_assert(!(size_in_blocks % blocks_per_vol));
  DiskStripeBlock *p = nullptr;
  for (; q; q = q->link.next) {
    if (static_cast<off_t>(q->b->len) >= size_in_blocks) {
      p            = q->b;
      q->new_block = 1;
      break;
    } else {
      if (closest_match->b->len < q->b->len) {
        closest_match = q;
      }
    }
  }

  if (!p && closest_match) {
    /* allocate from the closest match */
    q            = closest_match;
    p            = q->b;
    q->new_block = 1;
    ink_assert(size_in_blocks > (off_t)p->len);
    /* allocate in 128 megabyte chunks. The Remaining space should
       be thrown away */
    size_in_blocks  = (p->len - (p->len % blocks_per_vol));
    wasted_space   += p->len % blocks_per_vol;
  }

  free_blocks->dpb_queue.remove(q);
  free_space        -= p->len;
  free_blocks->size -= p->len;

  size_t new_size = p->len - size_in_blocks;
  if (new_size >= static_cast<size_t>(blocks_per_vol)) {
    /* create a new volume */
    DiskStripeBlock *dpb  = &header->vol_info[header->num_diskvol_blks];
    *dpb                  = *p;
    dpb->len             -= size_in_blocks;
    dpb->offset          += (size_in_blocks * STORE_BLOCK_SIZE);

    DiskStripeBlockQueue *new_q = new DiskStripeBlockQueue();
    new_q->b                    = dpb;
    free_blocks->dpb_queue.enqueue(new_q);
    free_blocks->size += dpb->len;
    free_space        += dpb->len;
    header->num_diskvol_blks++;
  } else {
    header->num_free--;
  }

  p->len    = size_in_blocks;
  p->free   = 0;
  p->number = number;
  p->type   = static_cast<unsigned int>(scheme);
  header->num_used++;

  unsigned int i;
  /* add it to its disk_vol */
  for (i = 0; i < header->num_volumes; i++) {
    if (disk_stripes[i]->vol_number == number) {
      disk_stripes[i]->dpb_queue.enqueue(q);
      disk_stripes[i]->num_volblocks++;
      disk_stripes[i]->size += q->b->len;
      break;
    }
  }
  if (i == header->num_volumes) {
    disk_stripes[i]                = new DiskStripe();
    disk_stripes[i]->num_volblocks = 1;
    disk_stripes[i]->vol_number    = number;
    disk_stripes[i]->disk          = this;
    disk_stripes[i]->dpb_queue.enqueue(q);
    disk_stripes[i]->size = q->b->len;
    header->num_volumes++;
  }
  return p;
}

int
CacheDisk::delete_volume(int number)
{
  unsigned int i;
  for (i = 0; i < header->num_volumes; i++) {
    if (disk_stripes[i]->vol_number == number) {
      DiskStripeBlockQueue *q;
      for (q = disk_stripes[i]->dpb_queue.head; q;) {
        DiskStripeBlock *p  = q->b;
        p->type             = static_cast<unsigned int>(CacheType::NONE);
        p->free             = 1;
        free_space         += p->len;
        header->num_free++;
        header->num_used--;
        DiskStripeBlockQueue *temp_q = q->link.next;
        disk_stripes[i]->dpb_queue.remove(q);
        free_blocks->dpb_queue.enqueue(q);
        q = temp_q;
      }
      free_blocks->num_volblocks += disk_stripes[i]->num_volblocks;
      free_blocks->size          += disk_stripes[i]->size;

      delete disk_stripes[i];

      /* move all the other disk vols */
      for (unsigned int j = i; j < (header->num_volumes - 1); j++) {
        disk_stripes[j] = disk_stripes[j + 1];
      }
      header->num_volumes--;
      return 0;
    }
  }
  return -1;
}

void
CacheDisk::update_header()
{
  unsigned int n = 0;
  unsigned int i, j;
  if (free_blocks) {
    DiskStripeBlockQueue *q = nullptr;
    while ((q = (free_blocks->dpb_queue.pop()))) {
      delete q;
    }
  }
  free_blocks                = std::make_unique<DiskStripe>();
  free_blocks->vol_number    = -1;
  free_blocks->disk          = this;
  free_blocks->num_volblocks = 0;
  free_blocks->size          = 0;
  free_space                 = 0;

  for (i = 0; i < header->num_diskvol_blks; i++) {
    DiskStripeBlockQueue *dpbq            = new DiskStripeBlockQueue();
    bool                  dpbq_referenced = false;
    dpbq->b                               = &header->vol_info[i];
    if (header->vol_info[i].free) {
      free_blocks->num_volblocks++;
      free_blocks->size += dpbq->b->len;
      free_blocks->dpb_queue.enqueue(dpbq);
      free_space += dpbq->b->len;
      continue;
    }
    int vol_number = header->vol_info[i].number;
    for (j = 0; j < n; j++) {
      if (disk_stripes[j]->vol_number == vol_number) {
        disk_stripes[j]->dpb_queue.enqueue(dpbq);
        dpbq_referenced = true;
        disk_stripes[j]->num_volblocks++;
        disk_stripes[j]->size += dpbq->b->len;
        break;
      }
    }
    if (j == n) {
      // did not find a matching volume number. create a new
      // one
      disk_stripes[j]                = new DiskStripe();
      disk_stripes[j]->vol_number    = vol_number;
      disk_stripes[j]->disk          = this;
      disk_stripes[j]->num_volblocks = 1;
      disk_stripes[j]->size          = dpbq->b->len;
      disk_stripes[j]->dpb_queue.enqueue(dpbq);
      dpbq_referenced = true;
      n++;
    }
    // check to see if we even used the dpbq allocated
    if (dpbq_referenced == false) {
      delete dpbq;
    }
  }

  ink_assert(n == header->num_volumes);
}

DiskStripe *
CacheDisk::get_diskvol(int vol_number)
{
  unsigned int i;
  for (i = 0; i < header->num_volumes; i++) {
    if (disk_stripes[i]->vol_number == vol_number) {
      return disk_stripes[i];
    }
  }
  return nullptr;
}

int
CacheDisk::delete_all_volumes()
{
  header->vol_info[0].offset = start;
  header->vol_info[0].len    = num_usable_blocks;
  header->vol_info[0].type   = static_cast<unsigned int>(CacheType::NONE);
  header->vol_info[0].free   = 1;

  header->magic            = DISK_HEADER_MAGIC;
  header->num_used         = 0;
  header->num_volumes      = 0;
  header->num_free         = 1;
  header->num_diskvol_blks = 1;
  header->num_blocks       = len;
  cleared                  = 1;
  update_header();

  return 0;
}
