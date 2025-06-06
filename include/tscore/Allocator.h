/** @file

  Fast-Allocators

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

  Provides three classes
    - Allocator for allocating memory blocks of fixed size
    - ClassAllocator for allocating objects
    - SpaceClassAllocator for allocating sparse objects (most members uninitialized)

  These class provides a efficient way for handling dynamic allocation.
  The fast allocator maintains its own freepool of objects from
  which it doles out object. Allocated objects when freed go back
  to the free pool.

  @note Fast allocators could accumulate a lot of objects in the
  free pool as a result of bursty demand. Memory used by the objects
  in the free pool never gets freed even if the freelist grows very
  large.

 */

#pragma once

#include <cstdlib>
#include <utility>
#include "tscore/ink_queue.h"
#include "tscore/ink_resource.h"
#include "tsutil/Metrics.h"
#include <execinfo.h>

#define RND16(_x) (((_x) + 15) & ~15)

/** Allocator for fixed size memory blocks. */
class FreelistAllocator
{
public:
  /**
    Allocate a block of memory (size specified during construction
    of Allocator.
  */
  void *
  alloc_void()
  {
    return ink_freelist_new(this->fl);
  }

  /**
    Deallocate a block of memory allocated by the Allocator.

    @param ptr pointer to be freed.
  */
  void
  free_void(void *ptr)
  {
    ink_freelist_free(this->fl, ptr);
  }

  /**
    Deallocate blocks of memory allocated by the Allocator.

    @param head pointer to be freed.
    @param tail pointer to be freed.
    @param num_item of blocks to be freed.
  */
  void
  free_void_bulk(void *head, void *tail, size_t num_item)
  {
    ink_freelist_free_bulk(this->fl, head, tail, num_item);
  }

  FreelistAllocator() { fl = nullptr; }

  /**
    Creates a new allocator.

    @param name identification tag used for mem tracking .
    @param element_size size of memory blocks to be allocated.
    @param chunk_size number of units to be allocated if free pool is empty.
    @param alignment of objects must be a power of 2.
  */
  FreelistAllocator(const char *name, unsigned int element_size, unsigned int chunk_size = 128, unsigned int alignment = 8,
                    bool use_hugepages = false)
  {
    ink_freelist_init(&fl, name, element_size, chunk_size, alignment, use_hugepages);
  }

  /** Re-initialize the parameters of the allocator. */
  void
  re_init(const char *name, unsigned int element_size, unsigned int chunk_size, unsigned int alignment, bool use_hugepages,
          int advice)
  {
    ink_freelist_madvise_init(&this->fl, name, element_size, chunk_size, alignment, use_hugepages, advice);
  }

  // Dummies
  void
  destroy_if_enabled(void *)
  {
  }
  FreelistAllocator &
  raw()
  {
    return *this;
  }

protected:
  InkFreeList *fl;
};

class MallocAllocator
{
public:
  /**
    Allocate a block of memory (size specified during construction
    of Allocator.
  */
  void *
  alloc_void()
  {
    void *ptr = nullptr;
    if (alignment) {
      ptr = aligned_alloc(alignment, element_size);
    } else {
      ptr = malloc(element_size);
    }
    if (advice) {
      madvise(ptr, element_size, advice);
    }
    return ptr;
  }

  /**
    Deallocate a block of memory allocated by the Allocator.

    @param ptr pointer to be freed.
  */
  void
  free_void(void *ptr)
  {
    ::free(ptr);
  }

  /**
    Deallocate blocks of memory allocated by the Allocator.

    @param head pointer to be freed.
    @param tail pointer to be freed.
    @param num_item of blocks to be freed.
  */
  void
  free_void_bulk(void *head, void *, size_t num_item)
  {
    void *item = head;
    void *next;

    for (size_t i = 0; i < num_item && item; ++i, item = next) {
      next = *static_cast<void **>(item); // find next item before freeing current item
      free_void(item);
    }
  }

  MallocAllocator() {}

  /**
    Creates a new allocator.

    @param name identification tag used for mem tracking .
    @param element_size size of memory blocks to be allocated.
    @param chunk_size number of units to be allocated if free pool is empty.
    @param alignment of objects must be a power of 2.
  */
  MallocAllocator(const char * /* name ATS_UNUSED */, unsigned int element_size, unsigned int /* chunk_size  ATS_UNUSED */ = 128,
                  unsigned int alignment = 8, bool /* use_hugepages  ATS_UNUSED */ = false)
    : element_size(element_size), alignment(alignment), advice(0)
  {
  }

  /** Re-initialize the parameters of the allocator. */
  void
  re_init(const char * /* name ATS_UNUSED */, unsigned int element_size, unsigned int /* chunk_size ATS_UNUSED */,
          unsigned int alignment, bool /* use_hugepages ATS_UNUSED */, int advice)
  {
    this->element_size = element_size;
    this->alignment    = alignment;
    this->advice       = advice;
  }

  // Dummies
  void
  destroy_if_enabled(void *)
  {
  }
  MallocAllocator &
  raw()
  {
    return *this;
  }

private:
  unsigned int element_size;
  unsigned int alignment;
  int          advice;
};

#if TS_USE_ALLOCATOR_METRICS
template <typename WrappedAllocator> class MeteredAllocator : public WrappedAllocator
{
public:
  void *
  alloc_void()
  {
    increment_for_alloc();
    return WrappedAllocator::alloc_void();
  }

  void
  free_void(void *ptr)
  {
    increment_for_free();
    WrappedAllocator::free_void(ptr);
  }

  void
  free_void_bulk(void *head, void *tail, size_t num_item)
  {
    // this is only currently called from ProxyAllocator to free
    // back to the watermark, so if this is called, it means
    // the ProxyAllocator free has been decrementing the free count
    // for items on its freelist so this function should not update metrics
    WrappedAllocator::free_void_bulk(head, tail, num_item);
  }

  // NOTE(cmcfarlen): These metric functions are also called
  // by ProxyAllocator when items are added/removed from its freelist
  void
  increment_for_alloc()
  {
    inuse_metric->increment(1);
    alloc_metric->increment(1);
  }

  void
  increment_for_free(int val = 1)
  {
    inuse_metric->decrement(val);
    free_metric->increment(val);
  }

  MeteredAllocator() {}

  MeteredAllocator(const char *name, unsigned int element_size, unsigned int chunk_size = 128, unsigned int alignment = 8,
                   bool use_hugepages = false)
    : WrappedAllocator(name, element_size, chunk_size, alignment, use_hugepages),
      inuse_metric{ts::Metrics::Gauge::createPtr("proxy.process.allocator.inuse.", name)},
      alloc_metric{ts::Metrics::Counter::createPtr("proxy.process.allocator.alloc.", name)},
      free_metric{ts::Metrics::Counter::createPtr("proxy.process.allocator.free.", name)},
      size_metric{ts::Metrics::Gauge::createPtr("proxy.process.allocator.size.", name)}
  {
    size_metric->store(element_size);
  }

  void
  re_init(const char *name, unsigned int element_size, unsigned int chunk_size, unsigned int alignment, bool use_hugepages,
          int advice)
  {
    if (inuse_metric == nullptr) {
      inuse_metric = ts::Metrics::Gauge::createPtr("proxy.process.allocator.inuse.", name);
      alloc_metric = ts::Metrics::Counter::createPtr("proxy.process.allocator.alloc.", name);
      free_metric  = ts::Metrics::Counter::createPtr("proxy.process.allocator.free.", name);
      size_metric  = ts::Metrics::Gauge::createPtr("proxy.process.allocator.size.", name);
    }
    size_metric->store(element_size);

    WrappedAllocator::re_init(name, element_size, chunk_size, alignment, use_hugepages, advice);
  }

  void
  destroy_if_enabled(void *p)
  {
    WrappedAllocator::destroy_if_enabled(p);
  }

  // for metered allocator we don't want to return superclass or we'll skip metrics (see THREAD_FREE macro)
  MeteredAllocator<WrappedAllocator> &
  raw()
  {
    return *this;
  }

private:
  ts::Metrics::AtomicType *inuse_metric = nullptr;
  ts::Metrics::AtomicType *alloc_metric = nullptr;
  ts::Metrics::AtomicType *free_metric  = nullptr;
  ts::Metrics::AtomicType *size_metric  = nullptr;
};

#if TS_USE_MALLOC_ALLOCATOR
using Allocator = MeteredAllocator<MallocAllocator>;
#else
using Allocator = MeteredAllocator<FreelistAllocator>;
#endif
#else
#if TS_USE_MALLOC_ALLOCATOR
using Allocator = MallocAllocator;
#else
using Allocator = FreelistAllocator;
#endif
#endif // TS_USE_ALLOCATOR_METRICS

/**
  Allocator for Class objects.

*/
template <class C, bool Destruct_on_free_ = false, typename BaseAllocator = Allocator> class ClassAllocator : public BaseAllocator
{
public:
  using Value_type                   = C;
  static bool const Destruct_on_free = Destruct_on_free_;

  /** Allocates objects of the templated type.  Arguments are forwarded to the constructor for the object. */
  template <typename... Args>
  C *
  alloc(Args &&...args)
  {
    void *ptr = this->alloc_void();

    ::new (ptr) C(std::forward<Args>(args)...);
    return reinterpret_cast<C *>(ptr);
  }

  /**
    Deallocates objects of the templated type.

    @param ptr pointer to be freed.
  */
  void
  free(C *ptr)
  {
    destroy_if_enabled(ptr);

    this->free_void(ptr);
  }

  /**
    Create a new class specific ClassAllocator.

    @param name some identifying name, used for mem tracking purposes.
    @param chunk_size number of units to be allocated if free pool is empty.
    @param alignment of objects must be a power of 2.
  */
  ClassAllocator(const char *name, unsigned int chunk_size = 128, unsigned int alignment = 16)
    : BaseAllocator(name, static_cast<unsigned int>(RND16(sizeof(C))), chunk_size, static_cast<unsigned int>(RND16(alignment)))
  {
  }

  BaseAllocator &
  raw()
  {
    return *this;
  }

  void
  destroy_if_enabled(C *ptr)
  {
    if (Destruct_on_free) {
      ptr->~C();
    }
  }

  // Ensure that C is big enough to hold a void pointer (when it's stored in the free list as raw memory).
  //
  static_assert(sizeof(C) >= sizeof(void *), "Can not allocate instances of this class using ClassAllocator");
};

template <class C, bool Destruct_on_free = false> class TrackerClassAllocator : public ClassAllocator<C, Destruct_on_free>
{
public:
  TrackerClassAllocator(const char *name, unsigned int chunk_size = 128, unsigned int alignment = 16)
    : ClassAllocator<C, Destruct_on_free>(name, chunk_size, alignment), allocations(0), trackerLock(PTHREAD_MUTEX_INITIALIZER)
  {
  }

  C *
  alloc()
  {
    void *callstack[3];
    int   frames = backtrace(callstack, 3);
    C    *ptr    = ClassAllocator<C, Destruct_on_free>::alloc();

    const void *symbol = nullptr;
    if (frames == 3 && callstack[2] != nullptr) {
      symbol = callstack[2];
    }

    tracker.increment(symbol, (int64_t)sizeof(C), this->fl->name);
    ink_mutex_acquire(&trackerLock);
    reverse_lookup[ptr] = symbol;
    ++allocations;
    ink_mutex_release(&trackerLock);

    return ptr;
  }

  void
  free(C *ptr)
  {
    ink_mutex_acquire(&trackerLock);
    std::map<void *, const void *>::iterator it = reverse_lookup.find(ptr);
    if (it != reverse_lookup.end()) {
      tracker.increment(static_cast<const void *>(it->second), (int64_t)sizeof(C) * -1, nullptr);
      reverse_lookup.erase(it);
    }
    ink_mutex_release(&trackerLock);
    ClassAllocator<C, Destruct_on_free>::free(ptr);
  }

private:
  ResourceTracker                tracker;
  std::map<void *, const void *> reverse_lookup;
  uint64_t                       allocations;
  ink_mutex                      trackerLock;
};
