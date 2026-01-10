/*
 * Copyright (c) 2024 The slhdsa-c project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../slh_dsa.h"

/* --- Cycle counter (cpucycles) --- */

#ifdef PERF_CYCLES
#include <linux/perf_event.h>
#include <sys/ioctl.h> /* for ioctl in clean shutdown if desired, though not strictly needed for just reading */
#include <sys/syscall.h>
#include <unistd.h>

static int fd_perf = -1;

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                            int cpu, int group_fd, unsigned long flags) {
  return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

static void __attribute__((constructor)) init_perf(void) {
  struct perf_event_attr pe;

  memset(&pe, 0, sizeof(struct perf_event_attr));
  pe.type = PERF_TYPE_HARDWARE;
  pe.size = sizeof(struct perf_event_attr);
  pe.config = PERF_COUNT_HW_CPU_CYCLES;
  pe.disabled = 1;
  pe.exclude_kernel = 1;
  pe.exclude_hv = 1;

  fd_perf = perf_event_open(&pe, 0, -1, -1, 0);
  if (fd_perf == -1) {
    perror("perf_event_open");
    exit(EXIT_FAILURE);
  }
  ioctl(fd_perf, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd_perf, PERF_EVENT_IOC_ENABLE, 0);
}

static void __attribute__((destructor)) fini_perf(void) {
  if (fd_perf != -1) {
    close(fd_perf);
  }
}

static inline uint64_t cpucycles(void) {
  uint64_t count;
  if (read(fd_perf, &count, sizeof(uint64_t)) == -1) {
    return 0;
  }
  return count;
}

#else /* !PERF_CYCLES */

#if defined(__x86_64__)
#include <x86intrin.h>
static inline uint64_t cpucycles(void) { return __rdtsc(); }
#elif defined(__aarch64__)
static inline uint64_t cpucycles(void) {
  uint64_t t;
  __asm__ volatile("mrs %0, cntvct_el0" : "=r"(t));
  return t;
}
#elif defined(__riscv)
static inline uint64_t cpucycles(void) {
#if __riscv_xlen == 32
  uint32_t hi, lo, hi2;
  do {
    __asm__ volatile("csrr %0, cycleh" : "=r"(hi));
    __asm__ volatile("csrr %0, cycle" : "=r"(lo));
    __asm__ volatile("csrr %0, cycleh" : "=r"(hi2));
  } while (hi != hi2);
  return ((uint64_t)hi << 32) | lo;
#else
  uint64_t cycle;
  __asm__ volatile("csrr %0, cycle" : "=r"(cycle));
  return cycle;
#endif
}
#else
static inline uint64_t cpucycles(void) {
#if defined(__GNUC__) || defined(__clang__)
  return (uint64_t)clock();
#else
  return 0;
#endif
}
#endif

#endif /* PERF_CYCLES */

/* --- Benchmark Parameters --- */

#define NWARMUP 1
#define NITER 5

static int cmp_u64(const void *a, const void *b) {
  if (*(const uint64_t *)a < *(const uint64_t *)b)
    return -1;
  if (*(const uint64_t *)a > *(const uint64_t *)b)
    return 1;
  return 0;
}

static uint64_t median(uint64_t *l, size_t llen) {
  qsort(l, llen, sizeof(uint64_t), cmp_u64);
  if (llen % 2)
    return l[llen / 2];
  return (l[llen / 2 - 1] + l[llen / 2]) / 2;
}

/* --- Random byte generator --- */

static int rbg(uint8_t *x, size_t xlen) {
  size_t i;
  for (i = 0; i < xlen; i++) {
    x[i] = (uint8_t)rand();
  }
  return 0;
}

/* --- Benchmark Driver --- */

static void bench_param(const slh_param_t *prm) {
  uint8_t *sk, *pk, *m, *sig;
  size_t sk_sz, pk_sz, sig_sz, m_sz = 32;
  uint64_t t[NITER];
  uint64_t t0, t1;
  size_t i;

  printf("Benchmarking %s:\n", slh_alg_id(prm));

  sk_sz = slh_sk_sz(prm);
  pk_sz = slh_pk_sz(prm);
  sig_sz = slh_sig_sz(prm);

  sk = malloc(sk_sz);
  pk = malloc(pk_sz);
  sig = malloc(sig_sz);
  m = malloc(m_sz);

  rbg(m, m_sz);

  /* --- KeyGen --- */
  /* Warmup */
  for (i = 0; i < NWARMUP; i++) {
    slh_keygen(sk, pk, rbg, prm);
  }
  /* Measure */
  for (i = 0; i < NITER; i++) {
    t0 = cpucycles();
    slh_keygen(sk, pk, rbg, prm);
    t1 = cpucycles();
    t[i] = t1 - t0;
  }
  printf("  KeyGen: %llu cycles\n", (unsigned long long)median(t, NITER));

  /* --- Signature Gen --- */
  /* Warmup */
  for (i = 0; i < NWARMUP; i++) {
    slh_sign(sig, m, m_sz, NULL, 0, sk, NULL, prm);
  }
  /* Measure */
  for (i = 0; i < NITER; i++) {
    t0 = cpucycles();
    slh_sign(sig, m, m_sz, NULL, 0, sk, NULL, prm);
    t1 = cpucycles();
    t[i] = t1 - t0;
  }
  printf("  Sign:   %llu cycles\n", (unsigned long long)median(t, NITER));

  /* --- Verification --- */
  /* Check correctness first */
  if (!slh_verify(m, m_sz, sig, sig_sz, NULL, 0, pk, prm)) {
    printf("  Verify: FAILED\n");
  } else {
    /* Warmup */
    for (i = 0; i < NWARMUP; i++) {
      slh_verify(m, m_sz, sig, sig_sz, NULL, 0, pk, prm);
    }
    /* Measure */
    for (i = 0; i < NITER; i++) {
      t0 = cpucycles();
      if (!slh_verify(m, m_sz, sig, sig_sz, NULL, 0, pk, prm)) {
        printf("Freq fail!\n");
      }
      t1 = cpucycles();
      t[i] = t1 - t0;
    }
    printf("  Verify: %llu cycles\n", (unsigned long long)median(t, NITER));
  }

  printf("\n");

  free(sk);
  free(pk);
  free(sig);
  free(m);
}

int main(void) {
  const slh_param_t *params[] = {&slh_dsa_sha2_128s,
                                 &slh_dsa_shake_128s,
                                 &slh_dsa_sha2_128f,
                                 &slh_dsa_shake_128f,
                                 &slh_dsa_sha2_192s,
                                 &slh_dsa_shake_192s,
                                 &slh_dsa_sha2_192f,
                                 &slh_dsa_shake_192f,
                                 &slh_dsa_sha2_256s,
                                 &slh_dsa_shake_256s,
                                 &slh_dsa_sha2_256f,
                                 &slh_dsa_shake_256f,
                                 NULL};
  int i;

  for (i = 0; params[i] != NULL; i++) {
    bench_param(params[i]);
  }

  return 0;
}
