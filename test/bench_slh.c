/*
 * Copyright (c) 2024 The slhdsa-c project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

#if defined(__linux__)
#if !defined(_GNU_SOURCE)
/* Ensure that syscall() is declared even when compiling with -std=c99 */
#define _GNU_SOURCE
#endif
#endif /* __linux__ */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../plat_local.h"
#include "../slh_dsa.h"

#ifdef SLH_EXPERIMENTAL
extern uint64_t keccak_f1600_cycles;
extern uint64_t keccak_f1600_count;
#endif

/* --- Cycle counter (slh_get_cycles) --- */

#ifdef PERF_CYCLES
/* slh_perf_fd is declared in plat_local.h */

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

  slh_perf_fd = perf_event_open(&pe, 0, -1, -1, 0);
  if (slh_perf_fd == -1) {
    perror("perf_event_open");
    exit(EXIT_FAILURE);
  }
  ioctl(slh_perf_fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(slh_perf_fd, PERF_EVENT_IOC_ENABLE, 0);
}

static void __attribute__((destructor)) fini_perf(void) {
  if (slh_perf_fd != -1) {
    close(slh_perf_fd);
  }
}

/* slh_get_cycles() is in plat_local.h */

#else  /* !PERF_CYCLES */
/* slh_get_cycles() is in plat_local.h */
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
#ifdef SLH_EXPERIMENTAL
  uint64_t k[NITER];
#endif
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
#ifdef SLH_EXPERIMENTAL
    // keccak_f1600_cycles = 0;
    keccak_f1600_count = 0;
#endif
    t0 = slh_get_cycles();
    slh_keygen(sk, pk, rbg, prm);
    t1 = slh_get_cycles();
    t[i] = t1 - t0;
#ifdef SLH_EXPERIMENTAL
    // k[i] = keccak_f1600_cycles;
    k[i] = keccak_f1600_count;
#endif
  }
#ifdef SLH_EXPERIMENTAL
  printf("  KeyGen: %llu cycles (%llu or %.0f%% Keccak)\n",
         (unsigned long long)median(t, NITER),
         (unsigned long long)median(k, NITER),
         100.0 * (double)median(k, NITER) / (double)median(t, NITER));
#else
  printf("  KeyGen: %llu cycles\n", (unsigned long long)median(t, NITER));
#endif

  /* --- Signature Gen --- */
  /* Warmup */
  for (i = 0; i < NWARMUP; i++) {
    slh_sign(sig, m, m_sz, NULL, 0, sk, NULL, prm);
  }
  /* Measure */
  for (i = 0; i < NITER; i++) {
#ifdef SLH_EXPERIMENTAL
    // keccak_f1600_cycles = 0;
    keccak_f1600_count = 0;
#endif
    t0 = slh_get_cycles();
    slh_sign(sig, m, m_sz, NULL, 0, sk, NULL, prm);
    t1 = slh_get_cycles();
    t[i] = t1 - t0;
#ifdef SLH_EXPERIMENTAL
    // k[i] = keccak_f1600_cycles;
    k[i] = keccak_f1600_count;
#endif
  }
#ifdef SLH_EXPERIMENTAL
  printf("  Sign:   %llu cycles (%llu or %.0f%% Keccak)\n",
         (unsigned long long)median(t, NITER),
         (unsigned long long)median(k, NITER),
         100.0 * (double)median(k, NITER) / (double)median(t, NITER));
#else
  printf("  Sign:   %llu cycles\n", (unsigned long long)median(t, NITER));
#endif

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
    /* Measure */
    for (i = 0; i < NITER; i++) {
#ifdef SLH_EXPERIMENTAL
      // keccak_f1600_cycles = 0;
      keccak_f1600_count = 0;
#endif
      t0 = slh_get_cycles();
      if (!slh_verify(m, m_sz, sig, sig_sz, NULL, 0, pk, prm)) {
        printf("Freq fail!\n");
      }
      t1 = slh_get_cycles();
      t[i] = t1 - t0;
#ifdef SLH_EXPERIMENTAL
      // k[i] = keccak_f1600_cycles;
      k[i] = keccak_f1600_count;
#endif
    }
#ifdef SLH_EXPERIMENTAL
    printf("  Verify: %llu cycles (%llu or %.0f%% Keccak)\n",
           (unsigned long long)median(t, NITER),
           (unsigned long long)median(k, NITER),
           100.0 * (double)median(k, NITER) / (double)median(t, NITER));
#else
    printf("  Verify: %llu cycles\n", (unsigned long long)median(t, NITER));
#endif
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
