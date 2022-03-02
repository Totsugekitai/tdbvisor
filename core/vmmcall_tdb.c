#include "../include/core/mmio.h"
#include "config.h"
#include "constants.h"
#include "current.h"
#include "debug.h"
#include "gmm_access.h"
#include "initfunc.h"
#include "panic.h"
#include "printf.h"
#include "process.h"
#include "spinlock.h"
#include "thread.h"
#include "vmmcall.h"

#define IS_MMIO_READ 0

static unsigned char hozon;

typedef struct pml4_entry {
  unsigned char present : 1;
  unsigned char rw : 1;
  unsigned char us : 1;
  unsigned char pwt : 1;
  unsigned char pcd : 1;
  unsigned char a : 1;
  unsigned char ign0 : 1;
  unsigned char rsvd0 : 1;
  unsigned char ign1 : 4;
  unsigned long long addr_pdpt : 36;
  unsigned int rsvd1 : 16;
} pml4_entry_t;

typedef struct pdpt_entry {
  unsigned char present : 1;
  unsigned char rw : 1;
  unsigned char us : 1;
  unsigned char pwt : 1;
  unsigned char pcd : 1;
  unsigned char a : 1;
  union {
    struct {
      unsigned char d : 1;
      unsigned char is_page : 1;
      unsigned char g : 1;
      unsigned char ign0 : 3;
      unsigned char pat : 1;
      unsigned int rsvd0 : 17;
      unsigned int addr_page_frame : 18;
    } page_1gb;
    struct {
      unsigned char ign0 : 1;
      unsigned char is_page : 1;
      unsigned char ign1 : 4;
      unsigned long long addr_pd : 36;
    } page_directory;
  } internal;
  unsigned int rsvd1 : 16;
} pdpt_entry_t;

typedef struct pd_entry {
  unsigned char present : 1;
  unsigned char rw : 1;
  unsigned char us : 1;
  unsigned char pwt : 1;
  unsigned char pcd : 1;
  unsigned char a : 1;
  union {
    struct {
      unsigned char d : 1;
      unsigned char is_page : 1;
      unsigned char g : 1;
      unsigned char ign0 : 3;
      unsigned char pat : 1;
      unsigned int rsvd0 : 8;
      unsigned int addr_page_frame : 27;
    } page_2mb;
    struct {
      unsigned char ign0 : 1;
      unsigned char is_page : 1;
      unsigned char ign1 : 4;
      unsigned long long addr_pt : 36;
    } page_table;
  } internal;
  unsigned int rsvd1 : 16;
} pd_entry_t;

typedef struct pt_entry {
  unsigned char present : 1;
  unsigned char rw : 1;
  unsigned char us : 1;
  unsigned char pwt : 1;
  unsigned char pcd : 1;
  unsigned char a : 1;
  unsigned char d : 1;
  unsigned char pat : 1;
  unsigned char g : 1;
  unsigned char ign0 : 3;
  unsigned long long addr_page_frame : 36;
  unsigned int rsvd1 : 16;
} pt_entry_t;

static phys_t virt_to_phys(ulong virt, ulong guest_cr3) {
  printf("virt addr: %lx\n", virt);
  // PML4 table
  ulong pml4 = virt >> 39;
  pml4_entry_t *pml4_entry_addr = ((pml4_entry_t *)guest_cr3) + pml4;

  pml4_entry_t pml4_entry;
  read_gphys_q((u64)pml4_entry_addr, (void *)&pml4_entry, 0);

  if (!pml4_entry.present) {
    return 0xffffffffffffffffull;
  }

  // PDP table
  ulong directory_ptr = (virt & 0x007fc0000000) >> 30;
  pdpt_entry_t *pdpt_entry_addr =
      ((pdpt_entry_t *)(((ulong)pml4_entry.addr_pdpt) << 12)) + directory_ptr;

  pdpt_entry_t pdpt_entry;
  read_gphys_q((u64)pdpt_entry_addr, (void *)&pdpt_entry, 0);

  if (!pdpt_entry.present) {
    return 0xfffffffffffffffeull;
  }
  if (pdpt_entry.internal.page_1gb.is_page) {
    return (((ulong)pdpt_entry.internal.page_1gb.addr_page_frame) << 30) +
           (virt & 0x3fffffff);
  }

  // PD table
  ulong directory = (virt & 0x00003fe00000) >> 21;
  pd_entry_t *pd_entry_addr =
      (pd_entry_t *)(((ulong)pdpt_entry.internal.page_directory.addr_pd)
                     << 12) +
      directory;

  pd_entry_t pd_entry;
  read_gphys_q((u64)pd_entry_addr, (void *)&pd_entry, 0);

  if (!pd_entry.present) {
    return 0xfffffffffffffffdull;
  }
  if (pd_entry.internal.page_2mb.is_page) {
    return (((ulong)pd_entry.internal.page_2mb.addr_page_frame) << 21) +
           (virt & 0x000fffff);
  }

  // Page table
  ulong table = (virt & 0x0000001ff000) >> 12;
  pt_entry_t *pt_entry_addr =
      (pt_entry_t *)(((ulong)pd_entry.internal.page_table.addr_pt) << 12) +
      table;

  pt_entry_t pt_entry;
  read_gphys_q((u64)pt_entry_addr, (void *)&pt_entry, 0);

  if (!pt_entry.present) {
    return 0xfffffffffffffffcull;
  }
  return (((ulong)pt_entry.addr_page_frame) << 12) + (virt & 0x0fff);
}

// return value: 0     = emulate MMIO by bitvisor
//               not 0 = don't emulate
static int tdb_mm_handler(void *data, phys_t gphys, bool wr, void *buf,
                          uint len, u32 flags) {
  ulong rip, cr3;
  current->vmctl.read_ip(&rip);
  current->vmctl.read_control_reg(CONTROL_REG_CR3, &cr3);

  phys_t gphys_rip = virt_to_phys(rip, cr3);
  printf("guest phys rip: %llx\n", gphys_rip);

  if (gphys_rip > 0xfffffffffffffffb) return 1;

  if (wr == IS_MMIO_READ) {
    // TODO
  } else {
    // TODO
  }
  read_gphys_b(gphys_rip, &hozon, 0);  // hozonに保存
  write_gphys_b(gphys_rip, 0xcc, 0);   // int3 を埋め込む
  rip--;
  current->vmctl.write_ip(rip);
  return 1;
}

static void register_mm_handler(phys_t gphys, uint len) {
  printf("[TDB] register_mm_handler: gphys = %llx, len = %x\n", gphys, len);
  mmio_register(gphys, len, tdb_mm_handler, NULL);
}

static void tdb(void) {
  ulong rbx, rcx;
  ulong ret = 0xdeadbeef;

  current->vmctl.read_general_reg(GENERAL_REG_RBX, &rbx);
  current->vmctl.read_general_reg(GENERAL_REG_RCX, &rcx);

  phys_t gphys_addr = rbx;
  ulong len = rcx;

  // register_mm_handler(gphys_addr, (uint)len);
  register_mm_handler(0xfed00000, (uint)len);

  current->vmctl.write_general_reg(GENERAL_REG_RDX, (ulong)ret);
}

static void vmmcall_tdb_init(void) { vmmcall_register("tdb", tdb); }

INITFUNC("vmmcal0", vmmcall_tdb_init);