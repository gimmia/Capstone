// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2019 Western Digital Corporation or its affiliates.
 *
 * Authors:
 *     Atish Patra <atish.patra@wdc.com>
 */

#include <linux/errno.h>
#include <linux/err.h>
#include <linux/kvm_host.h>
#include <asm/sbi.h>
#include <asm/kvm_vcpu_sbi.h>
#include <linux/printk.h>
#include <linux/bitmap.h>

#ifndef CONFIG_RISCV_SBI_V01
static const struct kvm_vcpu_sbi_extension vcpu_sbi_ext_v01 = {
	.extid_start = -1UL,
	.extid_end = -1UL,
	.handler = NULL,
};
#endif

#ifndef CONFIG_RISCV_PMU_SBI
static const struct kvm_vcpu_sbi_extension vcpu_sbi_ext_pmu = {
	.extid_start = -1UL,
	.extid_end = -1UL,
	.handler = NULL,
};
#endif

struct kvm_riscv_sbi_extension_entry {
	enum KVM_RISCV_SBI_EXT_ID ext_idx;
	const struct kvm_vcpu_sbi_extension *ext_ptr;
};

static const struct kvm_riscv_sbi_extension_entry sbi_ext[] = {
	{
		.ext_idx = KVM_RISCV_SBI_EXT_V01,
		.ext_ptr = &vcpu_sbi_ext_v01,
	},
	{
		.ext_idx = KVM_RISCV_SBI_EXT_MAX, /* Can't be disabled */
		.ext_ptr = &vcpu_sbi_ext_base,
	},
	{
		.ext_idx = KVM_RISCV_SBI_EXT_TIME,
		.ext_ptr = &vcpu_sbi_ext_time,
	},
	{
		.ext_idx = KVM_RISCV_SBI_EXT_IPI,
		.ext_ptr = &vcpu_sbi_ext_ipi,
	},
	{
		.ext_idx = KVM_RISCV_SBI_EXT_RFENCE,
		.ext_ptr = &vcpu_sbi_ext_rfence,
	},
	{
		.ext_idx = KVM_RISCV_SBI_EXT_SRST,
		.ext_ptr = &vcpu_sbi_ext_srst,
	},
	{
		.ext_idx = KVM_RISCV_SBI_EXT_HSM,
		.ext_ptr = &vcpu_sbi_ext_hsm,
	},
	{
		.ext_idx = KVM_RISCV_SBI_EXT_PMU,
		.ext_ptr = &vcpu_sbi_ext_pmu,
	},
	{
		.ext_idx = KVM_RISCV_SBI_EXT_DBCN,
		.ext_ptr = &vcpu_sbi_ext_dbcn,
	},
	{
		.ext_idx = KVM_RISCV_SBI_EXT_STA,
		.ext_ptr = &vcpu_sbi_ext_sta,
	},
	{
		.ext_idx = KVM_RISCV_SBI_EXT_EXPERIMENTAL,
		.ext_ptr = &vcpu_sbi_ext_experimental,
	},
	{
		.ext_idx = KVM_RISCV_SBI_EXT_VENDOR,
		.ext_ptr = &vcpu_sbi_ext_vendor,
	},
};

void dump_kvm_vcpu_config (struct kvm_vcpu_config *v_cfg) {
	if (!v_cfg) {
                pr_err("Error: v_cfg is NULL in v_cfg!\n");
                return;
        }
	
	pr_err("------- Dumping kvm_vcpu_config -------\n");

	pr_err("  henvcfg:     0x%lx\n", v_cfg->henvcfg);
	pr_err("  hstateen0:   0x%lx\n", v_cfg->hstateen0);
	pr_err("  hedeleg:     0x%lx\n", v_cfg->hedeleg);

	pr_err("------- End of kvm_vcpu_config -------\n");
}

void dump_kvm_mmu_cache (struct kvm_mmu_memory_cache *mmu_cache) {
	if (!mmu_cache) {
                pr_err("Error: mmu_cache is NULL in mmu_cache!\n");
                return;
        }
	
	pr_err("------- Dumping kvm_mmu_memory_cache -------\n");

	pr_err("  gfp_zero:     	%u\n", mmu_cache->gfp_zero);
	pr_err("  gfp_custom:   	%u\n", mmu_cache->gfp_custom);
	pr_err("  init_value:		0x%lx\n", mmu_cache->init_value);
	pr_err("  kmem_cache address:   %p\n", mmu_cache->kmem_cache);
	pr_err("  capacity:		%d\n", mmu_cache->capacity);
	pr_err("  nobjs:                %d\n", mmu_cache->nobjs);
	pr_err("  objects address:	%p\n", mmu_cache->objects);

	pr_err("------- End of kvm_mmu_memory_cache dump -------\n");
}

void dump_kvm_aia_csr (struct kvm_vcpu_aia_csr *aia_csr) {
	if (!aia_csr) {
		pr_err("Error: aia_csr is NULL in aia_csr!\n");
                return;
        }

        pr_err("------- Dumping kvm_vcpu_aia_csr -------\n");

        pr_err("  vsiselect:   0x%lx\n", aia_csr->vsiselect);
        pr_err("  hviprio1 :   0x%lx\n", aia_csr->hviprio1);
	pr_err("  hviprio2 :   0x%lx\n", aia_csr->hviprio2);
	pr_err("  vsieh    :   0x%lx\n", aia_csr->vsieh);
	pr_err("  hviph    :   0x%lx\n", aia_csr->hviph);
	pr_err("  hviprio1h:   0x%lx\n", aia_csr->hviprio1h);
	pr_err("  hviprio2h:   0x%lx\n", aia_csr->hviprio2h);

        pr_err("------- End of kvm_vcpu_aia_csr dump -------\n");
}

void dump_kvm_aia_ctx (struct kvm_vcpu_aia *aia_ctx) {
	if (!aia_ctx) {
                pr_err("Error: aia_ctx is NULL in dump_kvm_aia_ctx!\n");
                return;
        }

        pr_err("------- Dumping kvm_vcpu_aia -------\n");

	/* CPU AIA CSR context of Guest VCPU */
        pr_err("  guest_aia_csr addr:          %p\n", aia_ctx->guest_csr);
	dump_kvm_aia_csr(aia_ctx->guest_csr);

	/* CPU AIA CSR context upon Guest VCPU reset */
	pr_err("  guest_aia_reset_csr addr:    %p\n", aia_ctx->guest_reset_csr);
        dump_kvm_aia_csr(aia_ctx->guest_reset_csr);

	/* Guest physical address of IMSIC for this VCPU */
	pr_err("  GPA of IMSIC for this VCPU:  0x%lx\n", aia_ctx->imsic_addr);

	/* HART index of IMSIC extacted from guest physical address */
	pr_err("  HART index of IMSIC:         %u\n", aia_ctx->hart_index);

	/* Internal state of IMSIC for this VCPU */
	pr_err("  IMSIC state addr:            %p\n", aia_ctx->imsic_state);

	pr_err("------- End of kvm_vcpu_aia dump -------\n");
}

void dump_kvm_vcpu_smstateen_csr (struct kvm_vcpu_smstateen_csr *kvm_sms) {
	if (!kvm_sms) {
                pr_err("Error: kvm_sms is NULL in dump_kvm_vcpu_smstateen_csr!\n");
                return;
        }
	
	pr_err("------- Dumping kvm_vcpu_smstateen_csr -------\n");

	pr_err("  vsstatus:   0x%lx\n", kvm_sms->sstateen0);

        pr_err("------- End of kvm_vcpu_smstateen_csr dump -------\n");
}

void dump_kvm_vcpu_csr (struct kvm_vcpu_csr *kvm_csr) {
	if (!kvm_csr) {
                pr_err("Error: kvm_csr is NULL in dump_kvm_vcpu_csr!\n");
                return;
        }

        pr_err("------- Dumping kvm_vcpu_csr -------\n");

	pr_err("  vsstatus:   0x%lx\n", vcpu_csr->vsstatus);
	pr_err("  vsie:       0x%lx\n", vcpu_csr->vsie);
	pr_err("  vstvec:     0x%lx\n", vcpu_csr->vstvec);
	pr_err("  vsscratch:  0x%lx\n", vcpu_csr->vsscratch);
	pr_err("  vsepc:      0x%lx\n", vcpu_csr->vsepc);
	pr_err("  vscause:    0x%lx\n", vcpu_csr->vscause);
	pr_err("  vstval:     0x%lx\n", vcpu_csr->vstval);
	pr_err("  hvip:       0x%lx\n", vcpu_csr->hvip);
	pr_err("  vsatp:      0x%lx\n", vcpu_csr->vsatp);
	pr_err("  scounteren: 0x%lx\n", vcpu_csr->scounteren);
	pr_err("  senvcfg:    0x%lx\n", vcpu_csr->senvcfg);

	pr_err("------- End of kvm_vcpu_csr dump -------\n");
}

void dump_kvm_cpu_context (struct kvm_cpu_context *kvm_ctx) {
	struct __riscv_v_ext_state *vtr = &(kvm_ctx->vector);

	if (!kvm_ctx) {
		pr_err("Error: kvm_ctx is NULL in dump_kvm_cpu_context!\n");
		return;
	}

	pr_err("------- Dumping kvm_cpu_context -------\n");

	/* GPRs */
	pr_err("  GPRs:\n");
	pr_err("    zero: 0x%lx\n", kvm_ctx->zero); // x0
	pr_err("    ra:   0x%lx\n", kvm_ctx->ra);   // x1
	pr_err("    sp:   0x%lx\n", kvm_ctx->sp);   // x2
	pr_err("    gp:   0x%lx\n", kvm_ctx->gp);   // x3
	pr_err("    tp:   0x%lx\n", kvm_ctx->tp);   // x4
	pr_err("    t0:   0x%lx\n", kvm_ctx->t0);   // x5
	pr_err("    t1:   0x%lx\n", kvm_ctx->t1);   // x6
	pr_err("    t2:   0x%lx\n", kvm_ctx->t2);   // x7

	pr_err("    s0:   0x%lx\n", kvm_ctx->s0);   // x8 (fp)
	pr_err("    s1:   0x%lx\n", kvm_ctx->s1);   // x9

	pr_err("    a0:   0x%lx\n", kvm_ctx->a0);   // x10
	pr_err("    a1:   0x%lx\n", kvm_ctx->a1);   // x11
	pr_err("    a2:   0x%lx\n", kvm_ctx->a2);   // x12
	pr_err("    a3:   0x%lx\n", kvm_ctx->a3);   // x13
	pr_err("    a4:   0x%lx\n", kvm_ctx->a4);   // x14
	pr_err("    a5:   0x%lx\n", kvm_ctx->a5);   // x15
	pr_err("    a6:   0x%lx\n", kvm_ctx->a6);   // x16
	pr_err("    a7:   0x%lx\n", kvm_ctx->a7);   // x17

	pr_err("    s2:   0x%lx\n", kvm_ctx->s2);   // x18
	pr_err("    s3:   0x%lx\n", kvm_ctx->s3);   // x19
	pr_err("    s4:   0x%lx\n", kvm_ctx->s4);   // x20
	pr_err("    s5:   0x%lx\n", kvm_ctx->s5);   // x21
	pr_err("    s6:   0x%lx\n", kvm_ctx->s6);   // x22
	pr_err("    s7:   0x%lx\n", kvm_ctx->s7);   // x23
	pr_err("    s8:   0x%lx\n", kvm_ctx->s8);   // x24
	pr_err("    s9:   0x%lx\n", kvm_ctx->s9);   // x25
	pr_err("    s10:  0x%lx\n", kvm_ctx->s10);  // x26
	pr_err("    s11:  0x%lx\n", kvm_ctx->s11);  // x27

	pr_err("    t3:   0x%lx\n", kvm_ctx->t3);   // x28
	pr_err("    t4:   0x%lx\n", kvm_ctx->t4);   // x29
	pr_err("    t5:   0x%lx\n", kvm_ctx->t5);   // x30
	pr_err("    t6:   0x%lx\n", kvm_ctx->t6);   // x31

	/* CSRs */
	pr_err("  CSRs:\n");
	pr_err("    sepc:    0x%lx\n", kvm_ctx->sepc);
	pr_err("    sstatus: 0x%lx\n", kvm_ctx->sstatus);
	pr_err("    hstatus: 0x%lx\n", kvm_ctx->hstatus);

	/* Vector */
	pr_err("  Vector (address: %p):\n", vtr);
	pr_err("    vstart: 0x%lx\n", vtr->vstart);
	pr_err("    vl:     0x%lx\n", vtr->vl);
	pr_err("    vtype:  0x%lx\n", vtr->vtype);
	pr_err("    vcsr:   0x%lx\n", vtr->vcsr);
	pr_err("    vlenb:  0x%lx\n", vtr->vlenb);
	pr_err("    datap:  %p\n", vtr->datap);

	pr_err("------- End of kvm_cpu_context dump -------\n");
}

int dump_v (struct kvm_vcpu *vcpu) {
	struct kvm_vcpu_arch *arch_ptr = &(vcpu->arch);

	pr_err("------- Dumping kvm_vcpu_arch for vCPU %d -------\n", vcpu->vcpu_id);
	pr_err("  Struct kvm_vcpu_arch %p\n", arch_ptr);

	/* VCPU ran at least once */
	pr_err("  ran_atleast_once: %d\n", arch_ptr->ran_atleast_once);

	/* Last Host CPU on which Guest VCPU exited */
	pr_err("  last_exit_cpu: %d\n", arch_ptr->last_exit_cpu);

	/* ISA feature bits (similar to MISA) */
	pr_err("  isa (RISCV_ISA_EXT_MAX=%d):\n", RISCV_ISA_EXT_MAX);

	/* Vendor, Arch, and Implementation details */
	pr_err("  mvendorid: 0x%lx\n", arch_ptr->mvendorid);
	pr_err("  marchid: 0x%lx\n", arch_ptr->marchid);
	pr_err("  mimpid: 0x%lx\n", arch_ptr->mimpid);

	/* SSCRATCH, STVEC, and SCOUNTEREN of Host */
	pr_err("  host_sscratch: 0x%lx\n", arch_ptr->host_sscratch);
	pr_err("  host_stvec: 0x%lx\n", arch_ptr->host_stvec);
	pr_err("  host_scounteren: 0x%lx\n", arch_ptr->host_scounteren);
	pr_err("  host_senvcfg: 0x%lx\n", arch_ptr->host_senvcfg);
	pr_err("  host_sstateen0: 0x%lx\n", arch_ptr->host_sstateen0);

	/* CPU context of Host */
	pr_err("  host_context address: %p\n", &arch_ptr->host_context);
	dump_kvm_cpu_context(&arch_ptr->host_context);

	/* CPU context of Guest */
	pr_err("  guest_context address: %p\n", &arch_ptr->guest_context);
        dump_kvm_cpu_context(&arch_ptr->guest_context);

	/* CPU CSR context of Guest VCPU */
	pr_err("  guest_csr address: %p\n", &arch_ptr->guest_csr);
	dump_kvm_vcpu_csr(&arch_ptr->guest_csr);

	/* CPU Smstateen CSR context of Guest VCPU */
        pr_err("  smstateen_csr address: %p\n", &arch_ptr->smstateen_csr);
	dump_kvm_vcpu_smstateen_csr(&arch_ptr->smstateen_csr);

	/* CPU context upon Guest VCPU reset */
        pr_err("  guest_reset_context address: %p\n", &arch_ptr->guest_reset_context);
guest_reset_csr        dump_kvm_cpu_context(&arch_ptr->guest_reset_context);

	/* CPU CSR context upon Guest VCPU reset */
        pr_err("  guest_reset_csr address: %p\n", &arch_ptr->guest_reset_csr);

        dump_kvm_vcpu_csr(&arch_ptr->guest_reset_csr);

	/* HFENCE request queue 
        pr_err("  hfence_lock: %p\n", &arch_ptr->hfence_lock);
	pr_err("  hfence_head: 0x%lx\n", &arch_ptr->hfence_head);
	pr_err("  hfence_tail: 0x%lx\n", &arch_ptr->hfence_tail);
	pr_err("  hfence_queue address: %p\n", &arch_ptr->hfence_queue);
	dump_kvm_hfence_queue(&arch_ptr->hfence_queue);
	*/
	
	/* MMIO instruction details */
	pr_err("  kvm_mmio_decode address: %p\n", &arch_ptr->mmio_decode);
	pr_err("  mmio insn (load/store): 0x%lx\n", &arch_ptr->mmio_decode->insn);
        pr_err("  mmio insn_len (4b/2b): %d\n", &arch_ptr->mmio_decode->insn_len);
        pr_err("  mmio len (8,4,2,1): %d\n", &arch_ptr->mmio_decode->len);
	pr_err("  mmio shift: %d\n", &arch_ptr->mmio_decode->shift);
	pr_err("  mmio return_handled: %d\n", &arch_ptr->mmio_decode->return_handled);

	/* CSR instruction details */
	pr_err("  kvm_csr_decode address: %p\n", &arch_ptr->csr_decode);
        pr_err("  csr insn: 0x%lx\n", &arch_ptr->csr_decode->insn);
        pr_err("  csr return_handled: %d\n", &arch_ptr->csr_decode->return_handled);

	/* SBI context */
        pr_err("  kvm_vcpu_sbi_context address: %p\n", &arch_ptr->sbi_context);
	pr_err("  sbi return_handled: %d\n", &arch_ptr->sbi_context->return_handled);

	/* AIA VCPU context */
	pr_err("  kvm_vcpu_aia address: %p\n", &arch_ptr->aia_context);
	dump_kvm_aia_ctx(&arch_ptr->aia_context);

	/* Cache pages needed to program page tables with spinlock held */
	pr_err("  kvm_mmu_memory_cache address: %p\n", &arch_ptr->mmu_page_cache);
	dump_kvm_mmu_cache(&arch_ptr->mmu_page_cache);

	/* 'static' configurations which are set only once */
	pr_err("  kvm_vcpu_config address: %p\n", &arch_ptr->cfg);
	dump_kvm_vcpu_config(&arch_ptr->cfg);

	pr_err("------- End of kvm_vcpu_arch dump -------\n");

	return 0;
}

static const struct kvm_riscv_sbi_extension_entry *
riscv_vcpu_get_sbi_ext(struct kvm_vcpu *vcpu, unsigned long idx)
{
	const struct kvm_riscv_sbi_extension_entry *sext = NULL;

	if (idx >= KVM_RISCV_SBI_EXT_MAX)
		return NULL;

	for (int i = 0; i < ARRAY_SIZE(sbi_ext); i++) {
		if (sbi_ext[i].ext_idx == idx) {
			sext = &sbi_ext[i];
			break;
		}
	}

	return sext;
}

bool riscv_vcpu_supports_sbi_ext(struct kvm_vcpu *vcpu, int idx)
{
	struct kvm_vcpu_sbi_context *scontext = &vcpu->arch.sbi_context;
	const struct kvm_riscv_sbi_extension_entry *sext;

	sext = riscv_vcpu_get_sbi_ext(vcpu, idx);

	return sext && scontext->ext_status[sext->ext_idx] != KVM_RISCV_SBI_EXT_STATUS_UNAVAILABLE;
}

void kvm_riscv_vcpu_sbi_forward(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	struct kvm_cpu_context *cp = &vcpu->arch.guest_context;

	vcpu->arch.sbi_context.return_handled = 0;
	vcpu->stat.ecall_exit_stat++;
	run->exit_reason = KVM_EXIT_RISCV_SBI;
	run->riscv_sbi.extension_id = cp->a7;
	run->riscv_sbi.function_id = cp->a6;
	run->riscv_sbi.args[0] = cp->a0;
	run->riscv_sbi.args[1] = cp->a1;
	run->riscv_sbi.args[2] = cp->a2;
	run->riscv_sbi.args[3] = cp->a3;
	run->riscv_sbi.args[4] = cp->a4;
	run->riscv_sbi.args[5] = cp->a5;
	run->riscv_sbi.ret[0] = cp->a0;
	run->riscv_sbi.ret[1] = cp->a1;
}

void kvm_riscv_vcpu_sbi_system_reset(struct kvm_vcpu *vcpu,
				     struct kvm_run *run,
				     u32 type, u64 reason)
{
	unsigned long i;
	struct kvm_vcpu *tmp;

	kvm_for_each_vcpu(i, tmp, vcpu->kvm) {
		spin_lock(&vcpu->arch.mp_state_lock);
		WRITE_ONCE(tmp->arch.mp_state.mp_state, KVM_MP_STATE_STOPPED);
		spin_unlock(&vcpu->arch.mp_state_lock);
	}
	kvm_make_all_cpus_request(vcpu->kvm, KVM_REQ_SLEEP);

	memset(&run->system_event, 0, sizeof(run->system_event));
	run->system_event.type = type;
	run->system_event.ndata = 1;
	run->system_event.data[0] = reason;
	run->exit_reason = KVM_EXIT_SYSTEM_EVENT;
}

int kvm_riscv_vcpu_sbi_return(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	struct kvm_cpu_context *cp = &vcpu->arch.guest_context;

	/* Handle SBI return only once */
	if (vcpu->arch.sbi_context.return_handled)
		return 0;
	vcpu->arch.sbi_context.return_handled = 1;

	/* Update return values */
	cp->a0 = run->riscv_sbi.ret[0];
	cp->a1 = run->riscv_sbi.ret[1];

	/* Move to next instruction */
	vcpu->arch.guest_context.sepc += 4;

	return 0;
}

static int riscv_vcpu_set_sbi_ext_single(struct kvm_vcpu *vcpu,
					 unsigned long reg_num,
					 unsigned long reg_val)
{
	struct kvm_vcpu_sbi_context *scontext = &vcpu->arch.sbi_context;
	const struct kvm_riscv_sbi_extension_entry *sext;

	if (reg_val != 1 && reg_val != 0)
		return -EINVAL;

	sext = riscv_vcpu_get_sbi_ext(vcpu, reg_num);
	if (!sext || scontext->ext_status[sext->ext_idx] == KVM_RISCV_SBI_EXT_STATUS_UNAVAILABLE)
		return -ENOENT;

	scontext->ext_status[sext->ext_idx] = (reg_val) ?
			KVM_RISCV_SBI_EXT_STATUS_ENABLED :
			KVM_RISCV_SBI_EXT_STATUS_DISABLED;

	return 0;
}

static int riscv_vcpu_get_sbi_ext_single(struct kvm_vcpu *vcpu,
					 unsigned long reg_num,
					 unsigned long *reg_val)
{
	struct kvm_vcpu_sbi_context *scontext = &vcpu->arch.sbi_context;
	const struct kvm_riscv_sbi_extension_entry *sext;

	sext = riscv_vcpu_get_sbi_ext(vcpu, reg_num);
	if (!sext || scontext->ext_status[sext->ext_idx] == KVM_RISCV_SBI_EXT_STATUS_UNAVAILABLE)
		return -ENOENT;

	*reg_val = scontext->ext_status[sext->ext_idx] ==
				KVM_RISCV_SBI_EXT_STATUS_ENABLED;

	return 0;
}

static int riscv_vcpu_set_sbi_ext_multi(struct kvm_vcpu *vcpu,
					unsigned long reg_num,
					unsigned long reg_val, bool enable)
{
	unsigned long i, ext_id;

	if (reg_num > KVM_REG_RISCV_SBI_MULTI_REG_LAST)
		return -ENOENT;

	for_each_set_bit(i, &reg_val, BITS_PER_LONG) {
		ext_id = i + reg_num * BITS_PER_LONG;
		if (ext_id >= KVM_RISCV_SBI_EXT_MAX)
			break;

		riscv_vcpu_set_sbi_ext_single(vcpu, ext_id, enable);
	}

	return 0;
}

static int riscv_vcpu_get_sbi_ext_multi(struct kvm_vcpu *vcpu,
					unsigned long reg_num,
					unsigned long *reg_val)
{
	unsigned long i, ext_id, ext_val;

	if (reg_num > KVM_REG_RISCV_SBI_MULTI_REG_LAST)
		return -ENOENT;

	for (i = 0; i < BITS_PER_LONG; i++) {
		ext_id = i + reg_num * BITS_PER_LONG;
		if (ext_id >= KVM_RISCV_SBI_EXT_MAX)
			break;

		ext_val = 0;
		riscv_vcpu_get_sbi_ext_single(vcpu, ext_id, &ext_val);
		if (ext_val)
			*reg_val |= KVM_REG_RISCV_SBI_MULTI_MASK(ext_id);
	}

	return 0;
}

int kvm_riscv_vcpu_set_reg_sbi_ext(struct kvm_vcpu *vcpu,
				   const struct kvm_one_reg *reg)
{
	unsigned long __user *uaddr =
			(unsigned long __user *)(unsigned long)reg->addr;
	unsigned long reg_num = reg->id & ~(KVM_REG_ARCH_MASK |
					    KVM_REG_SIZE_MASK |
					    KVM_REG_RISCV_SBI_EXT);
	unsigned long reg_val, reg_subtype;

	if (KVM_REG_SIZE(reg->id) != sizeof(unsigned long))
		return -EINVAL;

	if (vcpu->arch.ran_atleast_once)
		return -EBUSY;

	reg_subtype = reg_num & KVM_REG_RISCV_SUBTYPE_MASK;
	reg_num &= ~KVM_REG_RISCV_SUBTYPE_MASK;

	if (copy_from_user(&reg_val, uaddr, KVM_REG_SIZE(reg->id)))
		return -EFAULT;

	switch (reg_subtype) {
	case KVM_REG_RISCV_SBI_SINGLE:
		return riscv_vcpu_set_sbi_ext_single(vcpu, reg_num, reg_val);
	case KVM_REG_RISCV_SBI_MULTI_EN:
		return riscv_vcpu_set_sbi_ext_multi(vcpu, reg_num, reg_val, true);
	case KVM_REG_RISCV_SBI_MULTI_DIS:
		return riscv_vcpu_set_sbi_ext_multi(vcpu, reg_num, reg_val, false);
	default:
		return -ENOENT;
	}

	return 0;
}

int kvm_riscv_vcpu_get_reg_sbi_ext(struct kvm_vcpu *vcpu,
				   const struct kvm_one_reg *reg)
{
	int rc;
	unsigned long __user *uaddr =
			(unsigned long __user *)(unsigned long)reg->addr;
	unsigned long reg_num = reg->id & ~(KVM_REG_ARCH_MASK |
					    KVM_REG_SIZE_MASK |
					    KVM_REG_RISCV_SBI_EXT);
	unsigned long reg_val, reg_subtype;

	if (KVM_REG_SIZE(reg->id) != sizeof(unsigned long))
		return -EINVAL;

	reg_subtype = reg_num & KVM_REG_RISCV_SUBTYPE_MASK;
	reg_num &= ~KVM_REG_RISCV_SUBTYPE_MASK;

	reg_val = 0;
	switch (reg_subtype) {
	case KVM_REG_RISCV_SBI_SINGLE:
		rc = riscv_vcpu_get_sbi_ext_single(vcpu, reg_num, &reg_val);
		break;
	case KVM_REG_RISCV_SBI_MULTI_EN:
	case KVM_REG_RISCV_SBI_MULTI_DIS:
		rc = riscv_vcpu_get_sbi_ext_multi(vcpu, reg_num, &reg_val);
		if (!rc && reg_subtype == KVM_REG_RISCV_SBI_MULTI_DIS)
			reg_val = ~reg_val;
		break;
	default:
		rc = -ENOENT;
	}
	if (rc)
		return rc;

	if (copy_to_user(uaddr, &reg_val, KVM_REG_SIZE(reg->id)))
		return -EFAULT;

	return 0;
}

int kvm_riscv_vcpu_set_reg_sbi(struct kvm_vcpu *vcpu,
			       const struct kvm_one_reg *reg)
{
	unsigned long __user *uaddr =
			(unsigned long __user *)(unsigned long)reg->addr;
	unsigned long reg_num = reg->id & ~(KVM_REG_ARCH_MASK |
					    KVM_REG_SIZE_MASK |
					    KVM_REG_RISCV_SBI_STATE);
	unsigned long reg_subtype, reg_val;

	if (KVM_REG_SIZE(reg->id) != sizeof(unsigned long))
		return -EINVAL;

	if (copy_from_user(&reg_val, uaddr, KVM_REG_SIZE(reg->id)))
		return -EFAULT;

	reg_subtype = reg_num & KVM_REG_RISCV_SUBTYPE_MASK;
	reg_num &= ~KVM_REG_RISCV_SUBTYPE_MASK;

	switch (reg_subtype) {
	case KVM_REG_RISCV_SBI_STA:
		return kvm_riscv_vcpu_set_reg_sbi_sta(vcpu, reg_num, reg_val);
	default:
		return -EINVAL;
	}

	return 0;
}

int kvm_riscv_vcpu_get_reg_sbi(struct kvm_vcpu *vcpu,
			       const struct kvm_one_reg *reg)
{
	unsigned long __user *uaddr =
			(unsigned long __user *)(unsigned long)reg->addr;
	unsigned long reg_num = reg->id & ~(KVM_REG_ARCH_MASK |
					    KVM_REG_SIZE_MASK |
					    KVM_REG_RISCV_SBI_STATE);
	unsigned long reg_subtype, reg_val;
	int ret;

	if (KVM_REG_SIZE(reg->id) != sizeof(unsigned long))
		return -EINVAL;

	reg_subtype = reg_num & KVM_REG_RISCV_SUBTYPE_MASK;
	reg_num &= ~KVM_REG_RISCV_SUBTYPE_MASK;

	switch (reg_subtype) {
	case KVM_REG_RISCV_SBI_STA:
		ret = kvm_riscv_vcpu_get_reg_sbi_sta(vcpu, reg_num, &reg_val);
		break;
	default:
		return -EINVAL;
	}

	if (ret)
		return ret;

	if (copy_to_user(uaddr, &reg_val, KVM_REG_SIZE(reg->id)))
		return -EFAULT;

	return 0;
}

const struct kvm_vcpu_sbi_extension *kvm_vcpu_sbi_find_ext(
				struct kvm_vcpu *vcpu, unsigned long extid)
{
	struct kvm_vcpu_sbi_context *scontext = &vcpu->arch.sbi_context;
	const struct kvm_riscv_sbi_extension_entry *entry;
	const struct kvm_vcpu_sbi_extension *ext;
	int i;

	for (i = 0; i < ARRAY_SIZE(sbi_ext); i++) {
		entry = &sbi_ext[i];
		ext = entry->ext_ptr;

		if (ext->extid_start <= extid && ext->extid_end >= extid) {
			if (entry->ext_idx >= KVM_RISCV_SBI_EXT_MAX ||
			    scontext->ext_status[entry->ext_idx] ==
						KVM_RISCV_SBI_EXT_STATUS_ENABLED)
				return ext;

			return NULL;
		}
	}

	return NULL;
}

int kvm_riscv_vcpu_sbi_ecall(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	int ret = 1;
	bool next_sepc = true;
	struct kvm_cpu_context *cp = &vcpu->arch.guest_context;
	const struct kvm_vcpu_sbi_extension *sbi_ext;
	struct kvm_cpu_trap utrap = {0};
	struct kvm_vcpu_sbi_return sbi_ret = {
		.out_val = 0,
		.err_val = 0,
		.utrap = &utrap,
	};
	bool ext_is_v01 = false;

	if (cp->a7 != 0xdeadbeef) {
		sbi_ext = kvm_vcpu_sbi_find_ext(vcpu, cp->a7);
		if (sbi_ext && sbi_ext->handler) {
#ifdef CONFIG_RISCV_SBI_V01
			if (cp->a7 >= SBI_EXT_0_1_SET_TIMER &&
			    cp->a7 <= SBI_EXT_0_1_SHUTDOWN)
				ext_is_v01 = true;
#endif
			ret = sbi_ext->handler(vcpu, run, &sbi_ret);
		} else {
			/* Return error for unsupported SBI calls */
			cp->a0 = SBI_ERR_NOT_SUPPORTED;
			goto ecall_done;
		}
	} else {
		ret = dump_v(vcpu);
	}

	/*
	 * When the SBI extension returns a Linux error code, it exits the ioctl
	 * loop and forwards the error to userspace.
	 */
	if (ret < 0) {
		next_sepc = false;
		goto ecall_done;
	}

	/* Handle special error cases i.e trap, exit or userspace forward */
	if (sbi_ret.utrap->scause) {
		/* No need to increment sepc or exit ioctl loop */
		ret = 1;
		sbi_ret.utrap->sepc = cp->sepc;
		kvm_riscv_vcpu_trap_redirect(vcpu, sbi_ret.utrap);
		next_sepc = false;
		goto ecall_done;
	}

	/* Exit ioctl loop or Propagate the error code the guest */
	if (sbi_ret.uexit) {
		next_sepc = false;
		ret = 0;
	} else {
		cp->a0 = sbi_ret.err_val;
		ret = 1;
	}
ecall_done:
	if (next_sepc)
		cp->sepc += 4;
	/* a1 should only be updated when we continue the ioctl loop */
	if (!ext_is_v01 && ret == 1)
		cp->a1 = sbi_ret.out_val;

	return ret;
}

void kvm_riscv_vcpu_sbi_init(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_sbi_context *scontext = &vcpu->arch.sbi_context;
	const struct kvm_riscv_sbi_extension_entry *entry;
	const struct kvm_vcpu_sbi_extension *ext;
	int i;

	for (i = 0; i < ARRAY_SIZE(sbi_ext); i++) {
		entry = &sbi_ext[i];
		ext = entry->ext_ptr;

		if (ext->probe && !ext->probe(vcpu)) {
			scontext->ext_status[entry->ext_idx] =
				KVM_RISCV_SBI_EXT_STATUS_UNAVAILABLE;
			continue;
		}

		scontext->ext_status[entry->ext_idx] = ext->default_disabled ?
					KVM_RISCV_SBI_EXT_STATUS_DISABLED :
					KVM_RISCV_SBI_EXT_STATUS_ENABLED;
	}
}
