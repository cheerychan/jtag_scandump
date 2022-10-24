/*
*	Copyright (C) 2016 Coming Zhu										  *
*	comingzhu@zhaoxin.com	
*	This project is about Z-Scaler debugger which contains the ARM debug logic:
*	ARM Debug Interface Architecture Specification ADIv5.0 - ADIv5.2
*/


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dsp563xx.h"
#include "jtag/interface.h"
#include "breakpoints.h"
//#include "cortex_m.h"
#include "target_request.h"
#include "target_type.h"
#include "arm_disassembler.h"
#include "register.h"
#include "arm_opcodes.h"
#include "arm_semihosting.h"
#include <helper/time_support.h>

#include "armv7a.h"


static int zx_pmp_get_gdb_reg_list(struct target *target,
	struct reg **reg_list[],
	int *reg_list_size,
	enum target_register_class reg_class)
{
	return ERROR_OK;

}


#if 0

static int zx_pmp_init_arch_info(struct target *target,
	struct zx_pmp_common *zx_pmp, struct jtag_tap *tap)
{
	/* prepare JTAG information for the new target */
	zx_pmp->jtag_info.tap = tap;
	zx_pmp->jtag_info.scann_size = 4;
	
	zx_pmp->dap.jtag_info = &zx_pmp->jtag_info;
	zx_pmp->dap.memaccess_tck = 8;
	
	target->arch_info = &zx_pmp->pmp;
#if 0
	int retval = arm_jtag_setup_connection(&zx_pmp->jtag_info);
	if (retval != ERROR_OK)
		return retval;
#endif
	return ERROR_OK;
}


static int zx_pmp_target_create(struct target *target, Jim_Interp *interp)
{
	struct zx_pmp_common *zx_pmp = calloc(1, sizeof(struct zx_pmp_common));
	int retval;
 
	retval = zx_pmp_init_arch_info(target, zx_pmp, target->tap);
	return retval;
}

#endif

#if 0
static int zx_pmp_target_create(struct target *target, Jim_Interp *interp)
{
	struct zx_pmp_common *zx_pmp = calloc(1, sizeof(struct zx_pmp_common));
	int retval;

	if (target->tap == NULL)
		return ERROR_FAIL;

	if (!zx_pmp)
		return ERROR_COMMAND_SYNTAX_ERROR;
	
	/* prepare JTAG information for the new target */
	zx_pmp->jtag_info.tap = target->tap;
	zx_pmp->jtag_info.scann_size = 4;
	target->arch_info = zx_pmp;

	////target_register_timer_callback(cortex_m_handle_target_request, 1, 1, target);

	retval = arm_jtag_setup_connection(&zx_pmp->jtag_info);
	if (retval != ERROR_OK)
		return retval;

	return ERROR_OK;
}
#endif





static int zx_pmp_init_arch_info(struct target *target,
	struct zx_pmp_common *zx_pmp, struct jtag_tap *tap)
{
	/* prepare JTAG information for the new target */
	int retval;
 	if (!zx_pmp)
		return ERROR_COMMAND_SYNTAX_ERROR;
	
	zx_pmp->jtag_info.tap = tap;
	zx_pmp->jtag_info.scann_size = 4;
	
	zx_pmp->dap.jtag_info = &zx_pmp->jtag_info;
	zx_pmp->dap.tar_autoincr_block = (1 << 10);	//new add 2016.10.10
	zx_pmp->dap.memaccess_tck = 80;


	/* register arch-specific functions, 2016. 11. 29 */
	zx_pmp->examine_debug_reason = NULL; //cortex_m_examine_debug_reason;
	zx_pmp->post_debug_entry = NULL;	//cortex_a_post_debug_entry
	zx_pmp->pre_restore_context = NULL;

	target->arch_info = zx_pmp;
	tap->dap = &zx_pmp->dap;	//new add 2016.10.10

		//new add 2016.10.10
	retval = arm_jtag_setup_connection(&zx_pmp->jtag_info);
	if (retval != ERROR_OK)
		return retval;

	return ERROR_OK;
}


static int zx_pmp_target_create(struct target *target, Jim_Interp *interp)
{
	struct zx_pmp_common *zx_pmp = calloc(1, sizeof(struct zx_pmp_common));

	return zx_pmp_init_arch_info(target, zx_pmp, target->tap);
}

#if 0

static int zx_pmp_target_create(struct target *target, Jim_Interp *interp)
{
	struct zx_pmp_common *zx_pmp = calloc(1, sizeof(struct zx_pmp_common));
	int retval;
 	if (!zx_pmp)
		return ERROR_COMMAND_SYNTAX_ERROR;
	
	zx_pmp->jtag_info.tap = target->tap;
	zx_pmp->jtag_info.scann_size = 4;
	
	zx_pmp->dap.jtag_info = &zx_pmp->jtag_info;
	zx_pmp->dap.tar_autoincr_block = (1 << 10);	//new add 2016.10.10
	zx_pmp->dap.memaccess_tck = 80;

	target->arch_info = zx_pmp;
	target->tap.dap = &zx_pmp->dap;	//new add 2016.10.10

		//new add 2016.10.10
	retval = arm_jtag_setup_connection(&zx_pmp->jtag_info);
	if (retval != ERROR_OK)
		return retval;
	
	return ERROR_OK;
}

#endif


static int zx_pmp_init_target(struct command_context *cmd_ctx, struct target *target)
{
	LOG_DEBUG("%s", __func__);

	return ERROR_OK;
}


static int zx_pmp_examine(struct target *target)
{
	LOG_DEBUG("%s", __func__);
	struct zx_pmp_common *zx_pmp = target_to_zx_pmp(target);
	struct pmp_v5_dap *jtagdp = &zx_pmp->dap;
	////struct pmp_common *pmp = &zx_pmp->pmp;
	int retval = ERROR_OK;

	/* We do one extra read to ensure DAP is configured,
	 * we call ahbap_debugport_init(swjdp) instead
	 */
	retval = pmp_ahbap_debugport_init(jtagdp);
	if (retval != ERROR_OK)
		return retval;

	/*Note: The two APs of ZX_pmp are all from AHB_AP,
		     The two AHB_APs' AP_ID is the same !!!!!!   */


	/* Search for the AHB_AP - 3 - it is used for accessing to E3K memory */
	retval = pmp_dap_find_ap(jtagdp, PMP_AP_TYPE_AHB_AP, &zx_pmp->memory_ap);
	LOG_DEBUG("[Coming] memory_ap index: (0x%x)", zx_pmp->memory_ap);
	zx_pmp->memory_ap = 3; //2019.1.21 For E3K mem
	if (retval != ERROR_OK) {
		/* AHB-AP not found - use APB-AP */
		LOG_DEBUG("Could not find AHB_AP - using APB-AP for memory access");
		zx_pmp->memory_ap_available = false;
	} else {
		zx_pmp->memory_ap_available = true;
	}


	/* Search for the AHB_AP - 5 - it is used for accessing to PMP debug registers */
	retval = pmp_dap_find_ap(jtagdp, PMP_AP_TYPE_AHB_AP2, &zx_pmp->debug_ap);
	//zx_pmp->debug_ap = 0;
	LOG_DEBUG("[Coming] debug_ap index: (0x%x)", zx_pmp->debug_ap);
	zx_pmp->debug_ap = 5;	//For PMP
	if (retval != ERROR_OK) {
		LOG_ERROR("Could not find JTAG_AP for debug access");
		return retval;
	}


	zx_pmp->debug_base = 0x0;	//coming: debug base


	/* Setup Breakpoint Register Pairs */
	struct pmp_common *pmp = &zx_pmp->pmp;
	pmp->brp_hw_num = 4;			//ZX2100 PMP support 4 HW BRPT
	pmp->brp_sw_num = 2;			//ZX2100 PMP support 2 SW BRPT
	pmp->brp_num_context = 0;	//=0 is a temp value
	pmp->brp_num_available = pmp->brp_hw_num + pmp->brp_sw_num;
	free(zx_pmp->brp_list);
	zx_pmp->brp_list = calloc(pmp->brp_num_available, sizeof(struct zx_pmp_brp));
	for (int i = 0; i < pmp->brp_num_available; i++) {
		zx_pmp->brp_list[i].used = 0;
		if (i < (pmp->brp_num_available - pmp->brp_num_context))
			zx_pmp->brp_list[i].type = BRP_NORMAL;
		else
			zx_pmp->brp_list[i].type = BRP_CONTEXT;
		zx_pmp->brp_list[i].value = 0;
		zx_pmp->brp_list[i].control = 0;
		zx_pmp->brp_list[i].BRPn = i;
	}

	LOG_DEBUG("Configured [%i] HW Breakpoints", pmp->brp_hw_num);
	LOG_DEBUG("Configured [%i] SW Breakpoints", pmp->brp_sw_num);


	if (!target_was_examined(target))
		target_set_examined(target);
	
#ifndef ZX2100_CA17_ENABLE_PMP_CLK
/*
	//Coming: Enable PMP clk 
	retval = pmp_mem_ap_sel_write_atomic_u32(jtagdp, zx_pmp->memory_ap,
				ZX2K_SUS_CLK_EN, PMP_CLK_EN_BIT);	//ap sel with 1
	if (retval != ERROR_OK) return retval;
	LOG_DEBUG("[Coming] PMP CLK Enable");

	retval = pmp_mem_ap_sel_write_atomic_u32(jtagdp, zx_pmp->memory_ap,
				PMP_ROM_EN_REG, PMP_ROM_EN_BIT);	//ap sel with 1
	if (retval != ERROR_OK) return retval;
	LOG_DEBUG("[Coming] PMP ROM Enable");
*/	
#endif

	return ERROR_OK;

}

static int zx_pmp_arch_state(struct target *target)
{
	LOG_DEBUG("%s", __func__);
	return ERROR_OK;
}

static int zx_pmp_restore_context(struct target *target)
{
	struct zx_pmp_common *zx_pmp = target_to_zx_pmp(target);

	LOG_DEBUG(" ");

	if (zx_pmp->pre_restore_context)
		zx_pmp->pre_restore_context(target);

	return ERROR_OK;
}


static int zx_pmp_maybe_skip_bkpt_inst(struct target *target, bool *inst_found)
{
	struct zx_pmp_common *zx_pmp = target_to_zx_pmp(target);
	////struct pmp_common *pmp = &zx_pmp->pmp;
	struct pmp_v5_dap *jtagdp = &zx_pmp->dap;
	bool result = false;
	int retval = ERROR_OK;
	uint32_t pc = 0;


	/* if we halted last time due to a bkpt instruction
	 * then we have to manually step over it, otherwise
	 * the core will break again */

	if (target->debug_reason == DBG_REASON_BREAKPOINT) {
		uint16_t op;
		retval = pmp_mem_ap_sel_read_atomic_u32(jtagdp, zx_pmp->debug_ap,
					zx_pmp->debug_base + PMP_DBG_PC, &pc);
		if (retval != ERROR_OK) return retval;

		pc &= ~1;
		if (target_read_u16(target, pc, &op) == ERROR_OK) {
			if ((op & 0xFF00) == 0xBE00) {
				//read PC
				retval = pmp_mem_ap_sel_read_atomic_u32(jtagdp, zx_pmp->debug_ap,
							zx_pmp->debug_base + PMP_DBG_PC, &pc);
				if (retval != ERROR_OK) return retval;
		
				pc += 2;
				
				//Write PC
				retval = pmp_mem_ap_sel_write_atomic_u32(jtagdp, zx_pmp->debug_ap,
							zx_pmp->debug_base + PMP_DBG_PC, pc);
				if (retval != ERROR_OK) return retval;
				
				////buf_set_u32(pmp->pc->value, 0, 32, pc);
				////pmp->pc->dirty = true;
				////pmp->pc->valid = true;
				result = true;
				LOG_DEBUG("Skipping over BKPT instruction");
			}
		}
	}

	if (inst_found)
		*inst_found = result;

	return ERROR_OK;
}


static int zx_pmp_poll(struct target *target)
{
	////LOG_DEBUG("%s", __func__);
	
	////uint32_t state;
	////struct zx_pmp_common *zx_pmp = target_to_zx_pmp(target);
	////struct pmp_v5_dap *jtagdp = &zx_pmp->dap;
	////enum target_state prev_target_state = target->state;
	int retval = ERROR_OK;

	/*  toggle to another core is done by gdb as follow */
	/*  maint packet J core_id */
	/*  continue */
	/*  the next polling trigger an halt event sent to gdb */
	if ((target->state == TARGET_HALTED) && (target->smp) &&
		(target->gdb_service) &&
		(target->gdb_service->target == NULL)) {
		////target->gdb_service->target =
			////get_cortex_a(target, target->gdb_service->core[1]);
		target_call_event_callbacks(target, TARGET_EVENT_HALTED);
		return retval;
	}
	//2019.1.24 Coming comment for loop polling target error
	/*
	retval = pmp_mem_ap_sel_read_atomic_u32(jtagdp, zx_pmp->debug_ap,
			zx_pmp->debug_base + PMP_DBG_HALT, &state);
	if (retval != ERROR_OK){
		target->state = TARGET_UNKNOWN;
		return retval;
	}
	*/
/*Coming: This function needed to be further modifed */

/*	!!!!!!!!!!!!!!!!!!!!!!!!!!	*/
	
	return retval;
}


int global_hw_reset = 0;
static int zx_pmp_halt(struct target *target)
{
	uint32_t data = 0;
	int retval = ERROR_OK;
	//struct zx_pmp_cmd pmp_cmd;
	struct zx_pmp_common *zx_pmp = target_to_zx_pmp(target);
	struct pmp_v5_dap *jtagdp = &zx_pmp->dap;

	LOG_DEBUG("%s", __func__);

	if (target->state == TARGET_HALTED) {
		LOG_DEBUG("ZX_pmp was already halted");
		return ERROR_OK;
	}

	/*
	 * Tell the core to be halted by writing pmp_DBG_REG_HALT with 0x1
	 * and then wait for the core to be halted.
	 */
	 //====== step 1: write 0x1 to make CPU enter into halt state
	retval = pmp_mem_ap_sel_write_atomic_u32(jtagdp, zx_pmp->debug_ap,
				zx_pmp->debug_base + PMP_DBG_HALT, PMP_DBG_HALT_BIT);
	if (retval != ERROR_OK)
		return retval;

	//====== step 2: check if CPU is in halt debug mode
	retval = pmp_mem_ap_sel_read_atomic_u32(jtagdp, zx_pmp->debug_ap,
			zx_pmp->debug_base + PMP_DBG_HALT, &data);
	if (retval != ERROR_OK)
		return retval;
	LOG_DEBUG("[Coming] After halt, Reg [PMP_DBG_REG_HALT] Value: [0x%x]", data);

	if (data != 0){
		LOG_DEBUG("ZX_pmp has already in Halt Mode");
		target->state = TARGET_HALTED;
		LOG_DEBUG("target->state: %s", target_state_name(target));
	}

	retval = pmp_mem_ap_sel_read_atomic_u32(jtagdp, zx_pmp->debug_ap,
			zx_pmp->debug_base + PMP_DBG_PC, &data);
	if (retval != ERROR_OK) return retval;
	LOG_DEBUG("[Coming] Current PC = [0x%x]", data);

	if (target->state == TARGET_UNKNOWN)
		LOG_WARNING("ZX_pmp was in unknown state when halt was requested");
	
	target->debug_reason = DBG_REASON_DBGRQ;
	
#if 0
	uint32_t reg_data = 0;
	retval = pmp_mem_ap_sel_write_atomic_u32(jtagdp, zx_pmp->debug_ap,
			zx_pmp->debug_base + PMP_DBG_REGFILE_ADDR, 0xa);
	if (retval != ERROR_OK) return retval;

	retval = pmp_mem_ap_sel_read_atomic_u32(jtagdp, zx_pmp->debug_ap,
			zx_pmp->debug_base + PMP_DBG_REGFILE_DBG_DATA, &reg_data);
	if (retval != ERROR_OK) return retval;
	LOG_DEBUG("[Coming] Reg[10] = [0x%x]", reg_data);

	//=============================
	retval = pmp_mem_ap_sel_write_atomic_u32(jtagdp, zx_pmp->debug_ap,
			zx_pmp->debug_base + PMP_DBG_REGFILE_ADDR, 0xb);
	if (retval != ERROR_OK) return retval;

	retval = pmp_mem_ap_sel_read_atomic_u32(jtagdp, zx_pmp->debug_ap,
			zx_pmp->debug_base + PMP_DBG_REGFILE_DBG_DATA, &reg_data);
	if (retval != ERROR_OK) return retval;
	LOG_DEBUG("[Coming] Reg[11] = [0x%x]", reg_data);

	//=============================
	retval = pmp_mem_ap_sel_write_atomic_u32(jtagdp, zx_pmp->debug_ap,
			zx_pmp->debug_base + PMP_DBG_REGFILE_ADDR, 0xd);
	if (retval != ERROR_OK) return retval;

	retval = pmp_mem_ap_sel_read_atomic_u32(jtagdp, zx_pmp->debug_ap,
			zx_pmp->debug_base + PMP_DBG_REGFILE_DBG_DATA, &reg_data);
	if (retval != ERROR_OK) return retval;
	LOG_DEBUG("[Coming] Reg[13] = [0x%x]", reg_data);


#endif

	return ERROR_OK;

}

static int zx_pmp_set_breakpoint(struct target *target,
	struct breakpoint *breakpoint, uint8_t matchmode);

int zx_pmp_set_watchpoint(struct target *target, struct watchpoint *watchpoint);


void zx_pmp_enable_breakpoints(struct target *target)
{
	struct breakpoint *breakpoint = target->breakpoints;

	/* set any pending breakpoints */
	while (breakpoint) {
		if (!breakpoint->set)
			/*Coming: athis part need to resume !!!!!! */
			zx_pmp_set_breakpoint(target, breakpoint, 0x0);
		breakpoint = breakpoint->next;
	}
}

void zx_pmp_enable_watchpoints(struct target *target)
{
	struct watchpoint *watchpoint = target->watchpoints;

	/* set any pending watchpoints */
	while (watchpoint) {
		if (!watchpoint->set)
			zx_pmp_set_watchpoint(target, watchpoint);
		watchpoint = watchpoint->next;
	}
}


/* ====== current = 0, handle_breakpoints = 1, debug_execution = 0 ======*/
static int zx_pmp_resume(struct target *target, int current,
	uint32_t address, int handle_breakpoints, int debug_execution)
{
	struct zx_pmp_common *zx_pmp = target_to_zx_pmp(target);
	////struct pmp_common *pmp = &zx_pmp->pmp;
	struct pmp_v5_dap *jtagdp = &zx_pmp->dap;
	int retval = ERROR_OK;
	uint32_t resume_pc;
	uint32_t addr = 0;;
	
	LOG_DEBUG("%s", __func__);

	if (target->state != TARGET_HALTED) {
		LOG_WARNING("target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}
		
	LOG_DEBUG("target->state: %s", target_state_name(target));

	//=========== The following part refer to CM4 ============
	if (!debug_execution){
		target_free_all_working_areas(target);
		zx_pmp_enable_breakpoints(target);
		zx_pmp_enable_watchpoints(target);
	}
	/* current = 1: continue on current pc, otherwise continue at <address> */
	////resume_pc = buf_get_u32(pmp->pc->value, 0, 32);

	//read current PC value
	retval = pmp_mem_ap_sel_read_atomic_u32(jtagdp, zx_pmp->debug_ap,
				zx_pmp->debug_base + PMP_DBG_PC, &resume_pc);
	if (retval != ERROR_OK) return retval;
	
#if 1
	if (!current)
		resume_pc = address;
	else
		addr = resume_pc;
#endif
	resume_pc &= 0xFFFFFFFC;

	LOG_DEBUG("Resume PC = 0x%08" PRIx32, resume_pc);
	//write back PC
	retval = pmp_mem_ap_sel_write_atomic_u32(jtagdp, zx_pmp->debug_ap,
			zx_pmp->debug_base + PMP_DBG_PC, resume_pc);
	if (retval != ERROR_OK) return retval;
	
	////buf_set_u32(pmp->pc->value, 0, 32, resume_pc);
	////pmp->pc->dirty = true;
	////pmp->pc->valid = true;


	//=========== The following part refer to CM4 ============
	/* if we halted last time due to a bkpt instruction
	 * then we have to manually step over it, otherwise the core will break again */
	 
	retval = pmp_mem_ap_sel_read_atomic_u32(jtagdp, zx_pmp->debug_ap,
			zx_pmp->debug_base + PMP_DBG_PC, &resume_pc);
	if (retval != ERROR_OK) return retval;

	if (!breakpoint_find(target, resume_pc) && !debug_execution)
		zx_pmp_maybe_skip_bkpt_inst(target, NULL);


	zx_pmp_restore_context(target);

/*Coming: This function needed to be further modifed */

#if 0
	if (debug_execution) {

	}
#endif


#if 0
	if (handle_breakpoints) {
	 	
	}
#endif

	 //====== Resume CPU: write arbitrary value ======
	retval = pmp_mem_ap_sel_write_atomic_u32(jtagdp, zx_pmp->debug_ap,
				zx_pmp->debug_base + PMP_DBG_RESUME, PMP_DBG_RESUME_BIT);
	if (retval != ERROR_OK)
		return retval;

	target->debug_reason = DBG_REASON_NOTHALTED;
	target->state = TARGET_RUNNING;

	if (!debug_execution) {
		target->state = TARGET_RUNNING;
		target_call_event_callbacks(target, TARGET_EVENT_RESUMED);
		LOG_DEBUG("ZX_pmp resumed at 0x%" PRIx32, addr);
	} else {
		target->state = TARGET_DEBUG_RUNNING;
		target_call_event_callbacks(target, TARGET_EVENT_DEBUG_RESUMED);
		LOG_DEBUG("ZX_pmp debug resumed at 0x%" PRIx32, addr);
	}

#if 0
	retval = pmp_mem_ap_sel_read_atomic_u32(jtagdp, zx_pmp->debug_ap,
			zx_pmp->debug_base + PMP_DBG_PC, &addr);
	if (retval != ERROR_OK) return retval;
	LOG_DEBUG("[Coming] Current PC Value: [0x%x]", addr);
#endif

	return ERROR_OK;

}



static int zx_pmp_run_algorithm(struct target *target,
	int num_mem_params, struct mem_param *mem_params,
	int num_reg_params, struct reg_param *reg_params,
	uint32_t entry_point, uint32_t exit_point,
	int timeout_ms, void *arch_info)
{
	return ERROR_OK;

}

/* Setup hardware Breakpoint Register Pair */
static int zx_pmp_set_breakpoint(struct target *target,
	struct breakpoint *breakpoint, uint8_t matchmode)
{
	int retval;
	int hw_brp_i = 0;
	int sw_brp_i = 0;
	uint32_t control;
	////uint8_t byte_addr_select = 0x0F;
	struct zx_pmp_common *zx_pmp = target_to_zx_pmp(target);
	struct pmp_v5_dap *jtagdp = &zx_pmp->dap;
	struct zx_pmp_brp *brp_list = zx_pmp->brp_list;
	struct pmp_common *pmp = &zx_pmp->pmp;

	if (breakpoint->set) {
		LOG_WARNING("Breakpoint has already Set");
		return ERROR_OK;
	}

	if (breakpoint->type == BKPT_HARD) {
		while (brp_list[hw_brp_i].used && (hw_brp_i < pmp->brp_hw_num))
			hw_brp_i++;
		if (hw_brp_i >= pmp->brp_hw_num) {
			LOG_ERROR("ERROR Can not find free HW Breakpoint Register Pair");
			return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
		}
		breakpoint->set = hw_brp_i + 1;
		
		retval = pmp_mem_ap_sel_read_atomic_u32(jtagdp, zx_pmp->debug_ap, zx_pmp->debug_base
				+ PMP_DBG_BK_EN, &control);
		if (retval != ERROR_OK) return retval;

		brp_list[hw_brp_i].used = 1;
		brp_list[hw_brp_i].value = (breakpoint->address & 0xFFFFFFFC);
		brp_list[hw_brp_i].control = control | (0x1 << hw_brp_i);	// HW BRPT Enable [3:0]

		retval = pmp_mem_ap_sel_write_atomic_u32(jtagdp, zx_pmp->debug_ap, zx_pmp->debug_base
				+ PMP_DBG_HW_BK0 + hw_brp_i * 0x4, brp_list[hw_brp_i].value);
		if (retval != ERROR_OK) return retval;
		
		retval = pmp_mem_ap_sel_write_atomic_u32(jtagdp, zx_pmp->debug_ap, zx_pmp->debug_base
				+ PMP_DBG_BK_EN, brp_list[hw_brp_i].control);
		if (retval != ERROR_OK) return retval;
		
		LOG_DEBUG("HW brp(%i) control 0x%0" PRIx32 " value 0x%0" PRIx32, hw_brp_i,
			brp_list[hw_brp_i].control, brp_list[hw_brp_i].value);
		
	}//Coming add for support ZX2100 PMP New SW bkpts on 2017.3.3
	else if (breakpoint->type == BKPT_HSOFT) {
		
		while (brp_list[pmp->brp_hw_num + sw_brp_i].used && (sw_brp_i < pmp->brp_sw_num))	// SW BRPT NUM = 2
			sw_brp_i++;
		if (sw_brp_i >= pmp->brp_sw_num) {
			LOG_ERROR("ERROR Can not find free SW Breakpoint Register Pair");
			return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
		}

		breakpoint->set = pmp->brp_hw_num + sw_brp_i + 1;
		
		retval = pmp_mem_ap_sel_read_atomic_u32(jtagdp, zx_pmp->debug_ap, zx_pmp->debug_base
				+ PMP_DBG_BK_EN, &control);
		if (retval != ERROR_OK) return retval;

		brp_list[pmp->brp_hw_num + sw_brp_i].used = 1;
		brp_list[pmp->brp_hw_num + sw_brp_i].value = breakpoint->address;
		brp_list[pmp->brp_hw_num + sw_brp_i].control = control | (0x1 << (sw_brp_i + pmp->brp_hw_num));	// HW BRPT Enable [5:4]

		retval = pmp_mem_ap_sel_write_atomic_u32(jtagdp, zx_pmp->debug_ap, zx_pmp->debug_base
				+ PMP_DBG_SW_BK0 + sw_brp_i * 0x4, brp_list[pmp->brp_hw_num + sw_brp_i].value);
		if (retval != ERROR_OK) return retval;
		
		retval = pmp_mem_ap_sel_write_atomic_u32(jtagdp, zx_pmp->debug_ap, zx_pmp->debug_base
				+ PMP_DBG_BK_EN, brp_list[pmp->brp_hw_num + sw_brp_i].control);
		if (retval != ERROR_OK) return retval;

		LOG_DEBUG("SW brp(%i) control 0x%0" PRIx32 " value 0x%0" PRIx32, sw_brp_i,
				brp_list[pmp->brp_hw_num + sw_brp_i].control, brp_list[pmp->brp_hw_num + sw_brp_i].value);

	}
	else if (breakpoint->type == BKPT_SOFT) {

		uint8_t code[4];
		buf_set_u32(code, 0, 32, PMP_BKPT(0x11));
		retval = target_read_memory(target,
				breakpoint->address & 0xFFFFFFFE,
				breakpoint->length, 1,
				breakpoint->orig_instr);
		if (retval != ERROR_OK)
			return retval;
		retval = target_write_memory(target,
				breakpoint->address & 0xFFFFFFFE,
				breakpoint->length, 1, code);
		if (retval != ERROR_OK)
			return retval;
		breakpoint->set = 0x11; /* Any nice value but 0 */

	}

	return ERROR_OK;

}

static int zx_pmp_unset_breakpoint(struct target *target, 
	struct breakpoint *breakpoint)
{
	struct zx_pmp_common *zx_pmp = target_to_zx_pmp(target);
	struct pmp_v5_dap *jtagdp = &zx_pmp->dap;
	struct zx_pmp_brp *brp_list = zx_pmp->brp_list;
	struct pmp_common *pmp = &zx_pmp->pmp;
	uint32_t control;
	int retval;
	int hw_brp_i = 0;
	int sw_brp_i = 0;

	if (!breakpoint->set) {
		LOG_WARNING("breakpoint not set");
		return ERROR_OK;
	}
	
	if (breakpoint->type == BKPT_HARD) {
		hw_brp_i = breakpoint->set - 1;
		if ((hw_brp_i < 0) || (hw_brp_i >= pmp->brp_hw_num)) {
			LOG_DEBUG("Invalid BRP number in breakpoint");
			return ERROR_OK;
		}
		LOG_DEBUG("HW rbp(%i) control 0x%0" PRIx32 " value 0x%0" PRIx32, hw_brp_i,
				brp_list[hw_brp_i].control, brp_list[hw_brp_i].value);

		retval = pmp_mem_ap_sel_read_atomic_u32(jtagdp, zx_pmp->debug_ap, zx_pmp->debug_base
				+ PMP_DBG_BK_EN, &control);
		if (retval != ERROR_OK) return retval;
			
		brp_list[hw_brp_i].used = 0;
		brp_list[hw_brp_i].value = 0;
		brp_list[hw_brp_i].control = control & (~(0x1 << hw_brp_i));

			/* Coming:  The following 2 regs needed to be modified */
		retval = pmp_mem_ap_sel_write_atomic_u32(jtagdp, zx_pmp->debug_ap, zx_pmp->debug_base
				+ PMP_DBG_HW_BK0 + hw_brp_i + 0x4, brp_list[hw_brp_i].value);
		if (retval != ERROR_OK) return retval;

		retval = pmp_mem_ap_sel_write_atomic_u32(jtagdp, zx_pmp->debug_ap, zx_pmp->debug_base
				+ PMP_DBG_BK_EN, brp_list[hw_brp_i].control);
		if (retval != ERROR_OK) return retval;
			
		breakpoint->set = 0;
		return ERROR_OK;

	}
	else if (breakpoint->type == BKPT_HSOFT) {	//Coming add for support ZX2100 PMP New SW bkpts on 2017.3.3
		
		sw_brp_i = breakpoint->set - pmp->brp_hw_num - 1;
		if ((sw_brp_i < 0) || (sw_brp_i >= pmp->brp_sw_num)) {
			LOG_DEBUG("Invalid BRP number in breakpoint");
			return ERROR_OK;
		}
		LOG_DEBUG("SW rbp(%i) control 0x%0" PRIx32 " value 0x%0" PRIx32, sw_brp_i,
			brp_list[pmp->brp_hw_num + sw_brp_i].control, brp_list[pmp->brp_hw_num + sw_brp_i].value);
		
		retval = pmp_mem_ap_sel_read_atomic_u32(jtagdp, zx_pmp->debug_ap, zx_pmp->debug_base
				+ PMP_DBG_BK_EN, &control);
		if (retval != ERROR_OK) return retval;
		
		brp_list[pmp->brp_hw_num + sw_brp_i].used = 0;
		brp_list[pmp->brp_hw_num + sw_brp_i].value = 0;
		brp_list[pmp->brp_hw_num + sw_brp_i].control = control & (~(0x1 << (sw_brp_i + pmp->brp_hw_num)));
		
		/* Coming:	The following 2 regs needed to be modified */
		retval = pmp_mem_ap_sel_write_atomic_u32(jtagdp, zx_pmp->debug_ap, zx_pmp->debug_base
				+ PMP_DBG_SW_BK0 + sw_brp_i * 0x4, brp_list[pmp->brp_hw_num + sw_brp_i].value);
		if (retval != ERROR_OK) return retval;
		
		retval = pmp_mem_ap_sel_write_atomic_u32(jtagdp, zx_pmp->debug_ap, zx_pmp->debug_base
				+ PMP_DBG_BK_EN, brp_list[pmp->brp_hw_num + sw_brp_i].control);
		if (retval != ERROR_OK) return retval;
		
		breakpoint->set = 0;
		return ERROR_OK;

	}
	else if (breakpoint->type == BKPT_SOFT) {
		/* restore original instruction (kept in target endianness) */
		if (breakpoint->length == 4) {
			retval = target_write_memory(target,
					breakpoint->address & 0xFFFFFFFE,
					4, 1, breakpoint->orig_instr);
			if (retval != ERROR_OK)
				return retval;
		} else {
			retval = target_write_memory(target,
					breakpoint->address & 0xFFFFFFFE,
					2, 1, breakpoint->orig_instr);
			if (retval != ERROR_OK)
				return retval;
		}

	}

	breakpoint->set = 0;

	return ERROR_OK;

}

static int zx_pmp_add_breakpoint(struct target *target,
	struct breakpoint *breakpoint)
{
	struct zx_pmp_common *zx_pmp = target_to_zx_pmp(target);
	struct pmp_common *pmp = &zx_pmp->pmp;

	if ((breakpoint->type == BKPT_HARD) && (pmp->brp_num_available < 1)) {
		LOG_INFO("no hardware breakpoint available");
		return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
	}

	if (breakpoint->type == BKPT_HARD)
		pmp->brp_num_available--;

	return zx_pmp_set_breakpoint(target, breakpoint, 0x00);	/* Exact match */
}

static int zx_pmp_remove_breakpoint(struct target *target, 
	struct breakpoint *breakpoint)
{
	struct zx_pmp_common *zx_pmp = target_to_zx_pmp(target);
	struct pmp_common *pmp = &zx_pmp->pmp;

#if 0
/* It is perfectly possible to remove breakpoints while the target is running */
	if (target->state != TARGET_HALTED) {
		LOG_WARNING("target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}
#endif

	if (breakpoint->set) {
		zx_pmp_unset_breakpoint(target, breakpoint);
		if (breakpoint->type == BKPT_HARD)
			pmp->brp_num_available++;
	}


	return ERROR_OK;
}


int zx_pmp_set_watchpoint(struct target *target, struct watchpoint *watchpoint)
{
	int dwt_num = 0;
	uint32_t mask, temp;
	struct zx_pmp_common *zx_pmp = target_to_zx_pmp(target);
	struct zx_pmp_dwt_comparator *comparator;

	/* watchpoint params were validated earlier */
	mask = 0;
	temp = watchpoint->length;
	while (temp) {
		temp >>= 1;
		mask++;
	}
	mask--;

	/* REVISIT Don't fully trust these "not used" records ... users
	 * may set up breakpoints by hand, e.g. dual-address data value
	 * watchpoint using comparator #1; comparator #0 matching cycle
	 * count; send data trace info through ITM and TPIU; etc
	 */
	
	for (comparator = zx_pmp->dwt_comparator_list;
		comparator->used && dwt_num < zx_pmp->dwt_num_comp;
		comparator++, dwt_num++)
		continue;
	if (dwt_num >= zx_pmp->dwt_num_comp) {
		LOG_ERROR("Can not find free DWT Comparator");
		return ERROR_FAIL;
	}
	comparator->used = 1;
	watchpoint->set = dwt_num + 1;

	comparator->comp = watchpoint->address;
	target_write_u32(target, comparator->dwt_comparator_address + 0,
		comparator->comp);

	comparator->mask = mask;
	target_write_u32(target, comparator->dwt_comparator_address + 4,
		comparator->mask);

	switch (watchpoint->rw) {
		case WPT_READ:
			comparator->function = 5;
			break;
		case WPT_WRITE:
			comparator->function = 6;
			break;
		case WPT_ACCESS:
			comparator->function = 7;
			break;
	}
	target_write_u32(target, comparator->dwt_comparator_address + 8,
		comparator->function);

	LOG_DEBUG("Watchpoint (ID %d) DWT%d 0x%08x 0x%x 0x%05x",
		watchpoint->unique_id, dwt_num,
		(unsigned) comparator->comp,
		(unsigned) comparator->mask,
		(unsigned) comparator->function);
	return ERROR_OK;
}


int zx_pmp_unset_watchpoint(struct target *target, struct watchpoint *watchpoint)
{
	struct zx_pmp_common *zx_pmp = target_to_zx_pmp(target);
	struct zx_pmp_dwt_comparator *comparator;
	int dwt_num;

	if (!watchpoint->set) {
		LOG_WARNING("watchpoint (wpid: %d) not set",
			watchpoint->unique_id);
		return ERROR_OK;
	}

	dwt_num = watchpoint->set - 1;

	LOG_DEBUG("Watchpoint (ID %d) DWT%d address: 0x%08x clear",
		watchpoint->unique_id, dwt_num,
		(unsigned) watchpoint->address);

	if ((dwt_num < 0) || (dwt_num >= zx_pmp->dwt_num_comp)) {
		LOG_DEBUG("Invalid DWT Comparator number in watchpoint");
		return ERROR_OK;
	}

	comparator = zx_pmp->dwt_comparator_list + dwt_num;
	comparator->used = 0;
	comparator->function = 0;
	target_write_u32(target, comparator->dwt_comparator_address + 8,
		comparator->function);

	watchpoint->set = false;

	return ERROR_OK;
}



/*========== current = 0, handle_breakpoints = 1 ==========*/
//======= modify on 2017.01.16, can work on FPGA======
static int zx_pmp_step(struct target *target, int current,
	uint32_t address, int handle_breakpoints)
{
	struct zx_pmp_common *zx_pmp = target_to_zx_pmp(target);
	////struct pmp_common *pmp = &zx_pmp->pmp;
	struct breakpoint *breakpoint = NULL;
	struct pmp_v5_dap *jtagdp = &zx_pmp->dap;
	int retval;

	if (target->state != TARGET_HALTED) {
		LOG_WARNING("target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	//Coming: add for handle SW BKPT 2017.3.2
	/* The front-end may request us not to handle breakpoints.
	 * But since Cortex-A uses breakpoint for single step,  we MUST handle breakpoints.*/
	handle_breakpoints = 1;
	if (handle_breakpoints) {
		breakpoint = breakpoint_find(target, address);
		if (breakpoint)
			zx_pmp_unset_breakpoint(target, breakpoint);
	}

	//Write Debug Step Reg [pmp_DBG_REG_STEP] with 0x1
	retval = pmp_mem_ap_sel_write_atomic_u32(jtagdp, zx_pmp->debug_ap,
			zx_pmp->debug_base + PMP_DBG_STEP, 1);
	if (retval != ERROR_OK) return retval;
	
	target->debug_reason = DBG_REASON_SINGLESTEP;

	long long then = timeval_ms();
	while (target->state != TARGET_HALTED) {
		retval = zx_pmp_poll(target);
		if (retval != ERROR_OK)
			return retval;
		if (timeval_ms() > then + 1000) {
			LOG_ERROR("timeout waiting for target halt");
			return ERROR_FAIL;
		}
	}

	if (target->state != TARGET_HALTED)
		LOG_DEBUG("target stepped");

	retval = pmp_mem_ap_sel_read_atomic_u32(jtagdp, zx_pmp->debug_ap,
			zx_pmp->debug_base + PMP_DBG_PC, &address);
	if (retval != ERROR_OK) return retval;
	LOG_DEBUG("[Coming] Current PC = [0x%x]", address);

	return ERROR_OK;

}

#if 0
static int zx_pmp_step(struct target *target, int current,
	uint32_t address, int handle_breakpoints)
{
	struct zx_pmp_common *zx_pmp = target_to_zx_pmp(target);
	////struct pmp_common *pmp = &zx_pmp->pmp;
	struct pmp_v5_dap *jtagdp = &zx_pmp->dap;
	struct breakpoint *breakpoint = NULL;
	struct breakpoint stepbreakpoint;
	////struct reg *r;
	int retval;

	if (target->state != TARGET_HALTED) {
		LOG_WARNING("target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}


	/* current = 1: continue on current pc, otherwise continue at <address> */
	if (!current){
		////buf_set_u32(pmp->pc->value, 0, 32, address);
		retval = pmp_mem_ap_sel_write_atomic_u32(jtagdp, zx_pmp->debug_ap,
				zx_pmp->debug_base + PMP_DBG_PC, address);
		if (retval != ERROR_OK) return retval;
	}
	else{
		////address = buf_get_u32(pmp->pc->value, 0, 32);
		retval = pmp_mem_ap_sel_read_atomic_u32(jtagdp, zx_pmp->debug_ap,
				zx_pmp->debug_base + PMP_DBG_PC, &address);
		if (retval != ERROR_OK) return retval;
	}
		

/* Coming:  This part need to double confirm */
	/* The front-end may request us not to handle breakpoints.
	 * But since Cortex-A uses breakpoint for single step,  we MUST handle breakpoints.*/
	handle_breakpoints = 1;
	if (handle_breakpoints) {
		breakpoint = breakpoint_find(target, address);
		if (breakpoint)
			zx_pmp_unset_breakpoint(target, breakpoint);
	}

	/* Setup single step breakpoint */
	stepbreakpoint.address = address;
	stepbreakpoint.length = 4;			/* Coming: This part need to double confirm(OK) */
	stepbreakpoint.type = BKPT_HARD;
	stepbreakpoint.set = 0;


	/* Break on IVA mismatch */
	zx_pmp_set_breakpoint(target, &stepbreakpoint, 0x04);


/*!!!!!!!!!!!! Coming:  This part need to double confirm ====== 2016.12.15 !!!!!!!!!!!! */

	//Write Debug Step Reg [PMP_DBG_STEP] with 0x1
	retval = pmp_mem_ap_sel_write_atomic_u32(jtagdp, zx_pmp->debug_ap,
			zx_pmp->debug_base + PMP_DBG_STEP, 1);
	if (retval != ERROR_OK) return retval;
	

	target->debug_reason = DBG_REASON_SINGLESTEP;

	retval = zx_pmp_resume(target, 1, address, 0, 0);//Note: handle_breakpoints = 0
	if (retval != ERROR_OK)
		return retval;

	long long then = timeval_ms();
	while (target->state != TARGET_HALTED) {
		retval = zx_pmp_poll(target);
		if (retval != ERROR_OK)
			return retval;
		if (timeval_ms() > then + 1000) {
			LOG_ERROR("timeout waiting for target halt");
			return ERROR_FAIL;
		}
	}

	zx_pmp_unset_breakpoint(target, &stepbreakpoint);

	target->debug_reason = DBG_REASON_BREAKPOINT;

	if (breakpoint)
		zx_pmp_set_breakpoint(target, breakpoint, 0);

	if (target->state != TARGET_HALTED)
		LOG_DEBUG("target stepped");

	retval = pmp_mem_ap_sel_read_atomic_u32(jtagdp, zx_pmp->debug_ap,
			zx_pmp->debug_base + PMP_DBG_PC, &address);
	if (retval != ERROR_OK) return retval;
	LOG_DEBUG("[Coming] Current PC = [0x%x]", address);

	return ERROR_OK;

}

#endif

static int zx_pmp_assert_reset(struct target *target)
{
	return ERROR_OK;

}


static int zx_pmp_deassert_reset(struct target *target)
{
	return ERROR_OK;

}


#if 1

static int zx_pmp_read_dbgreg(struct target *target, uint32_t address,
	uint32_t size, uint32_t count, uint8_t *buffer)
{
	struct zx_pmp_common *zx_pmp = target_to_zx_pmp(target);
	struct pmp_v5_dap *jtagdp = &zx_pmp->dap;
	int retval = ERROR_OK;
	uint32_t data = 0;
	
	if (((size == 4) && (address & 0x3u)) || ((size == 2) && (address & 0x1u)))
		return ERROR_TARGET_UNALIGNED_ACCESS;

	retval = pmp_mem_ap_sel_read_atomic_u32(jtagdp, zx_pmp->debug_ap,
				zx_pmp->debug_base + address, &data);
	LOG_DEBUG("[Coming] Debug Reg [0x%x]: [0x%x]", address, data);

	return retval;

}

static int zx_pmp_write_dbgreg(struct target *target, uint32_t address,
	uint32_t size, uint32_t count, const uint8_t *buffer)
{
	struct zx_pmp_common *zx_pmp = target_to_zx_pmp(target);
	struct pmp_v5_dap *jtagdp = &zx_pmp->dap;
	int retval = ERROR_OK;
	uint32_t *data_buf = (uint32_t*)buffer;
	uint32_t data = 0;

	if (((size == 4) && (address & 0x3u)) || ((size == 2) && (address & 0x1u)))
		return ERROR_TARGET_UNALIGNED_ACCESS;

	retval = pmp_mem_ap_sel_write_atomic_u32(jtagdp, zx_pmp->debug_ap,
				zx_pmp->debug_base + address, *data_buf);

	retval = pmp_mem_ap_sel_read_atomic_u32(jtagdp, zx_pmp->debug_ap,
				zx_pmp->debug_base + address, &data);
	LOG_DEBUG("[Coming] Debug Reg [0x%x]: [0x%x]", address, data);
	
	return retval;
}


#endif

static int zx_pmp_read_phys_memory(struct target *target, uint32_t address,
	uint32_t size, uint32_t count, uint8_t *buffer)
{
	struct zx_pmp_common *zx_pmp = target_to_zx_pmp(target);
	struct pmp_v5_dap *jtagdp = &zx_pmp->dap;
	
	LOG_DEBUG("[Coming] zx_pmp_read_phys_memory");
	
	if (((size == 4) && (address & 0x3u)) || ((size == 2) && (address & 0x1u)))
		return ERROR_TARGET_UNALIGNED_ACCESS;

	return pmp_mem_ap_sel_read_buf(jtagdp, zx_pmp->memory_ap, buffer, size, count, address);

}



static int zx_pmp_write_phys_memory(struct target *target, uint32_t address,
	uint32_t size, uint32_t count, const uint8_t *buffer)
{
	struct zx_pmp_common *zx_pmp = target_to_zx_pmp(target);
	struct pmp_v5_dap *jtagdp = &zx_pmp->dap;

	if (((size == 4) && (address & 0x3u)) || ((size == 2) && (address & 0x1u)))
		return ERROR_TARGET_UNALIGNED_ACCESS;

	return pmp_mem_ap_sel_write_buf(jtagdp, zx_pmp->memory_ap, buffer, size, count, address);
}


/*
 * Exit with error here, because we support watchpoints over a custom command.
 * This is because the DSP has separate X,Y,P memspace which is not compatible to the
 * traditional watchpoint logic.
 */
static int zx_pmp_add_watchpoint(struct target *target, struct watchpoint *watchpoint)
{
	return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
}

/* @see zx_pmp_add_watchpoint*/
static int  zx_pmp_remove_watchpoint(struct target *target, struct watchpoint *watchpoint)
{
	return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
}

COMMAND_HANDLER(pmp_handle_dbginit_command)
{
	struct target *target = get_current_target(CMD_CTX);
	if (!target_was_examined(target)) {
		LOG_ERROR("target not examined yet");
		return ERROR_FAIL;
	}

	////return cortex_a_init_debug_access(target);
	return ERROR_OK;
}

static const struct command_registration zx_pmp_exec_command_handlers[] = {
	{
		.name = "pmp_dbginit",
		.handler = pmp_handle_dbginit_command,
		.mode = COMMAND_EXEC,
		.help = "Initialize core debug",
		.usage = "",
	},
#if 0
	{
		.name = "vector_catch",
		.handler = handle_zx_pmp_vector_catch_command,
		.mode = COMMAND_EXEC,
		.help = "configure hardware vectors to trigger debug entry",
		.usage = "['all'|'none'|('bus_err'|'chk_err'|...)*]",
	},
	{
		.name = "reset_config",
		.handler = handle_zx_pmp_reset_config_command,
		.mode = COMMAND_ANY,
		.help = "configure software reset handling",
		.usage = "['srst'|'sysresetreq'|'vectreset']",
	},
#endif
	COMMAND_REGISTRATION_DONE
};

static const struct command_registration zx_pmp_command_handlers[] = {
	{
		.chain = pmp_dap_command_handlers,
	},
	{
		.name = "zx_pmp",
		.mode = COMMAND_EXEC,
		.help = "ZX PMP command group",
		.usage = "",
		.chain = zx_pmp_exec_command_handlers,
	},
	COMMAND_REGISTRATION_DONE

};


/** Holds methods for Zhaoxin pmp-V targets. */
struct target_type zx_pmp_target = {
	.name = "zx_pmp",
	.deprecated_name = "zx_pmp",

	.poll = zx_pmp_poll,
	.arch_state = zx_pmp_arch_state,

	.get_gdb_reg_list = zx_pmp_get_gdb_reg_list,

	.halt = zx_pmp_halt,
	.resume = zx_pmp_resume,
	.step = zx_pmp_step,

	.assert_reset = zx_pmp_assert_reset,
	.deassert_reset = zx_pmp_deassert_reset,

	.read_memory = zx_pmp_read_dbgreg,
	.write_memory = zx_pmp_write_dbgreg,

	.read_phys_memory = zx_pmp_read_phys_memory,
	.write_phys_memory = zx_pmp_write_phys_memory,

	.run_algorithm = zx_pmp_run_algorithm,

	.add_breakpoint = zx_pmp_add_breakpoint,
	.remove_breakpoint = zx_pmp_remove_breakpoint,
	.add_watchpoint = zx_pmp_add_watchpoint,
	.remove_watchpoint = zx_pmp_remove_watchpoint,

	.commands = zx_pmp_command_handlers,
	.target_create = zx_pmp_target_create,
	.init_target = zx_pmp_init_target,
	.examine = zx_pmp_examine,
};



