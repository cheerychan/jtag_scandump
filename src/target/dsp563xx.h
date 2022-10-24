#ifndef DSP563XX_H
#define DSP563XX_H

#include <jtag/jtag.h>
#include <target/dsp563xx_once.h>

//#include <target/zx_ivp_once.h>
#include "arm_jtag.h"
#include "target.h"

#define ZX_PMP_NUMCOREREGS	54
#define ZX_PMP_NUMONCEREGS	25


#define ZX2K_SUS_CLK_EN		0xd813910c	//bit[0]: PMP CLK Enable bit, SW write 1 to enable this bit, write 0 has no effect, 
#define PMP_CLK_EN_BIT		0x1

#define PMP_ROM_EN_REG		0x00078004
#define PMP_ROM_EN_BIT		0x7


//================ZX PMP Debug Regs from HW Team===================
//======= Part 1. =======

#define  PMP_DBG_HALT                  	0x8400  //write 1 to halt
#define  PMP_DBG_RESUME            		0x8404  //write 1 to resume
#define  PMP_DBG_STEP                   0x840c	//write 1 to step
#define  PMP_DBG_PC                     0x8410  //read pc, change pc

#define  PMP_DBG_BK_EN                	0x8414  //break point enable: HW[3:0], SW[5:4]
#define  PMP_DBG_SW_BK0               	0x8418  //config sw break point(imm)
#define  PMP_DBG_SW_BK1                	0x841c  
#define  PMP_DBG_HW_BK0             	0x843c	//config hw break point(PC)
#define  PMP_DBG_HW_BK1            		0x8440
#define  PMP_DBG_HW_BK2            	 	0x8444
#define  PMP_DBG_HW_BK3              	0x8448

#define  PMP_REPAIR_EN                  0x8420	/*Write 1 open the repair function, 
												   Write 0 or not write use the tranditional function*/
#define  PMP_DBG_RDATA_NUM     			0x8424
#define  PMP_DBG_RDATA                  0x8428
#define  PMP_INST_CODE                  0x842c	//Input instruction from jtag
#define  PMP_DBG_TRIGGER             	0x8430	//write arbitrary value to set debug triggle
#define  PMP_CMD_TRIGGER            	0x8434	//write arbitrary value to set CMD triggle


#define  PMP_DBG_HALT_BIT				0x19074283		//write value to make CPU enter into halt
#define  PMP_DBG_RESUME_BIT				0x1		//resume: exit from halt

//========================================================
/* Breakpoint instruction (ARMv5)
 * Im: 16-bit immediate
 * 0x4bd1_9063
 */
#define PMP_BKPT(Im) (0xe1200070 | ((Im & 0xfff0) << 8) | (Im & 0xf))	//Coming: need to be modified!!!!!!

#define BRP_NORMAL 0
#define BRP_CONTEXT 1


struct zx_pmp_cmd {
	uint16_t index;		//cmd[0:15]
	uint16_t opcode;	//cmd[16:31]
	uint32_t data;		//cmd[32:63]
	uint32_t addr;		//cmd[64:95]
};



//=======================================================
/*
struct pmp_mcu_jtag {
	struct jtag_tap *tap;
};

enum pmp_breakpoint_usage {
	BPU_NONE = 0,
	BPU_BREAKPOINT,
	BPU_WATCHPOINT
};

struct pmp_hardware_breakpoint {
	enum pmp_breakpoint_usage used;
};
*/
struct zx_pmp_brp {
	int used;
	int type;
	uint32_t value;
	uint32_t control;
	uint8_t BRPn;
};


struct zx_pmp_dwt_comparator {
	int used;
	uint32_t comp;
	uint32_t mask;
	uint32_t function;
	uint32_t dwt_comparator_address;
};


struct pmp_common {
	/* Breakpoint register pairs */
	int brp_num_context;
	int brp_hw_num;
	int brp_sw_num;
	int brp_num_available;
	/* Use cortex_a_read_regs_through_mem for fast register reads */
	int fast_reg_read;

	struct reg_cache *core_cache;

	/** Handle to the PC; valid in all core modes. */
	struct reg *pc;

	uint32_t cpuid;
	uint32_t ctypr;
	uint32_t ttypr;
	uint32_t didr;

};

struct zx_pmp_common {
	int common_magic;
	struct arm_jtag jtag_info;

	/* Context information */
	uint32_t cpudbg_dscr;	//this part need to modify	!!!!!!!!!!

	/* Saved cp15 registers */
	////uint32_t cp15_control_reg;
	/* latest cp15 register value written and cpsr processor mode */
	////uint32_t cp15_control_reg_curr;
	////enum arm_mode curr_mode;

	/*This part is similar as "struct armv7a_common"*/
	struct pmp_v5_dap dap;
	/* Core Debug Unit */
	uint32_t debug_base;
	uint8_t debug_ap;
	uint8_t memory_ap;
	bool memory_ap_available;

	struct zx_pmp_brp *brp_list;
	struct pmp_common pmp;

	/* Data Watchpoint and Trace (DWT) */
	int dwt_num_comp;
	int dwt_comp_available;
	struct zx_pmp_dwt_comparator *dwt_comparator_list;
	struct reg_cache *dwt_cache;

	int (*examine_debug_reason)(struct target *target);
	int (*post_debug_entry)(struct target *target);

	void (*pre_restore_context)(struct target *target);
};


/*
struct zx_pmp_core_reg {
	uint32_t num;
	const char *name;
	uint32_t size;
	uint8_t eame;
	uint32_t instr_mask;
	struct target *target;
	struct zx_pmp_common *zx_pmp_common;
};
*/

static inline struct zx_pmp_common *target_to_zx_pmp(struct target *target)
{
	//return container_of(target->arch_info, struct zx_pmp_common, pmp);
	return target->arch_info;
}




#endif /* DSP563XX_H */
