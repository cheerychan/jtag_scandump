/***************************************************************************
 *   Copyright (C) 2009 by Mathias Kuester                                 *
 *   mkdorg@users.sourceforge.net                                          *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.           *
 ***************************************************************************/

#ifndef DSP563XX_ONCE_H
#define DSP563XX_ONCE_H

#include <helper/list.h>
#include "arm_jtag.h"


#define PMP_DBG_BASE	0x0	// Coming: ZX pmp-V debug base address



/* FIXME remove these JTAG-specific decls when mem_ap_read_buf_u32()
 * is no longer JTAG-specific
 */
#define PMP_JTAG_DP_DPACC		0xA
#define PMP_JTAG_DP_APACC		0xB

/* three-bit ACK values for SWD access (sent LSB first) */
#define PMP_SWD_ACK_OK    0x1
#define PMP_SWD_ACK_WAIT  0x2
#define PMP_SWD_ACK_FAULT 0x4

#define PMP_DPAP_WRITE		0
#define PMP_DPAP_READ		1

#define PMP_BANK_REG(bank, reg)	(((bank) << 4) | (reg))

/* A[3:0] for DP registers; A[1:0] are always zero.
 * - JTAG accesses all of these via JTAG_DP_DPACC, except for
 *   IDCODE (JTAG_DP_IDCODE) and ABORT (JTAG_DP_ABORT).
 * - SWD accesses these directly, sometimes needing SELECT.CTRLSEL
 */
#define PMP_DP_IDCODE		PMP_BANK_REG(0x0, 0x0)	/* SWD: read */
#define PMP_DP_ABORT		PMP_BANK_REG(0x0, 0x0)	/* SWD: write */
#define PMP_DP_CTRL_STAT	PMP_BANK_REG(0x0, 0x4)	/* r/w */
#define PMP_DP_RESEND		PMP_BANK_REG(0x0, 0x8)	/* SWD: read */
#define PMP_DP_SELECT		PMP_BANK_REG(0x0, 0x8)	/* JTAG: r/w; SWD: write */
#define PMP_DP_RDBUFF		PMP_BANK_REG(0x0, 0xC)	/* read-only */
#define PMP_DP_WCR			PMP_BANK_REG(0x1, 0x4)	/* SWD: r/w */

#define PMP_WCR_TO_TRN(wcr) ((uint32_t)(1 + (3 & ((wcr)) >> 8)))	/* 1..4 clocks */
#define PMP_WCR_TO_PRESCALE(wcr) ((uint32_t)(7 & ((wcr))))		/* impl defined */

/* Fields of the DP's AP ABORT register */
#define PMP_DAPABORT        (1UL << 0)
#define PMP_STKCMPCLR       (1UL << 1) /* SWD-only */
#define PMP_STKERRCLR       (1UL << 2) /* SWD-only */
#define PMP_WDERRCLR        (1UL << 3) /* SWD-only */
#define PMP_ORUNERRCLR      (1UL << 4) /* SWD-only */

/* Fields of the DP's CTRL/STAT register */
#define PMP_CORUNDETECT     (1UL << 0)
#define PMP_SSTICKYORUN     (1UL << 1)
/* 3:2 - transaction mode (e.g. pushed compare) */
#define PMP_SSTICKYCMP      (1UL << 4)
#define PMP_SSTICKYERR      (1UL << 5)
#define PMP_READOK          (1UL << 6) /* SWD-only */
#define PMP_WDATAERR        (1UL << 7) /* SWD-only */
/* 11:8 - mask lanes for pushed compare or verify ops */
/* 21:12 - transaction counter */
#define PMP_CDBGRSTREQ      (1UL << 26)
#define PMP_CDBGRSTACK      (1UL << 27)
#define PMP_CDBGPWRUPREQ    (1UL << 28)
#define PMP_CDBGPWRUPACK    (1UL << 29)
#define PMP_CSYSPWRUPREQ    (1UL << 30)
#define PMP_CSYSPWRUPACK    (1UL << 31)

/* MEM-AP register addresses */
/* TODO: rename as MEM_AP_REG_* */
#define PMP_AP_REG_CSW		0x00
#define PMP_AP_REG_TAR		0x04
#define PMP_AP_REG_DRW		0x0C
#define PMP_AP_REG_BD0		0x10
#define PMP_AP_REG_BD1		0x14
#define PMP_AP_REG_BD2		0x18
#define PMP_AP_REG_BD3		0x1C
#define PMP_AP_REG_CFG		0xF4		/* big endian? */
#define PMP_AP_REG_BASE		0xF8

/* Generic AP register address */
#define PMP_AP_REG_IDR		0xFC

/* Fields of the MEM-AP's CSW register */
#define PMP_CSW_8BIT		0
#define PMP_CSW_16BIT		1
#define PMP_CSW_32BIT		2
#define PMP_CSW_ADDRINC_MASK    (3UL << 4)
#define PMP_CSW_ADDRINC_OFF      0UL
#define PMP_CSW_ADDRINC_SINGLE  (1UL << 4)
#define PMP_CSW_ADDRINC_PACKED  (2UL << 4)
#define PMP_CSW_DEVICE_EN       (1UL << 6)
#define PMP_CSW_TRIN_PROG       (1UL << 7)
#define PMP_CSW_SPIDEN          (1UL << 23)
/* 30:24 - implementation-defined! */
#define PMP_CSW_HPROT           (1UL << 25) /* ? */
#define PMP_CSW_MASTER_DEBUG    (1UL << 29) /* ? */
#define PMP_CSW_SPROT           (1UL << 30)
#define PMP_CSW_DBGSWENABLE     (1UL << 31)

//=============================================



/**
 * This represents an ARM Debug Interface (v5) Debug Access Port (DAP).
 * A DAP has two types of component:  one Debug Port (DP), which is a
 * transport agent; and at least one Access Port (AP), controlling
 * resource access.  Most common is a MEM-AP, for memory access.
 *
 * There are two basic DP transports: JTAG, and ARM's low pin-count SWD.
 * Accordingly, this interface is responsible for hiding the transport
 * differences so upper layer code can largely ignore them.
 *
 * When the chip is implemented with JTAG-DP or SW-DP, the transport is
 * fixed as JTAG or SWD, respectively.  Chips incorporating SWJ-DP permit
 * a choice made at board design time (by only using the SWD pins), or
 * as part of setting up a debug session (if all the dual-role JTAG/SWD
 * signals are available).
 */

struct pmp_v5_dap {
	const struct pmp_dap_ops *ops;

	struct arm_jtag *jtag_info;
	/* Control config */
	uint32_t dp_ctrl_stat;

	uint32_t apcsw[256];
	uint32_t apsel;

	/**
	 * Cache for DP_SELECT bits identifying the current AP.  A DAP may
	 * connect to multiple APs, such as one MEM-AP for general access,
	 * another reserved for accessing debug modules, and a JTAG-DP.
	 * "-1" indicates no cached value.
	 */
	uint32_t ap_current;

	/**
	 * Cache for DP_SELECT bits identifying the current four-word AP
	 * register bank.  This caches AP register addresss bits 7:4; JTAG
	 * and SWD access primitves pass address bits 3:2; bits 1:0 are zero.
	 * "-1" indicates no cached value.
	 */
	uint32_t ap_bank_value;

	/**
	 * Cache for DP_SELECT bits identifying the current four-word DP
	 * register bank.  This caches DP register addresss bits 7:4; JTAG
	 * and SWD access primitves pass address bits 3:2; bits 1:0 are zero.
	 */
	uint32_t dp_bank_value;

	/**
	 * Cache for (MEM-AP) AP_REG_CSW register value.  This is written to
	 * configure an access mode, such as autoincrementing AP_REG_TAR during
	 * word access.  "-1" indicates no cached value.
	 */
	uint32_t ap_csw_value;

	/**
	 * Cache for (MEM-AP) AP_REG_TAR register value This is written to
	 * configure the address being read or written
	 * "-1" indicates no cached value.
	 */
	uint32_t ap_tar_value;

	/* information about current pending SWjDP-AHBAP transaction */
	uint8_t  ack;

	/**
	 * Holds the pointer to the destination word for the last queued read,
	 * for use with posted AP read sequence optimization.
	 */
	uint32_t *last_read;

	/**
	 * Configures how many extra tck clocks are added after starting a
	 * MEM-AP access before we try to read its status (and/or result).
	 */
	uint32_t	memaccess_tck;

	/* Size of TAR autoincrement block, ARM ADI Specification requires at least 10 bits */
	uint32_t tar_autoincr_block;

	/* true if packed transfers are supported by the MEM-AP */
	bool packed_transfers;

	/* true if unaligned memory access is not supported by the MEM-AP */
	bool unaligned_access_bad;

	/* The TI TMS470 and TMS570 series processors use a BE-32 memory ordering
	 * despite lack of support in the ARMv7 architecture. Memory access through
	 * the AHB-AP has strange byte ordering these processors, and we need to
	 * swizzle appropriately. */
	bool ti_be_32_quirks;

	/**
	 * Signals that an attempt to reestablish communication afresh
	 * should be performed before the next access.
	 */
	bool do_reconnect;
};


/**
 * Transport-neutral representation of queued DAP transactions, supporting
 * both JTAG and SWD transports.  All submitted transactions are logically
 * queued, until the queue is executed by run().  Some implementations might
 * execute transactions as soon as they're submitted, but no status is made
 * available until run().
 */
struct pmp_dap_ops {
	/** If the DAP transport isn't SWD, it must be JTAG.  Upper level
	 * code may need to care about the difference in some cases.
	 */
	bool is_swd;

	/** DP register read. */
	int (*queue_dp_read)(struct pmp_v5_dap *dap, unsigned reg,
			uint32_t *data);
	/** DP register write. */
	int (*queue_dp_write)(struct pmp_v5_dap *dap, unsigned reg,
			uint32_t data);

	/** AP register read. */
	int (*queue_ap_read)(struct pmp_v5_dap *dap, unsigned reg,
			uint32_t *data);
	/** AP register write. */
	int (*queue_ap_write)(struct pmp_v5_dap *dap, unsigned reg,
			uint32_t data);

	/** AP operation abort. */
	int (*queue_ap_abort)(struct pmp_v5_dap *dap, uint8_t *ack);

	/** Executes all queued DAP operations. */
	int (*run)(struct pmp_v5_dap *dap);
};

/*
 * Access Port types
 */
enum pmp_ap_type {
	PMP_AP_TYPE_AHB_AP  = 0x01,  /* AHB Memory-AP */
	PMP_AP_TYPE_APB_AP  = 0x02,  /* APB Debug-AP */
	PMP_AP_TYPE_AHB_AP2 = 0x01   /* JTAG-AP - JTAG master for controlling other JTAG devices */
};



//=================================================================

//Coming: this function is used to read JTAG ID_CODE
int jtag_dp_q_read_common(struct pmp_v5_dap *dap, unsigned reg, uint32_t *data);

static inline int pmp_dap_queue_dp_read_common(struct pmp_v5_dap *dap,
		unsigned reg, uint32_t *data)
{
	assert(dap->ops != NULL);
	return jtag_dp_q_read_common(dap, reg, data);
}



/**
 * Queue a DP register read.
 * Note that not all DP registers are readable; also, that JTAG and SWD
 * have slight differences in DP register support.
 *
 * @param dap The DAP used for reading.
 * @param reg The two-bit number of the DP register being read.
 * @param data Pointer saying where to store the register's value
 * (in host endianness).
 *
 * @return ERROR_OK for success, else a fault code.
 */
static inline int pmp_dap_queue_dp_read(struct pmp_v5_dap *dap,
		unsigned reg, uint32_t *data)
{
	assert(dap->ops != NULL);
	return dap->ops->queue_dp_read(dap, reg, data);
}

/**
 * Queue a DP register write.
 * Note that not all DP registers are writable; also, that JTAG and SWD
 * have slight differences in DP register support.
 *
 * @param dap The DAP used for writing.
 * @param reg The two-bit number of the DP register being written.
 * @param data Value being written (host endianness)
 *
 * @return ERROR_OK for success, else a fault code.
 */
static inline int pmp_dap_queue_dp_write(struct pmp_v5_dap *dap,
		unsigned reg, uint32_t data)
{
	assert(dap->ops != NULL);
	return dap->ops->queue_dp_write(dap, reg, data);
}

/**
 * Queue an AP register read.
 *
 * @param ap The AP used for reading.
 * @param reg The number of the AP register being read.
 * @param data Pointer saying where to store the register's value
 * (in host endianness).
 *
 * @return ERROR_OK for success, else a fault code.
 */
static inline int pmp_dap_queue_ap_read(struct pmp_v5_dap *dap,
		unsigned reg, uint32_t *data)
{
	assert(dap->ops != NULL);
	return dap->ops->queue_ap_read(dap, reg, data);
}

/**
 * Queue an AP register write.
 *
 * @param ap The AP used for writing.
 * @param reg The number of the AP register being written.
 * @param data Value being written (host endianness)
 *
 * @return ERROR_OK for success, else a fault code.
 */
static inline int pmp_dap_queue_ap_write(struct pmp_v5_dap *dap,
		unsigned reg, uint32_t data)
{
	assert(dap->ops != NULL);
	return dap->ops->queue_ap_write(dap, reg, data);
}

/**
 * Queue an AP abort operation.  The current AP transaction is aborted,
 * including any update of the transaction counter.  The AP is left in
 * an unknown state (so it must be re-initialized).  For use only after
 * the AP has reported WAIT status for an extended period.
 *
 * @param dap The DAP used for writing.
 * @param ack Pointer to where transaction status will be stored.
 *
 * @return ERROR_OK for success, else a fault code.
 */
static inline int pmp_dap_queue_ap_abort(struct pmp_v5_dap *dap, uint8_t *ack)
{
	assert(dap->ops != NULL);
	return dap->ops->queue_ap_abort(dap, ack);
}

/**
 * Perform all queued DAP operations, and clear any errors posted in the
 * CTRL_STAT register when they are done.  Note that if more than one AP
 * operation will be queued, one of the first operations in the queue
 * should probably enable CORUNDETECT in the CTRL/STAT register.
 *
 * @param dap The DAP used.
 *
 * @return ERROR_OK for success, else a fault code.
 */
static inline int pmp_dap_run(struct pmp_v5_dap *dap)
{
	assert(dap->ops != NULL);
	return dap->ops->run(dap);	//coming add: jtag_dp_run()
}

#if 0
static inline int pmp_dap_sync(struct pmp_v5_dap *dap)
{
	assert(dap->ops != NULL);
	if (dap->ops->sync)
		return dap->ops->sync(dap);
	return ERROR_OK;
}
#endif

static inline int pmp_dap_dp_read_atomic(struct pmp_v5_dap *dap, unsigned reg,
				     uint32_t *value)
{
	int retval;

	retval = pmp_dap_queue_dp_read(dap, reg, value);
	if (retval != ERROR_OK)
		return retval;

	return pmp_dap_run(dap);
}

static inline int pmp_dap_dp_poll_register(struct pmp_v5_dap *dap, unsigned reg,
				       uint32_t mask, uint32_t value, int timeout)
{
	assert(timeout > 0);
	assert((value & mask) == value);

	int ret;
	uint32_t regval;
	LOG_DEBUG("DAP: poll %x, mask 0x08%" PRIx32 ", value 0x%08" PRIx32,
		  reg, mask, value);
	do {
		ret = pmp_dap_dp_read_atomic(dap, reg, &regval);
		if (ret != ERROR_OK)
			return ret;

		if ((regval & mask) == value)
			break;

		alive_sleep(10);
	} while (--timeout);

	if (!timeout) {
		LOG_DEBUG("DAP: poll %x timeout", reg);
		return ERROR_FAIL;
	} else {
		return ERROR_OK;
	}
}

/** Accessor for currently selected DAP-AP number (0..255) */
static inline uint8_t pmp_dap_ap_get_select(struct pmp_v5_dap *swjdp)
{
	return (uint8_t)(swjdp->ap_current >> 24);
}

/* AP selection applies to future AP transactions */
void pmp_dap_ap_select(struct pmp_v5_dap *dap, uint8_t ap);

/* Queued AP transactions */
int pmp_dap_setup_accessport(struct pmp_v5_dap *swjdp,
		uint32_t csw, uint32_t tar);

/* Queued MEM-AP memory mapped single word transfers */
int pmp_mem_ap_read_u32(struct pmp_v5_dap *swjdp, uint32_t address, uint32_t *value);
int pmp_mem_ap_write_u32(struct pmp_v5_dap *swjdp, uint32_t address, uint32_t value);

//====================Coming add for debug reg read/write use
int pmp_mem_ap_read_atomic_u32_dbg(struct pmp_v5_dap *dap, uint8_t *buffer, uint32_t address,
		uint32_t *value);

int pmp_mem_ap_write_atomic_u32_dbg(struct pmp_v5_dap *dap, const uint8_t *buffer, uint32_t address,
		uint32_t value);



/* Synchronous MEM-AP memory mapped single word transfers */
int pmp_mem_ap_read_atomic_u32(struct pmp_v5_dap *swjdp,
		uint32_t address, uint32_t *value);
int pmp_mem_ap_write_atomic_u32(struct pmp_v5_dap *swjdp,
		uint32_t address, uint32_t value);

/* Queued MEM-AP memory mapped single word transfers with selection of ap */
int pmp_mem_ap_sel_read_u32(struct pmp_v5_dap *swjdp, uint8_t ap,
		uint32_t address, uint32_t *value);
int pmp_mem_ap_sel_write_u32(struct pmp_v5_dap *swjdp, uint8_t ap,
		uint32_t address, uint32_t value);

/* Synchronous MEM-AP memory mapped single word transfers with selection of ap */
int pmp_mem_ap_sel_read_atomic_u32(struct pmp_v5_dap *swjdp, uint8_t ap,
		uint32_t address, uint32_t *value);
int pmp_mem_ap_sel_write_atomic_u32(struct pmp_v5_dap *swjdp, uint8_t ap,
		uint32_t address, uint32_t value);

/* Synchronous MEM-AP memory mapped bus block transfers */
int pmp_mem_ap_read(struct pmp_v5_dap *dap, uint8_t *buffer, uint32_t size,
		uint32_t count, uint32_t address, bool addrinc);
int pmp_mem_ap_write(struct pmp_v5_dap *dap, const uint8_t *buffer, uint32_t size,
		uint32_t count, uint32_t address, bool addrinc);

/* Synchronous MEM-AP memory mapped bus block transfers with selection of ap */
int pmp_mem_ap_sel_read_buf(struct pmp_v5_dap *swjdp, uint8_t ap,
		uint8_t *buffer, uint32_t size, uint32_t count, uint32_t address);
int pmp_mem_ap_sel_write_buf(struct pmp_v5_dap *swjdp, uint8_t ap,
		const uint8_t *buffer, uint32_t size, uint32_t count, uint32_t address);

/* Synchronous, non-incrementing buffer functions for accessing fifos, with
 * selection of ap */
int pmp_mem_ap_sel_read_buf_noincr(struct pmp_v5_dap *swjdp, uint8_t ap,
		uint8_t *buffer, uint32_t size, uint32_t count, uint32_t address);
int pmp_mem_ap_sel_write_buf_noincr(struct pmp_v5_dap *swjdp, uint8_t ap,
		const uint8_t *buffer, uint32_t size, uint32_t count, uint32_t address);

/* Create DAP struct */
////struct pmp_v5_ap *pmp_dap_init(void);

/* Initialisation of the debug system, power domains and registers */
int pmp_ahbap_debugport_init(struct pmp_v5_dap *swjdp);

/* Probe the AP for ROM Table location */
int pmp_dap_get_debugbase(struct pmp_v5_dap *dap, int ap,
			uint32_t *dbgbase, uint32_t *apid);

/* Probe Access Ports to find a particular type */
int pmp_dap_find_ap(struct pmp_v5_dap *dap,
			enum pmp_ap_type type_to_find,
			uint8_t *ap_num_out);

/* Lookup CoreSight component */
int pmp_dap_lookup_cs_component(struct pmp_v5_dap *dap, int ap,
			uint32_t dbgbase, uint8_t type, uint32_t *addr, int32_t *idx);

struct target;

/* Put debug link into SWD mode */
int pmp_dap_to_swd(struct target *target);

/* Put debug link into JTAG mode */
int pmp_dap_to_jtag(struct target *target);

extern const struct command_registration pmp_dap_command_handlers[];


#endif /* DSP563XX_ONCE_H */
