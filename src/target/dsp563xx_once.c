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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <jim.h>
#include "target.h"
#include "target_type.h"
#include "register.h"
#include "dsp563xx.h"
#include "dsp563xx_once.h"

#include "jtag/interface.h"
////#include <helper/jep106.h>
#include <helper/time_support.h>
#include <helper/list.h>

#include <helper/time_support.h>

//=============================================================
//======================zx_pmp_dbgv5_jtag.c==========================

/* JTAG instructions/registers for JTAG-DP and SWJ-DP */
#define PMP_JTAG_DP_ABORT		0x8
#define PMP_JTAG_DP_DPACC		0xA
#define PMP_JTAG_DP_APACC		0xB
#define PMP_JTAG_DP_IDCODE		0xE

/* three-bit ACK values for DPACC and APACC reads */
#define PMP_JTAG_ACK_OK_FAULT	0x2
#define PMP_JTAG_ACK_WAIT		0x1

static int jtag_ap_q_abort(struct pmp_v5_dap *dap, uint8_t *ack);

/***************************************************************************
 *
 * DPACC and APACC scanchain access through JTAG-DP (or SWJ-DP)
 *
***************************************************************************/

/**
 * Scan DPACC or APACC using target ordered uint8_t buffers.  No endianness
 * conversions are performed.  See section 4.4.3 of the ADIv5 spec, which
 * discusses operations which access these registers.
 *
 * Note that only one scan is performed.  If RnW is set, a separate scan
 * will be needed to collect the data which was read; the "invalue" collects
 * the posted result of a preceding operation, not the current one.
 *
 * @param dap the DAP
 * @param instr JTAG_DP_APACC (AP access) or JTAG_DP_DPACC (DP access)
 * @param reg_addr two significant bits; A[3:2]; for APACC access, the
 *	SELECT register has more addressing bits.
 * @param RnW false iff outvalue will be written to the DP or AP
 * @param outvalue points to a 32-bit (little-endian) integer
 * @param invalue NULL, or points to a 32-bit (little-endian) integer
 * @param ack points to where the three bit JTAG_ACK_* code will be stored
 */

static int adi_jtag_dp_scan(struct pmp_v5_dap *dap,
		uint8_t instr, uint8_t reg_addr, uint8_t RnW,
		uint8_t *outvalue, uint8_t *invalue, uint8_t *ack)
{
	struct arm_jtag *jtag_info = dap->jtag_info;
	struct scan_field fields[2];
	uint8_t out_addr_buf;
	int retval;

	retval = arm_jtag_set_instr(jtag_info, instr, NULL, TAP_IDLE);
	if (retval != ERROR_OK)
		return retval;

	//Coming add: for debug use
	//struct jtag_tap *tap = jtag_info->tap;
	//LOG_DEBUG("[Coming] jtag_info->tap.idcode:  0x%" SCNx32, tap->idcode);
	//LOG_DEBUG("[Coming] jtag_info->tap.ir_capture_mask:	0x%" SCNx32, tap->ir_capture_mask);
	//LOG_DEBUG("[Coming] jtag_info->tap.ir_capture_value:	0x%" SCNx32, tap->ir_capture_value);
	//LOG_DEBUG("[Coming] jtag_info->tap.abs_chain_position:	0x%" SCNx32, tap->abs_chain_position);

	/* Scan out a read or write operation using some DP or AP register.
	 * For APACC access with any sticky error flag set, this is discarded.
	 */
	fields[0].num_bits = 3;
	buf_set_u32(&out_addr_buf, 0, 3, ((reg_addr >> 1) & 0x6) | (RnW & 0x1));
	fields[0].out_value = &out_addr_buf;
	fields[0].in_value = ack;

	/* NOTE: if we receive JTAG_ACK_WAIT, the previous operation did not
	 * complete; data we write is discarded, data we read is unpredictable.
	 * When overrun detect is active, STICKYORUN is set.
	 */

	fields[1].num_bits = 32;
	fields[1].out_value = outvalue;
	fields[1].in_value = invalue;

	jtag_add_dr_scan(jtag_info->tap, 2, fields, TAP_IDLE);

	/* Add specified number of tck clocks after starting memory bus
	 * access, giving the hardware time to complete the access.
	 * They provide more time for the (MEM) AP to complete the read ...
	 * See "Minimum Response Time" for JTAG-DP, in the ADIv5 spec.
	 */


	if ((instr == PMP_JTAG_DP_APACC)
			&& ((reg_addr == PMP_AP_REG_DRW)
				|| ((reg_addr & 0xF0) == PMP_AP_REG_BD0))
			&& (dap->memaccess_tck != 0))
		jtag_add_runtest(dap->memaccess_tck,
				TAP_IDLE);

	return ERROR_OK;
}

/**
 * Scan DPACC or APACC out and in from host ordered uint32_t buffers.
 * This is exactly like adi_jtag_dp_scan(), except that endianness
 * conversions are performed (so the types of invalue and outvalue
 * must be different).
 */
static int adi_jtag_dp_scan_u32(struct pmp_v5_dap *dap,
		uint8_t instr, uint8_t reg_addr, uint8_t RnW,
		uint32_t outvalue, uint32_t *invalue, uint8_t *ack)
{
	uint8_t out_value_buf[4];
	int retval;

	buf_set_u32(out_value_buf, 0, 32, outvalue);

	retval = adi_jtag_dp_scan(dap, instr, reg_addr, RnW,
			out_value_buf, (uint8_t *)invalue, ack);
	if (retval != ERROR_OK)
		return retval;
	////LOG_DEBUG("[Coming] instr:  0x%" SCNx32, (uint32_t)instr);

	if (invalue)
		jtag_add_callback(arm_le_to_h_u32,
				(jtag_callback_data_t) invalue);

	//Coming add: for debug use
	////LOG_DEBUG("[Coming] out_value_buf[0]:  0x%" SCNx32, *out_value_buf);


	return retval;
}

/**
 * Utility to write AP registers.
 */
static inline int adi_jtag_ap_write_check(struct pmp_v5_dap *dap,
		uint8_t reg_addr, uint8_t *outvalue)
{
	return adi_jtag_dp_scan(dap, PMP_JTAG_DP_APACC, reg_addr, PMP_DPAP_WRITE,
			outvalue, NULL, NULL);
}

static int adi_jtag_scan_inout_check_u32(struct pmp_v5_dap *dap,
		uint8_t instr, uint8_t reg_addr, uint8_t RnW,
		uint32_t outvalue, uint32_t *invalue)
{
	int retval;

	/* Issue the read or write */
	retval = adi_jtag_dp_scan_u32(dap, instr, reg_addr,
			RnW, outvalue, NULL, NULL);
	if (retval != ERROR_OK)
		return retval;

	//Coming add: for debug use
	////	LOG_DEBUG("[Coming] instr:  0x%" SCNx32, (uint32_t)instr);

	/* For reads,  collect posted value; RDBUFF has no other effect.
	 * Assumes read gets acked with OK/FAULT, and CTRL_STAT says "OK".
	 */
	if ((RnW == PMP_DPAP_READ) && (invalue != NULL))
		retval = adi_jtag_dp_scan_u32(dap, PMP_JTAG_DP_DPACC,
				PMP_DP_RDBUFF, PMP_DPAP_READ, 0, invalue, &dap->ack);
	return retval;
}

static int jtagdp_transaction_endcheck(struct pmp_v5_dap *dap)
{
	int retval;
	uint32_t ctrlstat;

	/* too expensive to call keep_alive() here */

	/* Here be dragons!
	 *
	 * It is easy to be in a JTAG clock range where the target
	 * is not operating in a stable fashion. This happens
	 * for a few reasons:
	 *
	 * - the user may construct a simple test case to try to see
	 * if a higher JTAG clock works to eke out more performance.
	 * This simple case may pass, but more complex situations can
	 * fail.
	 *
	 * - The mostly works JTAG clock rate and the complete failure
	 * JTAG clock rate may be as much as 2-4x apart. This seems
	 * to be especially true on RC oscillator driven parts.
	 *
	 * So: even if calling adi_jtag_scan_inout_check_u32() multiple
	 * times here seems to "make things better here", it is just
	 * hiding problems with too high a JTAG clock.
	 *
	 * Note that even if some parts have RCLK/RTCK, that doesn't
	 * mean that RCLK/RTCK is the *correct* rate to run the JTAG
	 * interface at, i.e. RCLK/RTCK rates can be "too high", especially
	 * before the RC oscillator phase is not yet complete.
	 */

	/* Post CTRL/STAT read; discard any previous posted read value
	 * but collect its ACK status.
	 */
	retval = adi_jtag_scan_inout_check_u32(dap, PMP_JTAG_DP_DPACC,
			PMP_DP_CTRL_STAT, PMP_DPAP_READ, 0, &ctrlstat);
	if (retval != ERROR_OK)
		return retval;
	retval = jtag_execute_queue();
	if (retval != ERROR_OK)
		return retval;

	dap->ack = dap->ack & 0x7;

	/* common code path avoids calling timeval_ms() */
	if (dap->ack != PMP_JTAG_ACK_OK_FAULT) {
		long long then = timeval_ms();

		while (dap->ack != PMP_JTAG_ACK_OK_FAULT) {
			if (dap->ack == PMP_JTAG_ACK_WAIT) {
				if ((timeval_ms()-then) > 1000) {
					LOG_WARNING("Timeout (1000ms) waiting "
						"for ACK=OK/FAULT "
						"in JTAG-DP transaction - aborting");

					uint8_t ack;
					int abort_ret = jtag_ap_q_abort(dap, &ack);

					if (abort_ret != 0)
						LOG_WARNING("Abort failed : return=%d ack=%d", abort_ret, ack);

					return ERROR_JTAG_DEVICE_ERROR;
				}
			} else {
				LOG_WARNING("Invalid ACK %#x "
						"in JTAG-DP transaction",
						dap->ack);
				return ERROR_JTAG_DEVICE_ERROR;
			}

			retval = adi_jtag_scan_inout_check_u32(dap, PMP_JTAG_DP_DPACC,
					PMP_DP_CTRL_STAT, PMP_DPAP_READ, 0, &ctrlstat);
			if (retval != ERROR_OK)
				return retval;
			retval = jtag_execute_queue();
			if (retval != ERROR_OK)
				return retval;
			dap->ack = dap->ack & 0x7;
		}
	}

	////LOG_DEBUG("[Coming] DP_CTRL_STAT:  0x%" PRIx32, ctrlstat);

	/* REVISIT also STICKYCMP, for pushed comparisons (nyet used) */

	/* Check for STICKYERR and STICKYORUN */
	if (ctrlstat & (PMP_SSTICKYORUN | PMP_SSTICKYERR)) {
		LOG_DEBUG("jtag-dp: CTRL/STAT error, 0x%" PRIx32, ctrlstat);
		/* Check power to debug regions */
		if ((ctrlstat & 0xf0000000) != 0xf0000000) {
			LOG_ERROR("Debug regions are unpowered, an unexpected reset might have happened");
			return ERROR_JTAG_DEVICE_ERROR;
		} else {
			uint32_t mem_ap_csw, mem_ap_tar;

			/* Maybe print information about last intended
			 * MEM-AP access; but not if autoincrementing.
			 * *Real* CSW and TAR values are always shown.
			 */
			if (dap->ap_tar_value != (uint32_t) -1)
				LOG_DEBUG("MEM-AP Cached values: "
					"ap_bank 0x%" PRIx32
					", ap_csw 0x%" PRIx32
					", ap_tar 0x%" PRIx32,
					dap->ap_bank_value,
					dap->ap_csw_value,
					dap->ap_tar_value);

			if (ctrlstat & PMP_SSTICKYORUN)
				LOG_ERROR("JTAG-DP OVERRUN - check clock, "
					"memaccess, or reduce jtag speed");

			if (ctrlstat & PMP_SSTICKYERR)
				LOG_ERROR("JTAG-DP STICKY ERROR");

			/* Clear Sticky Error Bits */
			retval = adi_jtag_scan_inout_check_u32(dap, PMP_JTAG_DP_DPACC,
					PMP_DP_CTRL_STAT, PMP_DPAP_WRITE,
					dap->dp_ctrl_stat | PMP_SSTICKYORUN
						| PMP_SSTICKYERR, NULL);
			if (retval != ERROR_OK)
				return retval;
			retval = adi_jtag_scan_inout_check_u32(dap, PMP_JTAG_DP_DPACC,
					PMP_DP_CTRL_STAT, PMP_DPAP_READ, 0, &ctrlstat);
			if (retval != ERROR_OK)
				return retval;
			retval = jtag_execute_queue();
			if (retval != ERROR_OK)
				return retval;

			LOG_DEBUG("jtag-dp: CTRL/STAT 0x%" PRIx32, ctrlstat);

			retval = pmp_dap_queue_ap_read(dap,
					PMP_AP_REG_CSW, &mem_ap_csw);
			if (retval != ERROR_OK)
				return retval;

			retval = pmp_dap_queue_ap_read(dap,
					PMP_AP_REG_TAR, &mem_ap_tar);
			if (retval != ERROR_OK)
				return retval;

			retval = jtag_execute_queue();
			if (retval != ERROR_OK)
				return retval;
			LOG_ERROR("MEM_AP_CSW 0x%" PRIx32 ", MEM_AP_TAR 0x%"
					PRIx32, mem_ap_csw, mem_ap_tar);

		}
		retval = jtag_execute_queue();
		if (retval != ERROR_OK)
			return retval;
		return ERROR_JTAG_DEVICE_ERROR;
	}

	return ERROR_OK;
}

/*--------------------------------------------------------------------------*/

//Coming: this function is used to read JTAG ID_CODE
int jtag_dp_q_read_common(struct pmp_v5_dap *dap, unsigned reg,
		uint32_t *data)
{
	uint8_t ack;

	/* for JTAG, this is the only valid for ID_CODE register operation */
	return adi_jtag_dp_scan_u32(dap, PMP_JTAG_DP_IDCODE,
			0, PMP_DPAP_READ, 0, data, &ack);
}

static int jtag_dp_q_read(struct pmp_v5_dap *dap, unsigned reg,
		uint32_t *data)
{
	return adi_jtag_scan_inout_check_u32(dap, PMP_JTAG_DP_DPACC,
			reg, PMP_DPAP_READ, 0, data);
}

static int jtag_dp_q_write(struct pmp_v5_dap *dap, unsigned reg,
		uint32_t data)
{
	return adi_jtag_scan_inout_check_u32(dap, PMP_JTAG_DP_DPACC,
			reg, PMP_DPAP_WRITE, data, NULL);
}

/** Select the AP register bank matching bits 7:4 of reg. */
static int jtag_ap_q_bankselect(struct pmp_v5_dap *dap, unsigned reg)
{
	uint32_t select_ap_bank = reg & 0x000000F0;

	if (select_ap_bank == dap->ap_bank_value)
		return ERROR_OK;
	dap->ap_bank_value = select_ap_bank;

	select_ap_bank |= dap->ap_current;

	return jtag_dp_q_write(dap, PMP_DP_SELECT, select_ap_bank);
}

static int jtag_ap_q_read(struct pmp_v5_dap *dap, unsigned reg,
		uint32_t *data)
{
	int retval = jtag_ap_q_bankselect(dap, reg);

	if (retval != ERROR_OK)
		return retval;

	return adi_jtag_scan_inout_check_u32(dap, PMP_JTAG_DP_APACC, reg,
			PMP_DPAP_READ, 0, data);
}

static int jtag_ap_q_write(struct pmp_v5_dap *dap, unsigned reg,
		uint32_t data)
{
	uint8_t out_value_buf[4];

	int retval = jtag_ap_q_bankselect(dap, reg);
	if (retval != ERROR_OK)
		return retval;

	buf_set_u32(out_value_buf, 0, 32, data);

	return adi_jtag_ap_write_check(dap, reg, out_value_buf);
}

static int jtag_ap_q_abort(struct pmp_v5_dap *dap, uint8_t *ack)
{
	/* for JTAG, this is the only valid ABORT register operation */
	return adi_jtag_dp_scan_u32(dap, PMP_JTAG_DP_ABORT,
			0, PMP_DPAP_WRITE, 1, NULL, ack);
}

static int jtag_dp_run(struct pmp_v5_dap *dap)
{
	return jtagdp_transaction_endcheck(dap);
}

/* FIXME don't export ... just initialize as
 * part of DAP setup
*/
const struct pmp_dap_ops pmp_jtag_dp_ops = {
	.is_swd				 = false,	//coming add
	.queue_dp_read       = jtag_dp_q_read,
	.queue_dp_write      = jtag_dp_q_write,
	.queue_ap_read       = jtag_ap_q_read,
	.queue_ap_write      = jtag_ap_q_write,
	.queue_ap_abort      = jtag_ap_q_abort,
	.run                 = jtag_dp_run,
};


static const uint8_t swd2jtag_bitseq[] = {
	/* More than 50 TCK/SWCLK cycles with TMS/SWDIO high,
	 * putting both JTAG and SWD logic into reset state.
	 */
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	/* Switching equence disables SWD and enables JTAG
	 * NOTE: bits in the DP's IDCODE can expose the need for
	 * the old/deprecated sequence (0xae 0xde).
	 */
	0x3c, 0xe7,
	/* At least 50 TCK/SWCLK cycles with TMS/SWDIO high,
	 * putting both JTAG and SWD logic into reset state.
	 * NOTE:  some docs say "at least 5".
	 */
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

/** Put the debug link into JTAG mode, if the target supports it.
 * The link's initial mode may be either SWD or JTAG.
 *
 * @param target Enters JTAG mode (if possible).
 *
 * Note that targets implemented with SW-DP do not support JTAG, and
 * that some targets which could otherwise support it may have been
 * configured to disable JTAG signaling
 *
 * @return ERROR_OK or else a fault code.
 */
#if 0		//coming: this function has been defined in adi_v5_jtag.c
int dap_to_jtag(struct target *target)
{
	int retval;

	LOG_DEBUG("Enter JTAG mode");

	/* REVISIT it's nasty to need to make calls to a "jtag"
	 * subsystem if the link isn't in JTAG mode...
	 */

	retval = jtag_add_tms_seq(8 * sizeof(swd2jtag_bitseq),
			swd2jtag_bitseq, TAP_RESET);
	if (retval == ERROR_OK)
		retval = jtag_execute_queue();

	/* REVISIT set up the DAP's ops vector for JTAG mode. */

	return retval;
}

#endif


//=============================================================
//=============================================================

/* ADI Specification requires at least 10 bits used for TAR autoincrement  */

/*
	uint32_t tar_block_size(uint32_t address)
	Return the largest block starting at address that does not cross a tar block size alignment boundary
*/
static uint32_t pmp_max_tar_block_size(uint32_t tar_autoincr_block, uint32_t address)
{
	return tar_autoincr_block - ((tar_autoincr_block - 1) & address);
}

/***************************************************************************
 *                                                                         *
 * DP and MEM-AP register access through APACC and DPACC                 *
 *                                                                         *
***************************************************************************/

/**
 * Select one of the APs connected to the specified DAP.  The
 * selection is implicitly used with future AP transactions.
 * This is a NOP if the specified AP is already selected.
 *
 * @param dap The DAP
 * @param apsel Number of the AP to (implicitly) use with further
 *	transactions.  This normally identifies a MEM-AP.
 */
void pmp_dap_ap_select(struct pmp_v5_dap *dap, uint8_t ap)
{
	uint32_t new_ap = (ap << 24) & 0xFF000000;

	if (new_ap != dap->ap_current) {
		dap->ap_current = new_ap;
		/* Switching AP invalidates cached values.
		 * Values MUST BE UPDATED BEFORE AP ACCESS.
		 */
		dap->ap_bank_value = -1;
		dap->ap_csw_value = -1;
		dap->ap_tar_value = -1;
	}
}

static int pmp_dap_setup_accessport_csw(struct pmp_v5_dap *dap, uint32_t csw)
{
	csw = csw | PMP_CSW_DBGSWENABLE | PMP_CSW_MASTER_DEBUG | PMP_CSW_HPROT |
		dap->apcsw[dap->ap_current >> 24];

	if (csw != dap->ap_csw_value) {
		/* LOG_DEBUG("DAP: Set CSW %x",csw); */
		int retval = pmp_dap_queue_ap_write(dap, PMP_AP_REG_CSW, csw);
		if (retval != ERROR_OK)
			return retval;
		dap->ap_csw_value = csw;
	}
	return ERROR_OK;
}

static int pmp_dap_setup_accessport_tar(struct pmp_v5_dap *dap, uint32_t tar)
{
	if (tar != dap->ap_tar_value || dap->ap_csw_value & PMP_CSW_ADDRINC_MASK) {
		/* LOG_DEBUG("DAP: Set TAR %x",tar); */
		int retval = pmp_dap_queue_ap_write(dap, PMP_AP_REG_TAR, tar);
		if (retval != ERROR_OK)
			return retval;
		dap->ap_tar_value = tar;
	}
	return ERROR_OK;
}

/**
 * Queue transactions setting up transfer parameters for the
 * currently selected MEM-AP.
 *
 * Subsequent transfers using registers like MEM_AP_REG_DRW or MEM_AP_REG_BD2
 * initiate data reads or writes using memory or peripheral addresses.
 * If the CSW is configured for it, the TAR may be automatically
 * incremented after each transfer.
 *
 * @param ap The MEM-AP.
 * @param csw MEM-AP Control/Status Word (CSW) register to assign.  If this
 *	matches the cached value, the register is not changed.
 * @param tar MEM-AP Transfer Address Register (TAR) to assign.  If this
 *	matches the cached address, the register is not changed.
 *
 * @return ERROR_OK if the transaction was properly queued, else a fault code.
 */
int pmp_dap_setup_accessport(struct pmp_v5_dap *dap, uint32_t csw, uint32_t tar)
{
	int retval;
	retval = pmp_dap_setup_accessport_csw(dap, csw);
	if (retval != ERROR_OK)
		return retval;
	retval = pmp_dap_setup_accessport_tar(dap, tar);
	if (retval != ERROR_OK)
		return retval;
	return ERROR_OK;
}

/**
 * Asynchronous (queued) read of a word from memory or a system register.
 *
 * @param ap The MEM-AP to access.
 * @param address Address of the 32-bit word to read; it must be
 *	readable by the currently selected MEM-AP.
 * @param value points to where the word will be stored when the
 *	transaction queue is flushed (assuming no errors).
 *
 * @return ERROR_OK for success.  Otherwise a fault code.
 */
int pmp_mem_ap_read_u32(struct pmp_v5_dap *dap, uint32_t address,
		uint32_t *value)
{
	int retval;

	/* Use banked addressing (REG_BDx) to avoid some link traffic
	 * (updating TAR) when reading several consecutive addresses.
	 */
	retval = pmp_dap_setup_accessport(dap, PMP_CSW_32BIT | PMP_CSW_ADDRINC_OFF,
			address & 0xFFFFFFF0);
	if (retval != ERROR_OK)
		return retval;

	return pmp_dap_queue_ap_read(dap, PMP_AP_REG_BD0 | (address & 0xC), value);
}



/**
 * Synchronous read of a word from memory or a system register.
 * As a side effect, this flushes any queued transactions.
 *
 * @param ap The MEM-AP to access.
 * @param address Address of the 32-bit word to read; it must be
 *	readable by the currently selected MEM-AP.
 * @param value points to where the result will be stored.
 *
 * @return ERROR_OK for success; *value holds the result.
 * Otherwise a fault code.
 */
int pmp_mem_ap_read_atomic_u32(struct pmp_v5_dap *dap, uint32_t address,
		uint32_t *value)
{
	int retval;

	retval = pmp_mem_ap_read_u32(dap, address, value);
	if (retval != ERROR_OK)
		return retval;

	return pmp_dap_run(dap);
}

/**
 * Asynchronous (queued) write of a word to memory or a system register.
 *
 * @param ap The MEM-AP to access.
 * @param address Address to be written; it must be writable by
 *	the currently selected MEM-AP.
 * @param value Word that will be written to the address when transaction
 *	queue is flushed (assuming no errors).
 *
 * @return ERROR_OK for success.  Otherwise a fault code.
 */
int pmp_mem_ap_write_u32(struct pmp_v5_dap *dap, uint32_t address,
		uint32_t value)
{
	int retval;

	/* Use banked addressing (REG_BDx) to avoid some link traffic
	 * (updating TAR) when writing several consecutive addresses.
	 */
	retval = pmp_dap_setup_accessport(dap, PMP_CSW_32BIT | PMP_CSW_ADDRINC_OFF,
			address & 0xFFFFFFF0);
	if (retval != ERROR_OK)
		return retval;

	return pmp_dap_queue_ap_write(dap, PMP_AP_REG_BD0 | (address & 0xC),
			value);
}

/**
 * Synchronous write of a word to memory or a system register.
 * As a side effect, this flushes any queued transactions.
 *
 * @param ap The MEM-AP to access.
 * @param address Address to be written; it must be writable by
 *	the currently selected MEM-AP.
 * @param value Word that will be written.
 *
 * @return ERROR_OK for success; the data was written.  Otherwise a fault code.
 */
int pmp_mem_ap_write_atomic_u32(struct pmp_v5_dap *dap, uint32_t address,
		uint32_t value)
{
	int retval = pmp_mem_ap_write_u32(dap, address, value);

	if (retval != ERROR_OK)
		return retval;

	return pmp_dap_run(dap);
}

//==============================================================================
//======================= Coming add for displaying the debug reg data =========================
int pmp_mem_ap_read_dbg(struct pmp_v5_dap *dap, uint8_t *buffer, uint32_t size, uint32_t count,
		uint32_t adr)
{
	size_t nbytes = size * count;
	uint32_t address = adr;
	
	if ((size != 4)&&(size != 2)&&(size != 1))
		return ERROR_TARGET_UNALIGNED_ACCESS;

	if (dap->unaligned_access_bad && (adr % size != 0))
		return ERROR_TARGET_UNALIGNED_ACCESS;

	/* Allocate buffer to hold the sequence of DRW reads that will be made. This is a significant
	 * over-allocation if packed transfers are going to be used, but determining the real need at
	 * this point would be messy. */
	uint32_t *read_buf = malloc(count * sizeof(uint32_t));
	uint32_t *read_ptr = read_buf;
	if (read_buf == NULL) {
		LOG_ERROR("Failed to allocate read buffer");
		return ERROR_FAIL;
	}

	/* Replay loop to populate caller's buffer from the correct word and byte lane */
	while (nbytes > 0) {
		switch (size) {
			case 4:
				*buffer++ = *read_ptr >> 8 * (3 - (address++ & 3));
				*buffer++ = *read_ptr >> 8 * (3 - (address++ & 3));
			case 2:
				*buffer++ = *read_ptr >> 8 * (3 - (address++ & 3));
			case 1:
				*buffer++ = *read_ptr >> 8 * (3 - (address++ & 3));
				
			#if 0
			case 4:
				*buffer++ = *read_ptr >> 8 * (address++ & 3);
				*buffer++ = *read_ptr >> 8 * (address++ & 3);
			case 2:
				*buffer++ = *read_ptr >> 8 * (address++ & 3);
			case 1:
				*buffer++ = *read_ptr >> 8 * (address++ & 3);
			#endif
		}

		read_ptr++;
		nbytes -= size;
	}

	free(read_buf);
	return ERROR_OK;
}



int pmp_mem_ap_read_atomic_u32_dbg(struct pmp_v5_dap *dap, uint8_t *buffer, uint32_t address,
		uint32_t *value)
{
	int retval;

	retval = pmp_mem_ap_read_u32(dap, address, value);
	if (retval != ERROR_OK)
		return retval;

	//return dap_run(dap);	//coming comment
	retval = pmp_dap_run(dap);
	return pmp_mem_ap_read_dbg(dap, buffer, 4, 1, address);	//coming: the size will needed to modified
}


int pmp_mem_ap_write_atomic_u32_dbg(struct pmp_v5_dap *dap, const uint8_t *buffer, uint32_t address,
		uint32_t value)
{
	int retval;

	retval = pmp_mem_ap_write_u32(dap, address, value);
	if (retval != ERROR_OK)
		return retval;

	return pmp_dap_run(dap);	//coming comment
}

//=========================================================================
//=========================================================================



/**
 * Synchronous write of a block of memory, using a specific access size.
 *
 * @param ap The MEM-AP to access.
 * @param buffer The data buffer to write. No particular alignment is assumed.
 * @param size Which access size to use, in bytes. 1, 2 or 4.
 * @param count The number of writes to do (in size units, not bytes).
 * @param address Address to be written; it must be writable by the currently selected MEM-AP.
 * @param addrinc Whether the target address should be increased for each write or not. This
 *  should normally be true, except when writing to e.g. a FIFO.
 * @return ERROR_OK on success, otherwise an error code.
 */
int pmp_mem_ap_write(struct pmp_v5_dap *dap, const uint8_t *buffer, uint32_t size, uint32_t count,
		uint32_t address, bool addrinc)
{
	size_t nbytes = size * count;
	const uint32_t csw_addrincr = addrinc ? PMP_CSW_ADDRINC_SINGLE : PMP_CSW_ADDRINC_OFF;
	uint32_t csw_size;
	uint32_t addr_xor;
	int retval;

	/* TI BE-32 Quirks mode:
	 * Writes on big-endian TMS570 behave very strangely. Observed behavior:
	 *   size   write address   bytes written in order
	 *   4      TAR ^ 0         (val >> 24), (val >> 16), (val >> 8), (val)
	 *   2      TAR ^ 2         (val >> 8), (val)
	 *   1      TAR ^ 3         (val)
	 * For example, if you attempt to write a single byte to address 0, the processor
	 * will actually write a byte to address 3.
	 *
	 * To make writes of size < 4 work as expected, we xor a value with the address before
	 * setting the TAP, and we set the TAP after every transfer rather then relying on
	 * address increment. */

	if (size == 4) {
		csw_size = PMP_CSW_32BIT;
		addr_xor = 0;
	} else if (size == 2) {
		csw_size = PMP_CSW_16BIT;
		addr_xor = dap->ti_be_32_quirks ? 2 : 0;
	} else if (size == 1) {
		csw_size = PMP_CSW_8BIT;
		addr_xor = dap->ti_be_32_quirks ? 3 : 0;
	} else {
		return ERROR_TARGET_UNALIGNED_ACCESS;
	}

	if (dap->unaligned_access_bad && (address % size != 0))
		return ERROR_TARGET_UNALIGNED_ACCESS;

	retval = pmp_dap_setup_accessport_tar(dap, address ^ addr_xor);
	if (retval != ERROR_OK)
		return retval;

	////uint32_t drw_data = 0;
	////int i = 0;

	LOG_DEBUG("[Coming] size = (%d)", size);
	LOG_DEBUG("[Coming] count = (%d)", count);
	LOG_DEBUG("[Coming] nbytes = (%zd)", nbytes);
	////nbytes = 1000;		//Coming add 
	while (nbytes > 0) {
		uint32_t this_size = size;

		/* Select packed transfer if possible */
		if (addrinc && dap->packed_transfers && nbytes >= 4
				&& pmp_max_tar_block_size(dap->tar_autoincr_block, address) >= 4) {
			this_size = 4;
			retval = pmp_dap_setup_accessport_csw(dap, csw_size | PMP_CSW_ADDRINC_PACKED);
		} else {
			retval = pmp_dap_setup_accessport_csw(dap, csw_size | csw_addrincr);
		}

		if (retval != ERROR_OK)
			break;
/*
if(i < 4){

		LOG_DEBUG("[Coming] address = (0x%x)", address);
		LOG_DEBUG("[Coming] invalue = (0x%x)", *buffer);
}
*/

		/* How many source bytes each transfer will consume, and their location in the DRW,
		 * depends on the type of transfer and alignment. See ARM document IHI0031C. */
		uint32_t outvalue = 0;
		if (dap->ti_be_32_quirks) {
			switch (this_size) {
			case 4:
				outvalue |= (uint32_t)*buffer++ << 8 * (3 ^ (address++ & 3) ^ addr_xor);
				outvalue |= (uint32_t)*buffer++ << 8 * (3 ^ (address++ & 3) ^ addr_xor);
				outvalue |= (uint32_t)*buffer++ << 8 * (3 ^ (address++ & 3) ^ addr_xor);
				outvalue |= (uint32_t)*buffer++ << 8 * (3 ^ (address++ & 3) ^ addr_xor);
				break;
			case 2:
				outvalue |= (uint32_t)*buffer++ << 8 * (1 ^ (address++ & 3) ^ addr_xor);
				outvalue |= (uint32_t)*buffer++ << 8 * (1 ^ (address++ & 3) ^ addr_xor);
				break;
			case 1:
				outvalue |= (uint32_t)*buffer++ << 8 * (0 ^ (address++ & 3) ^ addr_xor);
				break;
			}
		} else {
			switch (this_size) {
			case 4:
				outvalue |= (uint32_t)*buffer++ << 8 * (address++ & 3);
				outvalue |= (uint32_t)*buffer++ << 8 * (address++ & 3);
			case 2:
				outvalue |= (uint32_t)*buffer++ << 8 * (address++ & 3);
			case 1:
				outvalue |= (uint32_t)*buffer++ << 8 * (address++ & 3);
			}
		}

		nbytes -= this_size;
/*
if(i < 4){
		////LOG_DEBUG("[Coming] address = (0x%x)", address);
		////LOG_DEBUG("[Coming] invalue = (0x%x)", *buffer);
		LOG_DEBUG("[Coming] outvalue = (0x%x)", outvalue);
		////LOG_DEBUG("[Coming] nbytes = (0x%zx)", nbytes);
		////i++;
}
*/
		retval = pmp_dap_queue_ap_write(dap, PMP_AP_REG_DRW, outvalue);
		if (retval != ERROR_OK)
			break;
/*
	if(i < 4){	
			////retval = pmp_dap_run(dap);
			pmp_dap_queue_ap_read(dap, pmp_AP_REG_DRW, &drw_data);
			retval = pmp_dap_run(dap);
			LOG_DEBUG("[Coming] drw_data = (0x%x)", drw_data);
			i++;
	}
*/
			/* Rewrite TAR if it wrapped or we're xoring addresses */
		if (addrinc && (addr_xor || (address % dap->tar_autoincr_block < size && nbytes > 0))) {
			retval = pmp_dap_setup_accessport_tar(dap, address ^ addr_xor);
		////LOG_DEBUG("[Coming] ==============================================");
			if (retval != ERROR_OK)
				break;
		}

	}

	/* REVISIT: Might want to have a queued version of this function that does not run. */
	if (retval == ERROR_OK)
		retval = pmp_dap_run(dap);

	if (retval != ERROR_OK) {
		uint32_t tar;
		if (pmp_dap_queue_ap_read(dap, PMP_AP_REG_TAR, &tar) == ERROR_OK
				&& pmp_dap_run(dap) == ERROR_OK)
			LOG_ERROR("Failed to write memory at 0x%08"PRIx32, tar);
		else
			LOG_ERROR("Failed to write memory and, additionally, failed to find out where");
	}

	return retval;
}

/**
 * Synchronous read of a block of memory, using a specific access size.
 *
 * @param ap The MEM-AP to access.
 * @param buffer The data buffer to receive the data. No particular alignment is assumed.
 * @param size Which access size to use, in bytes. 1, 2 or 4.
 * @param count The number of reads to do (in size units, not bytes).
 * @param address Address to be read; it must be readable by the currently selected MEM-AP.
 * @param addrinc Whether the target address should be increased after each read or not. This
 *  should normally be true, except when reading from e.g. a FIFO.
 * @return ERROR_OK on success, otherwise an error code.
 */
int pmp_mem_ap_read(struct pmp_v5_dap *dap, uint8_t *buffer, uint32_t size, uint32_t count,
		uint32_t adr, bool addrinc)
{
	size_t nbytes = size * count;
	const uint32_t csw_addrincr = addrinc ? PMP_CSW_ADDRINC_SINGLE : PMP_CSW_ADDRINC_OFF;
	uint32_t csw_size;
	uint32_t address = adr;
	int retval;

	/* TI BE-32 Quirks mode:
	 * Reads on big-endian TMS570 behave strangely differently than writes.
	 * They read from the physical address requested, but with DRW byte-reversed.
	 * For example, a byte read from address 0 will place the result in the high bytes of DRW.
	 * Also, packed 8-bit and 16-bit transfers seem to sometimes return garbage in some bytes,
	 * so avoid them. */

	if (size == 4)
		csw_size = PMP_CSW_32BIT;
	else if (size == 2)
		csw_size = PMP_CSW_16BIT;
	else if (size == 1)
		csw_size = PMP_CSW_8BIT;
	else
		return ERROR_TARGET_UNALIGNED_ACCESS;

	if (dap->unaligned_access_bad && (adr % size != 0))
		return ERROR_TARGET_UNALIGNED_ACCESS;

	/* Allocate buffer to hold the sequence of DRW reads that will be made. This is a significant
	 * over-allocation if packed transfers are going to be used, but determining the real need at
	 * this point would be messy. */
	uint32_t *read_buf = malloc(count * sizeof(uint32_t));
	uint32_t *read_ptr = read_buf;
	if (read_buf == NULL) {
		LOG_ERROR("Failed to allocate read buffer");
		return ERROR_FAIL;
	}

	retval = pmp_dap_setup_accessport_tar(dap, address);
	if (retval != ERROR_OK) {
		free(read_buf);
		return retval;
	}

	/* Queue up all reads. Each read will store the entire DRW word in the read buffer. How many
	 * useful bytes it contains, and their location in the word, depends on the type of transfer
	 * and alignment. */
	while (nbytes > 0) {
		uint32_t this_size = size;

		/* Select packed transfer if possible */
		if (addrinc && dap->packed_transfers && nbytes >= 4
				&& pmp_max_tar_block_size(dap->tar_autoincr_block, address) >= 4) {
			this_size = 4;
			retval = pmp_dap_setup_accessport_csw(dap, csw_size | PMP_CSW_ADDRINC_PACKED);
		} else {
			retval = pmp_dap_setup_accessport_csw(dap, csw_size | csw_addrincr);
		}
		if (retval != ERROR_OK)
			break;

		retval = pmp_dap_queue_ap_read(dap, PMP_AP_REG_DRW, read_ptr++);
		if (retval != ERROR_OK)
			break;

		nbytes -= this_size;
		address += this_size;

		/* Rewrite TAR if it wrapped */
		if (addrinc && address % dap->tar_autoincr_block < size && nbytes > 0) {
			retval = pmp_dap_setup_accessport_tar(dap, address);
			if (retval != ERROR_OK)
				break;
		}
	}

	if (retval == ERROR_OK)
		retval = pmp_dap_run(dap);

	/* Restore state */
	address = adr;
	nbytes = size * count;
	read_ptr = read_buf;

	/* If something failed, read TAR to find out how much data was successfully read, so we can
	 * at least give the caller what we have. */
	if (retval != ERROR_OK) {
		uint32_t tar;
		if (pmp_dap_queue_ap_read(dap, PMP_AP_REG_TAR, &tar) == ERROR_OK
				&& pmp_dap_run(dap) == ERROR_OK) {
			LOG_ERROR("Failed to read memory at 0x%08"PRIx32, tar);
			if (nbytes > tar - address)
				nbytes = tar - address;
		} else {
			LOG_ERROR("Failed to read memory and, additionally, failed to find out where");
			nbytes = 0;
		}
	}

	/* Replay loop to populate caller's buffer from the correct word and byte lane */
	while (nbytes > 0) {
		uint32_t this_size = size;

		if (addrinc && dap->packed_transfers && nbytes >= 4
				&& pmp_max_tar_block_size(dap->tar_autoincr_block, address) >= 4) {
			this_size = 4;
		}

		if (dap->ti_be_32_quirks) {
			switch (this_size) {
			case 4:
				*buffer++ = *read_ptr >> 8 * (3 - (address++ & 3));
				*buffer++ = *read_ptr >> 8 * (3 - (address++ & 3));
			case 2:
				*buffer++ = *read_ptr >> 8 * (3 - (address++ & 3));
			case 1:
				*buffer++ = *read_ptr >> 8 * (3 - (address++ & 3));
			}
		} else {
			switch (this_size) {
			case 4:
				*buffer++ = *read_ptr >> 8 * (address++ & 3);
				*buffer++ = *read_ptr >> 8 * (address++ & 3);
			case 2:
				*buffer++ = *read_ptr >> 8 * (address++ & 3);
			case 1:
				*buffer++ = *read_ptr >> 8 * (address++ & 3);
			}
		}

		read_ptr++;
		nbytes -= this_size;
	}

	free(read_buf);
	return retval;
}

/*--------------------------------------------------------------------*/
/*          Wrapping function with selection of AP                    */
/*--------------------------------------------------------------------*/
int pmp_mem_ap_sel_read_u32(struct pmp_v5_dap *swjdp, uint8_t ap,
		uint32_t address, uint32_t *value)
{
	pmp_dap_ap_select(swjdp, ap);
	return pmp_mem_ap_read_u32(swjdp, address, value);
}

int pmp_mem_ap_sel_write_u32(struct pmp_v5_dap *swjdp, uint8_t ap,
		uint32_t address, uint32_t value)
{
	pmp_dap_ap_select(swjdp, ap);
	return pmp_mem_ap_write_u32(swjdp, address, value);
}

int pmp_mem_ap_sel_read_atomic_u32(struct pmp_v5_dap *swjdp, uint8_t ap,
		uint32_t address, uint32_t *value)
{
	pmp_dap_ap_select(swjdp, ap);
	return pmp_mem_ap_read_atomic_u32(swjdp, address, value);
}

int pmp_mem_ap_sel_write_atomic_u32(struct pmp_v5_dap *swjdp, uint8_t ap,
		uint32_t address, uint32_t value)
{
	pmp_dap_ap_select(swjdp, ap);
	return pmp_mem_ap_write_atomic_u32(swjdp, address, value);
}

int pmp_mem_ap_sel_read_buf(struct pmp_v5_dap *swjdp, uint8_t ap,
		uint8_t *buffer, uint32_t size, uint32_t count, uint32_t address)
{
	pmp_dap_ap_select(swjdp, ap);
	return pmp_mem_ap_read(swjdp, buffer, size, count, address, true);
}

int pmp_mem_ap_sel_write_buf(struct pmp_v5_dap *swjdp, uint8_t ap,
		const uint8_t *buffer, uint32_t size, uint32_t count, uint32_t address)
{
	pmp_dap_ap_select(swjdp, ap);
	return pmp_mem_ap_write(swjdp, buffer, size, count, address, true);
}

int pmp_mem_ap_sel_read_buf_noincr(struct pmp_v5_dap *swjdp, uint8_t ap,
		uint8_t *buffer, uint32_t size, uint32_t count, uint32_t address)
{
	pmp_dap_ap_select(swjdp, ap);
	return pmp_mem_ap_read(swjdp, buffer, size, count, address, false);
}

int pmp_mem_ap_sel_write_buf_noincr(struct pmp_v5_dap *swjdp, uint8_t ap,
		const uint8_t *buffer, uint32_t size, uint32_t count, uint32_t address)
{
	pmp_dap_ap_select(swjdp, ap);
	return pmp_mem_ap_write(swjdp, buffer, size, count, address, false);
}

/*--------------------------------------------------------------------------*/


#define PMP_DAP_POWER_DOMAIN_TIMEOUT (10)

/* FIXME don't import ... just initialize as
 * part of DAP transport setup
*/

/*--------------------------------------------------------------------------*/

/**
 * Create a new DAP
 */
 #if 0
struct pmp_v5_dap *pmp_dap_init(void)
{
	struct pmp_v5_dap *dap = calloc(1, sizeof(struct pmp_v5_dap));
	int i;
	/* Set up with safe defaults */
	for (i = 0; i <= 255; i++) {
		dap->ap[i].dap = dap;
		dap->ap[i].ap_num = i;
		/* memaccess_tck max is 255 */
		dap->ap[i].memaccess_tck = 255;
		/* Number of bits for tar autoincrement, impl. dep. at least 10 */
		dap->ap[i].tar_autoincr_block = (1<<10);
	}
	INIT_LIST_HEAD(&dap->cmd_journal);
	return dap;
}

#endif
/**
 * Initialize a DAP.  This sets up the power domains, prepares the DP
 * for further use, and arranges to use AP #0 for all AP operations
 * until dap_ap-select() changes that policy.
 *
 * @param dap The DAP being initialized.
 *
 * @todo Rename this.  We also need an initialization scheme which account
 * for SWD transports not just JTAG; that will need to address differences
 * in layering.  (JTAG is useful without any debug target; but not SWD.)
 * And this may not even use an AHB-AP ... e.g. DAP-Lite uses an APB-AP.
 */


////extern const struct pmp_dap_ops pmp_jtag_dp_ops;	//coming add

int pmp_ahbap_debugport_init(struct pmp_v5_dap *dap)
{
	/* check that we support packed transfers */
	uint32_t csw, cfg;
	int retval;
	LOG_DEBUG(" ");
	/* JTAG-DP or SWJ-DP, in JTAG mode
	 * ... for SWD mode this is patched as part
	 * of link switchover
	 * FIXME: This should already be setup by the respective transport specific DAP creation.
	 */
	if (!dap->ops)
		dap->ops = &pmp_jtag_dp_ops;	//dap->ops = &pmp_jtag_dp_ops;

	/* Default MEM-AP setup.
	 *
	 * REVISIT AP #0 may be an inappropriate default for this.
	 * Should we probe, or take a hint from the caller?
	 * Presumably we can ignore the possibility of multiple APs.
	 */
	dap->ap_current = !0;
	pmp_dap_ap_select(dap, 0);
	dap->last_read = NULL;

	for (size_t i = 0; i < 10; i++) {
		/* DP initialization */

		dap->dp_bank_value = 0;

		retval = pmp_dap_queue_dp_write(dap, PMP_DP_CTRL_STAT, PMP_SSTICKYERR);
		if (retval != ERROR_OK)
			continue;

		retval = pmp_dap_queue_dp_read(dap, PMP_DP_CTRL_STAT, NULL);
		if (retval != ERROR_OK)
			continue;

		dap->dp_ctrl_stat = PMP_CDBGPWRUPREQ | PMP_CSYSPWRUPREQ;
		retval = pmp_dap_queue_dp_write(dap, PMP_DP_CTRL_STAT, dap->dp_ctrl_stat);
		if (retval != ERROR_OK)
			continue;

		/* Check that we have debug power domains activated */
		LOG_DEBUG("DAP: wait CDBGPWRUPACK");
		retval = pmp_dap_dp_poll_register(dap, PMP_DP_CTRL_STAT,
					      PMP_CDBGPWRUPACK, PMP_CDBGPWRUPACK,
					      PMP_DAP_POWER_DOMAIN_TIMEOUT);
		if (retval != ERROR_OK)
			continue;

		LOG_DEBUG("DAP: wait CSYSPWRUPACK");
		retval = pmp_dap_dp_poll_register(dap, PMP_DP_CTRL_STAT,
					      PMP_CSYSPWRUPACK, PMP_CSYSPWRUPACK,
					      PMP_DAP_POWER_DOMAIN_TIMEOUT);
		if (retval != ERROR_OK)
			continue;

		retval = pmp_dap_queue_dp_read(dap, PMP_DP_CTRL_STAT, NULL);
		if (retval != ERROR_OK)
			continue;

		/* With debug power on we can activate OVERRUN checking */
		dap->dp_ctrl_stat = PMP_CDBGPWRUPREQ | PMP_CSYSPWRUPREQ | PMP_CORUNDETECT;
		retval = pmp_dap_queue_dp_write(dap, PMP_DP_CTRL_STAT, dap->dp_ctrl_stat);
		if (retval != ERROR_OK)
			continue;
		
		retval = pmp_dap_queue_dp_read(dap, PMP_DP_CTRL_STAT, NULL);
		if (retval != ERROR_OK)
			continue;

		retval = pmp_dap_setup_accessport(dap, PMP_CSW_8BIT | PMP_CSW_ADDRINC_PACKED, 0);
		if (retval != ERROR_OK)
			continue;

		retval = pmp_dap_queue_ap_read(dap, PMP_AP_REG_CSW, &csw);
		if (retval != ERROR_OK)
			continue;

		retval = pmp_dap_queue_ap_read(dap, PMP_AP_REG_CFG, &cfg);
		if (retval != ERROR_OK)
			continue;

		retval = pmp_dap_run(dap);
		if (retval != ERROR_OK)
			continue;

		break;
	}

	if (retval != ERROR_OK)
		return retval;
	LOG_DEBUG("[Coming] pmp_AP_REG_CSW:  0x%" SCNx32, csw);
	LOG_DEBUG("[Coming] pmp_AP_REG_CFG:  0x%" SCNx32, cfg);

	if (csw & PMP_CSW_ADDRINC_PACKED)
		dap->packed_transfers = true;
	else
		dap->packed_transfers = false;

	/* Packed transfers on TI BE-32 processors do not work correctly in
	 * many cases. */
	if (dap->ti_be_32_quirks)
		dap->packed_transfers = false;

	LOG_DEBUG("MEM_AP Packed Transfers: %s",
			dap->packed_transfers ? "enabled" : "disabled");

	/* The ARM ADI spec leaves implementation-defined whether unaligned
	 * memory accesses work, only work partially, or cause a sticky error.
	 * On TI BE-32 processors, reads seem to return garbage in some bytes
	 * and unaligned writes seem to cause a sticky error.
	 * TODO: it would be nice to have a way to detect whether unaligned
	 * operations are supported on other processors. */
	dap->unaligned_access_bad = dap->ti_be_32_quirks;

	LOG_DEBUG("MEM_AP CFG: large data %d, long address %d, big-endian %d",
			!!(cfg & 0x04), !!(cfg & 0x02), !!(cfg & 0x01));

	return ERROR_OK;
}

#if 0

/* CID interpretation -- see ARM IHI 0029B section 3
 * and ARM IHI 0031A table 13-3.
 */
static const char *class_description[16] = {
	"Reserved", "ROM table", "Reserved", "Reserved",
	"Reserved", "Reserved", "Reserved", "Reserved",
	"Reserved", "CoreSight component", "Reserved", "Peripheral Test Block",
	"Reserved", "OptimoDE DESS",
	"Generic IP component", "PrimeCell or System component"
};


static bool is_dap_cid_ok(uint32_t cid3, uint32_t cid2, uint32_t cid1, uint32_t cid0)
{
	return cid3 == 0xb1 && cid2 == 0x05
			&& ((cid1 & 0x0f) == 0) && cid0 == 0x0d;
}

#endif

/*
 * This function checks the ID for each access port to find the requested Access Port type
 */
int pmp_dap_find_ap(struct pmp_v5_dap *dap, enum pmp_ap_type type_to_find, uint8_t *ap_num_out)
{
	int ap;
	int ahb_ap_cnt = 0;		//Coming: add for find the PMP AHB_AP
	
	/* Maximum AP number is 255 since the SELECT register is 8 bits */
	for (ap = 0; ap <= 255; ap++) {

		/* read the IDR register of the Access Port */
		uint32_t id_val = 0;
		pmp_dap_ap_select(dap, ap);

		int retval = pmp_dap_queue_ap_read(dap, PMP_AP_REG_IDR, &id_val);
		if (retval != ERROR_OK)
			return retval;
		retval = pmp_dap_run(dap);
		if(ap < 10){
			////LOG_DEBUG("[Coming] AP Index: (%d)", ap);
			LOG_DEBUG("[Coming] PMP_AP_REG_IDR: [0x%08" PRIx32 "]", id_val);

		}

		/* IDR bits:
		 * 31-28 : Revision
		 * 27-24 : JEDEC bank (0x4 for ARM)
		 * 23-17 : JEDEC code (0x3B for ARM)
		 * 16    : Mem-AP
		 * 15-8  : Reserved
		 *  7-0  : AP Identity (1=AHB-AP0 2=AHB-AP1 0x10=JTAG-AP)
		 */

		/* Reading register for a non-existant AP should not cause an error,
		 * but just to be sure, try to continue searching if an error does happen.
		 */
		if ((retval == ERROR_OK) &&                  /* Register read success */
			((id_val & 0x0FFF0000) == 0x04770000) && /* Jedec codes match */
			((id_val & 0xFF) == type_to_find)) {     /* type matches*/
			if (ap < 5){
			LOG_DEBUG("Found %s at AP index: %d [IDR=0x%08" PRIX32 "]",
						(type_to_find == PMP_AP_TYPE_AHB_AP)  	? "AHB-AP"  :
						(type_to_find == PMP_AP_TYPE_APB_AP)  	? "APB-AP"  :	"Unknown", 
						ap, id_val);
			}
			else {
			LOG_DEBUG("Found %s at AP index: %d [IDR=0x%08" PRIX32 "]",
						(type_to_find == PMP_AP_TYPE_APB_AP)  	? "APB-AP"  : 
						(type_to_find == PMP_AP_TYPE_AHB_AP2)   ? "AHB-AP2" :	"Unknown",
						ap, id_val);
			}
			*ap_num_out = ap;
			
			//Coming: add for find the PMP AHB_AP
			ahb_ap_cnt++;
			if(ahb_ap_cnt >= 2)
				return ERROR_OK;
		}
	}

	LOG_DEBUG("No %s found",
				(type_to_find == PMP_AP_TYPE_AHB_AP)  ? "AHB-AP"  :
				(type_to_find == PMP_AP_TYPE_APB_AP)  ? "APB-AP"  : 
				(type_to_find == PMP_AP_TYPE_AHB_AP2)  ? "AHB-AP2"  : "Unknown");

				
	return ERROR_FAIL;
}

int pmp_dap_get_debugbase(struct pmp_v5_dap *dap, int ap,
			uint32_t *dbgbase, uint32_t *apid)
{
	uint32_t ap_old;
	int retval;

	/* AP address is in bits 31:24 of DP_SELECT */
	if (ap >= 256)
		return ERROR_COMMAND_SYNTAX_ERROR;

	ap_old = dap->ap_current;
	pmp_dap_ap_select(dap, ap);

	retval = pmp_dap_queue_ap_read(dap, PMP_AP_REG_BASE, dbgbase);
	if (retval != ERROR_OK)
		return retval;
	retval = pmp_dap_queue_ap_read(dap, PMP_AP_REG_IDR, apid);
	if (retval != ERROR_OK)
		return retval;
	retval = pmp_dap_run(dap);
	if (retval != ERROR_OK)
		return retval;

	pmp_dap_ap_select(dap, ap_old);

	return ERROR_OK;
}

int pmp_dap_lookup_cs_component(struct pmp_v5_dap *dap, int ap,
			uint32_t dbgbase, uint8_t type, uint32_t *addr, int32_t *idx)
{
	uint32_t ap_old;
	uint32_t romentry, entry_offset = 0, component_base, devtype;
	int retval;

	if (ap >= 256)
		return ERROR_COMMAND_SYNTAX_ERROR;

	*addr = 0;
	ap_old = dap->ap_current;
	pmp_dap_ap_select(dap, ap);

	do {
		retval = pmp_mem_ap_read_atomic_u32(dap, (dbgbase&0xFFFFF000) |
						entry_offset, &romentry);
		if (retval != ERROR_OK)
			return retval;

		component_base = (dbgbase & 0xFFFFF000)
			+ (romentry & 0xFFFFF000);

		if (romentry & 0x1) {
			uint32_t c_cid1;
			retval = pmp_mem_ap_read_atomic_u32(dap, component_base | 0xff4, &c_cid1);
			if (retval != ERROR_OK) {
				LOG_ERROR("Can't read component with base address 0x%" PRIx32
					  ", the corresponding core might be turned off", component_base);
				return retval;
			}
			if (((c_cid1 >> 4) & 0x0f) == 1) {
				retval = pmp_dap_lookup_cs_component(dap, ap, component_base,
							type, addr, idx);
				if (retval == ERROR_OK)
					break;
				if (retval != ERROR_TARGET_RESOURCE_NOT_AVAILABLE)
					return retval;
			}

			retval = pmp_mem_ap_read_atomic_u32(dap,
					(component_base & 0xfffff000) | 0xfcc,
					&devtype);
			if (retval != ERROR_OK)
				return retval;
			if ((devtype & 0xff) == type) {
				if (!*idx) {
					*addr = component_base;
					break;
				} else
					(*idx)--;
			}
		}
		entry_offset += 4;
	} while (romentry > 0);

	pmp_dap_ap_select(dap, ap_old);

	if (!*addr)
		return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;

	return ERROR_OK;
}


#if 0
static int pmp_dap_rom_display(struct command_context *cmd_ctx,
				struct pmp_v5_dap *dap, int ap, uint32_t dbgbase, int depth)
{
	int retval;
	uint32_t cid0, cid1, cid2, cid3, memtype, romentry;
	uint16_t entry_offset;
	char tabs[7] = "";

	if (depth > 16) {
		command_print(cmd_ctx, "\tTables too deep");
		return ERROR_FAIL;
	}

	if (depth)
		snprintf(tabs, sizeof(tabs), "[L%02d] ", depth);

	/* bit 16 of apid indicates a memory access port */
	if (dbgbase & 0x02)
		command_print(cmd_ctx, "\t%sValid ROM table present", tabs);
	else
		command_print(cmd_ctx, "\t%sROM table in legacy format", tabs);

	/* Now we read ROM table ID registers, ref. ARM IHI 0029B sec  */
	retval = pmp_mem_ap_read_u32(dap, (dbgbase&0xFFFFF000) | 0xFF0, &cid0);
	if (retval != ERROR_OK)
		return retval;
	retval = pmp_mem_ap_read_u32(dap, (dbgbase&0xFFFFF000) | 0xFF4, &cid1);
	if (retval != ERROR_OK)
		return retval;
	retval = pmp_mem_ap_read_u32(dap, (dbgbase&0xFFFFF000) | 0xFF8, &cid2);
	if (retval != ERROR_OK)
		return retval;
	retval = pmp_mem_ap_read_u32(dap, (dbgbase&0xFFFFF000) | 0xFFC, &cid3);
	if (retval != ERROR_OK)
		return retval;
	retval = pmp_mem_ap_read_u32(dap, (dbgbase&0xFFFFF000) | 0xFCC, &memtype);
	if (retval != ERROR_OK)
		return retval;
	retval = pmp_dap_run(dap);
	if (retval != ERROR_OK)
		return retval;

	if (!is_dap_cid_ok(cid3, cid2, cid1, cid0))
		command_print(cmd_ctx, "\t%sCID3 0x%02x"
				", CID2 0x%02x"
				", CID1 0x%02x"
				", CID0 0x%02x",
				tabs,
				(unsigned)cid3, (unsigned)cid2,
				(unsigned)cid1, (unsigned)cid0);
	if (memtype & 0x01)
		command_print(cmd_ctx, "\t%sMEMTYPE system memory present on bus", tabs);
	else
		command_print(cmd_ctx, "\t%sMEMTYPE system memory not present: dedicated debug bus", tabs);

	/* Now we read ROM table entries from dbgbase&0xFFFFF000) | 0x000 until we get 0x00000000 */
	for (entry_offset = 0; ; entry_offset += 4) {
		retval = pmp_mem_ap_read_atomic_u32(dap, (dbgbase&0xFFFFF000) | entry_offset, &romentry);
		if (retval != ERROR_OK)
			return retval;
		command_print(cmd_ctx, "\t%sROMTABLE[0x%x] = 0x%" PRIx32 "",
				tabs, entry_offset, romentry);
		if (romentry & 0x01) {
			uint32_t c_cid0, c_cid1, c_cid2, c_cid3;
			uint32_t c_pid0, c_pid1, c_pid2, c_pid3, c_pid4;
			uint32_t component_base;
			uint32_t part_num;
			const char *type, *full;

			component_base = (dbgbase & 0xFFFFF000) + (romentry & 0xFFFFF000);

			/* IDs are in last 4K section */
			retval = pmp_mem_ap_read_atomic_u32(dap, component_base + 0xFE0, &c_pid0);
			if (retval != ERROR_OK) {
				command_print(cmd_ctx, "\t%s\tCan't read component with base address 0x%" PRIx32
					      ", the corresponding core might be turned off", tabs, component_base);
				continue;
			}
			c_pid0 &= 0xff;
			retval = pmp_mem_ap_read_atomic_u32(dap, component_base + 0xFE4, &c_pid1);
			if (retval != ERROR_OK)
				return retval;
			c_pid1 &= 0xff;
			retval = pmp_mem_ap_read_atomic_u32(dap, component_base + 0xFE8, &c_pid2);
			if (retval != ERROR_OK)
				return retval;
			c_pid2 &= 0xff;
			retval = pmp_mem_ap_read_atomic_u32(dap, component_base + 0xFEC, &c_pid3);
			if (retval != ERROR_OK)
				return retval;
			c_pid3 &= 0xff;
			retval = pmp_mem_ap_read_atomic_u32(dap, component_base + 0xFD0, &c_pid4);
			if (retval != ERROR_OK)
				return retval;
			c_pid4 &= 0xff;

			retval = pmp_mem_ap_read_atomic_u32(dap, component_base + 0xFF0, &c_cid0);
			if (retval != ERROR_OK)
				return retval;
			c_cid0 &= 0xff;
			retval = pmp_mem_ap_read_atomic_u32(dap, component_base + 0xFF4, &c_cid1);
			if (retval != ERROR_OK)
				return retval;
			c_cid1 &= 0xff;
			retval = pmp_mem_ap_read_atomic_u32(dap, component_base + 0xFF8, &c_cid2);
			if (retval != ERROR_OK)
				return retval;
			c_cid2 &= 0xff;
			retval = pmp_mem_ap_read_atomic_u32(dap, component_base + 0xFFC, &c_cid3);
			if (retval != ERROR_OK)
				return retval;
			c_cid3 &= 0xff;

			command_print(cmd_ctx, "\t\tComponent base address 0x%" PRIx32 ", "
				      "start address 0x%" PRIx32, component_base,
				      /* component may take multiple 4K pages */
				      (uint32_t)(component_base - 0x1000*(c_pid4 >> 4)));
			command_print(cmd_ctx, "\t\tComponent class is 0x%" PRIx8 ", %s",
					(uint8_t)((c_cid1 >> 4) & 0xf),
					/* See ARM IHI 0029B Table 3-3 */
					class_description[(c_cid1 >> 4) & 0xf]);

			/* CoreSight component? */
			if (((c_cid1 >> 4) & 0x0f) == 9) {
				uint32_t devtype;
				unsigned minor;
				const char *major = "Reserved", *subtype = "Reserved";

				retval = pmp_mem_ap_read_atomic_u32(dap,
						(component_base & 0xfffff000) | 0xfcc,
						&devtype);
				if (retval != ERROR_OK)
					return retval;
				minor = (devtype >> 4) & 0x0f;
				switch (devtype & 0x0f) {
				case 0:
					major = "Miscellaneous";
					switch (minor) {
					case 0:
						subtype = "other";
						break;
					case 4:
						subtype = "Validation component";
						break;
					}
					break;
				case 1:
					major = "Trace Sink";
					switch (minor) {
					case 0:
						subtype = "other";
						break;
					case 1:
						subtype = "Port";
						break;
					case 2:
						subtype = "Buffer";
						break;
					case 3:
						subtype = "Router";
						break;
					}
					break;
				case 2:
					major = "Trace Link";
					switch (minor) {
					case 0:
						subtype = "other";
						break;
					case 1:
						subtype = "Funnel, router";
						break;
					case 2:
						subtype = "Filter";
						break;
					case 3:
						subtype = "FIFO, buffer";
						break;
					}
					break;
				case 3:
					major = "Trace Source";
					switch (minor) {
					case 0:
						subtype = "other";
						break;
					case 1:
						subtype = "Processor";
						break;
					case 2:
						subtype = "DSP";
						break;
					case 3:
						subtype = "Engine/Coprocessor";
						break;
					case 4:
						subtype = "Bus";
						break;
					case 6:
						subtype = "Software";
						break;
					}
					break;
				case 4:
					major = "Debug Control";
					switch (minor) {
					case 0:
						subtype = "other";
						break;
					case 1:
						subtype = "Trigger Matrix";
						break;
					case 2:
						subtype = "Debug Auth";
						break;
					case 3:
						subtype = "Power Requestor";
						break;
					}
					break;
				case 5:
					major = "Debug Logic";
					switch (minor) {
					case 0:
						subtype = "other";
						break;
					case 1:
						subtype = "Processor";
						break;
					case 2:
						subtype = "DSP";
						break;
					case 3:
						subtype = "Engine/Coprocessor";
						break;
					case 4:
						subtype = "Bus";
						break;
					case 5:
						subtype = "Memory";
						break;
					}
					break;
				case 6:
					major = "Perfomance Monitor";
					switch (minor) {
					case 0:
						subtype = "other";
						break;
					case 1:
						subtype = "Processor";
						break;
					case 2:
						subtype = "DSP";
						break;
					case 3:
						subtype = "Engine/Coprocessor";
						break;
					case 4:
						subtype = "Bus";
						break;
					case 5:
						subtype = "Memory";
						break;
					}
					break;
				}
				command_print(cmd_ctx, "\t\tType is 0x%02" PRIx8 ", %s, %s",
						(uint8_t)(devtype & 0xff),
						major, subtype);
				/* REVISIT also show 0xfc8 DevId */
			}

			if (!is_dap_cid_ok(cid3, cid2, cid1, cid0))
				command_print(cmd_ctx,
						"\t\tCID3 0%02x"
						", CID2 0%02x"
						", CID1 0%02x"
						", CID0 0%02x",
						(int)c_cid3,
						(int)c_cid2,
						(int)c_cid1,
						(int)c_cid0);
			command_print(cmd_ctx,
				"\t\tPeripheral ID[4..0] = hex "
				"%02x %02x %02x %02x %02x",
				(int)c_pid4, (int)c_pid3, (int)c_pid2,
				(int)c_pid1, (int)c_pid0);

			/* Part number interpretations are from Cortex
			 * core specs, the CoreSight components TRM
			 * (ARM DDI 0314H), CoreSight System Design
			 * Guide (ARM DGI 0012D) and ETM specs; also
			 * from chip observation (e.g. TI SDTI).
			 */
			part_num = (c_pid0 & 0xff);
			part_num |= (c_pid1 & 0x0f) << 8;
			switch (part_num) {
			case 0x000:
				type = "Cortex-M3 NVIC";
				full = "(Interrupt Controller)";
				break;
			case 0x001:
				type = "Cortex-M3 ITM";
				full = "(Instrumentation Trace Module)";
				break;
			case 0x002:
				type = "Cortex-M3 DWT";
				full = "(Data Watchpoint and Trace)";
				break;
			case 0x003:
				type = "Cortex-M3 FBP";
				full = "(Flash Patch and Breakpoint)";
				break;
			case 0x008:
				type = "Cortex-M0 SCS";
				full = "(System Control Space)";
				break;
			case 0x00a:
				type = "Cortex-M0 DWT";
				full = "(Data Watchpoint and Trace)";
				break;
			case 0x00b:
				type = "Cortex-M0 BPU";
				full = "(Breakpoint Unit)";
				break;
			case 0x00c:
				type = "Cortex-M4 SCS";
				full = "(System Control Space)";
				break;
			case 0x00d:
				type = "CoreSight ETM11";
				full = "(Embedded Trace)";
				break;
			/* case 0x113: what? */
			case 0x120:		/* from OMAP3 memmap */
				type = "TI SDTI";
				full = "(System Debug Trace Interface)";
				break;
			case 0x343:		/* from OMAP3 memmap */
				type = "TI DAPCTL";
				full = "";
				break;
			case 0x906:
				type = "Coresight CTI";
				full = "(Cross Trigger)";
				break;
			case 0x907:
				type = "Coresight ETB";
				full = "(Trace Buffer)";
				break;
			case 0x908:
				type = "Coresight CSTF";
				full = "(Trace Funnel)";
				break;
			case 0x910:
				type = "CoreSight ETM9";
				full = "(Embedded Trace)";
				break;
			case 0x912:
				type = "Coresight TPIU";
				full = "(Trace Port Interface Unit)";
				break;
			case 0x913:
				type = "Coresight ITM";
				full = "(Instrumentation Trace Macrocell)";
				break;
			case 0x914:
				type = "Coresight SWO";
				full = "(Single Wire Output)";
				break;
			case 0x917:
				type = "Coresight HTM";
				full = "(AHB Trace Macrocell)";
				break;
			case 0x920:
				type = "CoreSight ETM11";
				full = "(Embedded Trace)";
				break;
			case 0x921:
				type = "Cortex-A8 ETM";
				full = "(Embedded Trace)";
				break;
			case 0x922:
				type = "Cortex-A8 CTI";
				full = "(Cross Trigger)";
				break;
			case 0x923:
				type = "Cortex-M3 TPIU";
				full = "(Trace Port Interface Unit)";
				break;
			case 0x924:
				type = "Cortex-M3 ETM";
				full = "(Embedded Trace)";
				break;
			case 0x925:
				type = "Cortex-M4 ETM";
				full = "(Embedded Trace)";
				break;
			case 0x930:
				type = "Cortex-R4 ETM";
				full = "(Embedded Trace)";
				break;
			case 0x950:
				type = "CoreSight Component";
				full = "(unidentified Cortex-A9 component)";
				break;
			case 0x961:
				type = "CoreSight TMC";
				full = "(Trace Memory Controller)";
				break;
			case 0x962:
				type = "CoreSight STM";
				full = "(System Trace Macrocell)";
				break;
			case 0x9a0:
				type = "CoreSight PMU";
				full = "(Performance Monitoring Unit)";
				break;
			case 0x9a1:
				type = "Cortex-M4 TPUI";
				full = "(Trace Port Interface Unit)";
				break;
			case 0x9a5:
				type = "Cortex-A5 ETM";
				full = "(Embedded Trace)";
				break;
			case 0xc05:
				type = "Cortex-A5 Debug";
				full = "(Debug Unit)";
				break;
			case 0xc08:
				type = "Cortex-A8 Debug";
				full = "(Debug Unit)";
				break;
			case 0xc09:
				type = "Cortex-A9 Debug";
				full = "(Debug Unit)";
				break;
			case 0x4af:
				type = "Cortex-A15 Debug";
				full = "(Debug Unit)";
				break;
			default:
				LOG_DEBUG("Unrecognized Part number 0x%" PRIx32, part_num);
				type = "-*- unrecognized -*-";
				full = "";
				break;
			}
			command_print(cmd_ctx, "\t\tPart is %s %s",
					type, full);

			/* ROM Table? */
			if (((c_cid1 >> 4) & 0x0f) == 1) {
				retval = pmp_dap_rom_display(cmd_ctx, dap, ap, component_base, depth + 1);
				if (retval != ERROR_OK)
					return retval;
			}
		} else {
			if (romentry)
				command_print(cmd_ctx, "\t\tComponent not present");
			else
				break;
		}
	}
	command_print(cmd_ctx, "\t%s\tEnd of ROM table", tabs);
	return ERROR_OK;
}


#endif


#if 0

static int pmp_dap_info_command(struct command_context *cmd_ctx,
		struct pmp_v5_dap *dap, int ap)
{
	int retval;
	uint32_t dbgbase, apid;
	int romtable_present = 0;
	uint8_t mem_ap;
	uint32_t ap_old;

	retval = pmp_dap_get_debugbase(dap, ap, &dbgbase, &apid);
	if (retval != ERROR_OK)
		return retval;

	ap_old = dap->ap_current;
	pmp_dap_ap_select(dap, ap);

	/* Now we read ROM table ID registers, ref. ARM IHI 0029B sec  */
	mem_ap = ((apid&0x10000) && ((apid&0x0F) != 0));
	command_print(cmd_ctx, "AP ID register 0x%8.8" PRIx32, apid);
	if (apid) {
		switch (apid&0x0F) {
			case 0:
				command_print(cmd_ctx, "\tType is JTAG-AP");
				break;
			case 1:
				command_print(cmd_ctx, "\tType is MEM-AP AHB");
				break;
			case 2:
				command_print(cmd_ctx, "\tType is MEM-AP APB");
				break;
			default:
				command_print(cmd_ctx, "\tUnknown AP type");
				break;
		}

		/* NOTE: a MEM-AP may have a single CoreSight component that's
		 * not a ROM table ... or have no such components at all.
		 */
		if (mem_ap)
			command_print(cmd_ctx, "AP BASE 0x%8.8" PRIx32, dbgbase);
	} else
		command_print(cmd_ctx, "No AP found at this ap 0x%x", ap);

	romtable_present = ((mem_ap) && (dbgbase != 0xFFFFFFFF));
	if (romtable_present)
		pmp_dap_rom_display(cmd_ctx, dap, ap, dbgbase, 0);
	else
		command_print(cmd_ctx, "\tNo ROM table present");
	pmp_dap_ap_select(dap, ap_old);

	return ERROR_OK;
}


/*=========================================
Coming:
the following command need to be changed for zx pmp-v!!!!!
==========================================*/

COMMAND_HANDLER(pmp_handle_dap_info_command)
{
	struct target *target = get_current_target(CMD_CTX);
	struct zx_pmp_common *zx_pmp = target_to_zx_pmp(target);
	struct pmp_v5_dap *dap = zx_pmp->dap;

	uint32_t apsel;

	switch (CMD_ARGC) {
	case 0:
		apsel = dap->apsel;
		break;
	case 1:
		COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], apsel);
		break;
	default:
		return ERROR_COMMAND_SYNTAX_ERROR;
	}

	return pmp_dap_info_command(CMD_CTX, dap, apsel);
}


#endif

COMMAND_HANDLER(pmp_dap_baseaddr_command)
{
	struct target *target = get_current_target(CMD_CTX);
	struct zx_pmp_common *zx_pmp = target_to_zx_pmp(target);
	struct pmp_v5_dap *dap = &zx_pmp->dap;

	uint32_t apsel, baseaddr;
	int retval;

	switch (CMD_ARGC) {
	case 0:
		apsel = dap->apsel;
		break;
	case 1:
		COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], apsel);
		/* AP address is in bits 31:24 of DP_SELECT */
		if (apsel >= 256)
			return ERROR_COMMAND_SYNTAX_ERROR;
		break;
	default:
		return ERROR_COMMAND_SYNTAX_ERROR;
	}

	pmp_dap_ap_select(dap, apsel);

	/* NOTE:  assumes we're talking to a MEM-AP, which
	 * has a base address.  There are other kinds of AP,
	 * though they're not common for now.  This should
	 * use the ID register to verify it's a MEM-AP.
	 */
	retval = pmp_dap_queue_ap_read(dap, PMP_AP_REG_BASE, &baseaddr);
	if (retval != ERROR_OK)
		return retval;
	retval = pmp_dap_run(dap);
	if (retval != ERROR_OK)
		return retval;

	command_print(CMD_CTX, "0x%8.8" PRIx32, baseaddr);

	return retval;
}

COMMAND_HANDLER(pmp_dap_memaccess_command)
{
	struct target *target = get_current_target(CMD_CTX);
	struct zx_pmp_common *zx_pmp = target_to_zx_pmp(target);
	struct pmp_v5_dap *dap = &zx_pmp->dap;

	uint32_t memaccess_tck;

	switch (CMD_ARGC) {
	case 0:
		memaccess_tck = dap->memaccess_tck;
		break;
	case 1:
		COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], memaccess_tck);
		break;
	default:
		return ERROR_COMMAND_SYNTAX_ERROR;
	}
	dap->memaccess_tck = memaccess_tck;

	command_print(CMD_CTX, "memory bus access delay set to %" PRIi32 " tck",
			dap->memaccess_tck);

	return ERROR_OK;
}

COMMAND_HANDLER(pmp_dap_apsel_command)
{
	struct target *target = get_current_target(CMD_CTX);
	struct zx_pmp_common *zx_pmp = target_to_zx_pmp(target);
	struct pmp_v5_dap *dap = &zx_pmp->dap;

	uint32_t apsel, apid;
	int retval;

	switch (CMD_ARGC) {
	case 0:
		apsel = 0;
		break;
	case 1:
		COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], apsel);
		/* AP address is in bits 31:24 of DP_SELECT */
		if (apsel >= 256)
			return ERROR_COMMAND_SYNTAX_ERROR;
		break;
	default:
		return ERROR_COMMAND_SYNTAX_ERROR;
	}

	dap->apsel = apsel;
	pmp_dap_ap_select(dap, apsel);

	retval = pmp_dap_queue_ap_read(dap, PMP_AP_REG_IDR, &apid);
	if (retval != ERROR_OK)
		return retval;
	retval = pmp_dap_run(dap);
	if (retval != ERROR_OK)
		return retval;

	command_print(CMD_CTX, "ap %" PRIi32 " selected, identification register 0x%8.8" PRIx32,
			apsel, apid);

	return retval;
}

COMMAND_HANDLER(pmp_dap_apcsw_command)
{
	struct target *target = get_current_target(CMD_CTX);
	struct zx_pmp_common *zx_pmp = target_to_zx_pmp(target);
	struct pmp_v5_dap *dap = &zx_pmp->dap;

	uint32_t apcsw = dap->apcsw[dap->apsel], sprot = 0;

	switch (CMD_ARGC) {
	case 0:
		command_print(CMD_CTX, "apsel %" PRIi32 " selected, csw 0x%8.8" PRIx32,
			(dap->apsel), apcsw);
		break;
	case 1:
		COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], sprot);
		/* AP address is in bits 31:24 of DP_SELECT */
		if (sprot > 1)
			return ERROR_COMMAND_SYNTAX_ERROR;
		if (sprot)
			apcsw |= PMP_CSW_SPROT;
		else
			apcsw &= ~PMP_CSW_SPROT;
		break;
	default:
		return ERROR_COMMAND_SYNTAX_ERROR;
	}
	dap->apcsw[dap->apsel] = apcsw;

	return 0;
}



COMMAND_HANDLER(pmp_dap_apid_command)
{
	struct target *target = get_current_target(CMD_CTX);
	struct zx_pmp_common *zx_pmp = target_to_zx_pmp(target);
	struct pmp_v5_dap *dap = &zx_pmp->dap;

	uint32_t apsel, apid;
	int retval;

	switch (CMD_ARGC) {
	case 0:
		apsel = dap->apsel;
		break;
	case 1:
		COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], apsel);
		/* AP address is in bits 31:24 of DP_SELECT */
		if (apsel >= 256)
			return ERROR_COMMAND_SYNTAX_ERROR;
		break;
	default:
		return ERROR_COMMAND_SYNTAX_ERROR;
	}

	pmp_dap_ap_select(dap, apsel);

	retval = pmp_dap_queue_ap_read(dap, PMP_AP_REG_IDR, &apid);
	if (retval != ERROR_OK)
		return retval;
	retval = pmp_dap_run(dap);
	if (retval != ERROR_OK)
		return retval;

	command_print(CMD_CTX, "0x%8.8" PRIx32, apid);

	return retval;
}


static const struct command_registration pmp_dap_commands[] = {
	
#ifdef DAP_DISPLAY
	{
		.name = "pmp_info",
		.handler = pmp_handle_dap_info_command,
		.mode = COMMAND_EXEC,
		.help = "display ROM table for MEM-AP "
			"(default currently selected AP)",
		.usage = "[ap_num]",
	},
#endif

	{
		.name = "pmp_apsel",
		.handler = pmp_dap_apsel_command,
		.mode = COMMAND_EXEC,
		.help = "Set the currently selected AP (default 0) "
			"and display the result",
		.usage = "[ap_num]",
	},
	{
		.name = "pmp_apcsw",
		.handler = pmp_dap_apcsw_command,
		.mode = COMMAND_EXEC,
		.help = "Set csw access bit ",
		.usage = "[sprot]",
	},
	{
		.name = "pmp_apid",
		.handler = pmp_dap_apid_command,
		.mode = COMMAND_EXEC,
		.help = "return ID register from AP "
			"(default currently selected AP)",
		.usage = "[ap_num]",
	},
	{
		.name = "pmp_baseaddr",
		.handler = pmp_dap_baseaddr_command,
		.mode = COMMAND_EXEC,
		.help = "return debug base address from MEM-AP "
			"(default currently selected AP)",
		.usage = "[ap_num]",
	},
	{
		.name = "pmp_memaccess",
		.handler = pmp_dap_memaccess_command,
		.mode = COMMAND_EXEC,
		.help = "set/get number of extra tck for MEM-AP memory "
			"bus access [0-255]",
		.usage = "[cycles]",
	},

	COMMAND_REGISTRATION_DONE
};

const struct command_registration pmp_dap_command_handlers[] = {
	{
		.name = "pmp_dap",
		.mode = COMMAND_EXEC,
		.help = "DAP command group",
		.usage = "",
		.chain = pmp_dap_commands,
	},
	COMMAND_REGISTRATION_DONE
};

