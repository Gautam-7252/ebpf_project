/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023, Linaro Limited
 */

#ifndef QCOM_PHY_QMP_QSERDES_TXRX_PCIE_V6_20_H_
#define QCOM_PHY_QMP_QSERDES_TXRX_PCIE_V6_20_H_

#define QSERDES_V6_20_TX_RES_CODE_LANE_OFFSET_TX		0x30
#define QSERDES_V6_20_TX_RES_CODE_LANE_OFFSET_RX		0x34
#define QSERDES_V6_20_TX_TRAN_DRVR_EMP_EN			0xac
#define QSERDES_V6_20_TX_LANE_MODE_1				0x78
#define QSERDES_V6_20_TX_LANE_MODE_2				0x7c
#define QSERDES_V6_20_TX_LANE_MODE_3				0x80

#define QSERDES_V6_20_RX_UCDR_FO_GAIN_RATE_2			0x08
#define QSERDES_V6_20_RX_UCDR_FO_GAIN_RATE_3			0x0c
#define QSERDES_V6_20_RX_UCDR_SO_GAIN_RATE_2			0x18
#define QSERDES_V6_20_RX_UCDR_PI_CONTROLS			0x20
#define QSERDES_V6_20_RX_UCDR_SO_ACC_DEFAULT_VAL_RATE3		0x34
#define QSERDES_V6_20_RX_IVCM_CAL_CTRL2				0x9c
#define QSERDES_V6_20_RX_IVCM_POSTCAL_OFFSET			0xa0
#define QSERDES_V6_20_RX_DFE_1					0xac
#define QSERDES_V6_20_RX_DFE_2					0xb0
#define QSERDES_V6_20_RX_DFE_3					0xb4
#define QSERDES_V6_20_RX_TX_ADPT_CTRL				0xd4
#define QSERDES_V6_20_VGA_CAL_CNTRL1				0xe0
#define QSERDES_V6_20_RX_VGA_CAL_MAN_VAL			0xe8
#define QSERDES_V6_20_RX_GM_CAL					0x10c
#define QSERDES_V6_20_RX_EQU_ADAPTOR_CNTRL4			0x120
#define QSERDES_V6_20_RX_SIGDET_ENABLES				0x148
#define QSERDES_V6_20_RX_PHPRE_CTRL				0x188
#define QSERDES_V6_20_RX_DFE_CTLE_POST_CAL_OFFSET		0x194
#define QSERDES_V6_20_RX_Q_PI_INTRINSIC_BIAS_RATE32		0x1dc
#define QSERDES_V6_20_RX_MODE_RATE2_B0				0x1f4
#define QSERDES_V6_20_RX_MODE_RATE2_B1				0x1f8
#define QSERDES_V6_20_RX_MODE_RATE2_B2				0x1fc
#define QSERDES_V6_20_RX_MODE_RATE2_B3				0x200
#define QSERDES_V6_20_RX_MODE_RATE2_B4				0x204
#define QSERDES_V6_20_RX_MODE_RATE2_B5				0x208
#define QSERDES_V6_20_RX_MODE_RATE2_B6				0x20c
#define QSERDES_V6_20_RX_MODE_RATE3_B0				0x210
#define QSERDES_V6_20_RX_MODE_RATE3_B1				0x214
#define QSERDES_V6_20_RX_MODE_RATE3_B2				0x218
#define QSERDES_V6_20_RX_MODE_RATE3_B3				0x21c
#define QSERDES_V6_20_RX_MODE_RATE3_B4				0x220
#define QSERDES_V6_20_RX_MODE_RATE3_B5				0x224
#define QSERDES_V6_20_RX_MODE_RATE3_B6				0x228
#define QSERDES_V6_20_RX_BKUP_CTRL1				0x22c

#endif
