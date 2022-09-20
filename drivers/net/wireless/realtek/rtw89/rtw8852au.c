// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright(c) 2022  Mary-nyan	<mary@mary.zone>
 */


#include <linux/module.h>
#include <linux/usb.h>

#include "usb.h"
#include "reg.h"
#include "rtw8852a.h"


static const struct rtw89_usb_info rtw8852a_usb_info = {
};

static const struct rtw89_driver_info rtw89_8852au_info = {
	.chip = &rtw8852a_chip_info,
	.bus = {
		.usb = &rtw8852a_usb_info,
	},
};

static const struct usb_device_id rtw89_8852au_id_table[] = {
    /* Realtek */
	{RTW89_USB_DEVICE(0x0bda,		/* Realtek generic, e.g. Comfast CF-957AX */
			 0x8832, rtw89_8852au_info)},
	{RTW89_USB_DEVICE(0x0bda,
			 0x885a, rtw89_8852au_info)},
	{RTW89_USB_DEVICE(0x0bda,		/* Realtek generic, e.g. Fenvi FU-AX1800P */
			 0x885c, rtw89_8852au_info)},
	{RTW89_USB_DEVICE(0x0B05,		/* ASUS USB-AX56 */
			 0x1997, rtw89_8852au_info)},
	{RTW89_USB_DEVICE(0x2001,		/* D-Link DWA-X1850 */
			 0x3321, rtw89_8852au_info)},
	{},
};
MODULE_DEVICE_TABLE(usb, rtw89_8852au_id_table);

static struct usb_driver rtw89_8852au_driver = {
	.name = "rtw89_8852au",
	.id_table = rtw89_8852au_id_table,
	.probe = rtw89_usb_probe,
	.disconnect = rtw89_usb_disconnect,
};

module_usb_driver(rtw89_8852au_driver);

MODULE_AUTHOR("Mary-nyan	<mary@mary.zone>");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("Realtek 802.11ax wireless 8852AU driver");
