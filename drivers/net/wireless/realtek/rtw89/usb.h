/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2009-2012  Realtek Corporation.*/

#ifndef __RTW89_USB_H__
#define __RTW89_USB_H__

#include <linux/module.h>
#include <linux/usb.h>

#define RTW89_USB_DEVICE(vend, prod, cfg) \
	.match_flags = USB_DEVICE_ID_MATCH_DEVICE, \
	.idVendor = (vend), \
	.idProduct = (prod), \
	.driver_info = (kernel_ulong_t)&(cfg)

struct rtw89_usb_info {

};

struct rtw89_usb {
	struct rtw89_dev *rtwdev;
	struct usb_device *udev;
	u32 max_bulk_out_size;
};

int rtw89_usb_probe(struct usb_interface *interface, const struct usb_device_id *id);
void rtw89_usb_disconnect(struct usb_interface *interface);
int rtw89_usb_pm_suspend(struct usb_interface *interface, pm_message_t message);
int rtw89_usb_pm_resume(struct usb_interface *interface);

#endif
