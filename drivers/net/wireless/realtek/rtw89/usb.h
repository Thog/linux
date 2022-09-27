/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2009-2012  Realtek Corporation.*/

#ifndef __RTW89_USB_H__
#define __RTW89_USB_H__

#include <linux/module.h>
#include <linux/usb.h>

#include "txrx.h"

#define RTW89_USB_DEVICE(vend, prod, cfg) \
	.match_flags = USB_DEVICE_ID_MATCH_DEVICE, \
	.idVendor = (vend), \
	.idProduct = (prod), \
	.driver_info = (kernel_ulong_t)&(cfg)

#define RTW89_EP_IN_MAX		1
#define RTW89_EP_OUT_MAX	8
#define R_AX_USB_STATUS		0x11F0
#define R_AX_USB_STATUS_V1	0x51F0
#define B_AX_R_SSIC_EN		BIT(2)
#define B_AX_R_USB2_SEL		BIT(1)
#define B_AX_MODE_HS		BIT(0)

#define R_AX_USB_HOST_REQUEST_2	0x1078
#define B_AX_R_USBIO_MODE	BIT(4)

#define R_AX_USB_WLAN0_1	0x1174
#define R_AX_USB_WLAN0_1_V1	0x5174
#define B_AX_USBRX_RST		BIT(9)
#define B_AX_USBTX_RST		BIT(8)

struct rtw89_usb_info {
};

struct rtw89_usb_rx {
	int endpoint;
	int endpoint_type;
	struct urb *urb;
	struct sk_buff *skb;
};

struct rtw89_usb {
	struct rtw89_dev *rtwdev;
	struct usb_device *udev;
	enum usb_device_speed transport_speed;
	int num_input_endpoint;
	int num_output_endpoint;
	struct rtw89_usb_rx input_endpoint[RTW89_EP_IN_MAX];
	int output_endpoint[RTW89_EP_OUT_MAX];
};

int rtw89_usb_probe(struct usb_interface *interface, const struct usb_device_id *id);
void rtw89_usb_disconnect(struct usb_interface *interface);
int rtw89_usb_pm_suspend(struct usb_interface *interface, pm_message_t message);
int rtw89_usb_pm_resume(struct usb_interface *interface);

#endif
