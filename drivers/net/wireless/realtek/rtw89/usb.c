#include "usb.h"
#include "core.h"
#include "debug.h"
#include <linux/export.h>
#include <linux/module.h>

#define	REALTEK_USB_VENQT_READ			0xC0
#define	REALTEK_USB_VENQT_WRITE			0x40
#define REALTEK_USB_VENQT_CMD_REQ		0x05
#define RTW89_USB_CONTROL_MSG_TIMEOUT	500/* ms */

#define IS_HIGH_SPEED_USB(udev) \
		((USB_SPEED_HIGH == (udev)->speed) ? true : false)

int rtw89_usb_ops_tx_write(struct rtw89_dev *rtwdev, struct rtw89_core_tx_request *tx_req)
{
	BUG();

	return 0;
}

void rtw89_usb_ops_tx_kick_off(struct rtw89_dev *rtwdev, u8 txch)
{
	// TODO
	rtw89_err(rtwdev, "rtw89_usb_ops_tx_kick_off: not implemented\n");
}

void rtw89_usb_ops_flush_queues(struct rtw89_dev *rtwdev, u32 queues, bool drop)
{
	// TODO
	rtw89_err(rtwdev, "rtw89_usb_ops_flush_queues: not implemented\n");
}

void rtw89_usb_ops_reset(struct rtw89_dev *rtwdev)
{
	// TODO
	rtw89_err(rtwdev, "rtw89_usb_ops_reset: not implemented\n");
}

int rtw89_usb_ops_start(struct rtw89_dev *rtwdev)
{
	// TODO
	rtw89_err(rtwdev, "rtw89_usb_ops_start: not implemented\n");
	return -ENOTSUPP;
}

void rtw89_usb_ops_stop(struct rtw89_dev *rtwdev)
{
	// TODO
	rtw89_err(rtwdev, "rtw89_usb_ops_stop: not implemented\n");
}

void rtw89_usb_ops_pause(struct rtw89_dev *rtwdev, bool pause)
{
	// TODO
	rtw89_err(rtwdev, "rtw89_usb_ops_pause: not implemented\n");
}

void rtw89_usb_ops_switch_mode(struct rtw89_dev *rtwdev, bool low_power)
{
	// TODO
	rtw89_err(rtwdev, "rtw89_usb_ops_switch_mode: not implemented\n");
}

void rtw89_usb_recalc_int_mit(struct rtw89_dev *rtwdev)
{
	// TODO
	rtw89_err(rtwdev, "rtw89_usb_recalc_int_mit: not implemented\n");
}

static int rtw89_usb_write_sync(struct rtw89_dev *rtwdev, u32 addr, const void *data, u16 len)
{
	struct rtw89_usb *rtwusb = (struct rtw89_usb *)rtwdev->priv;
	struct usb_device *udev = rtwusb->udev;

	u8 request = REALTEK_USB_VENQT_CMD_REQ;
	u8 requesttype =  REALTEK_USB_VENQT_WRITE;
	u16 index = (u16)((addr & 0x00ff0000) >> 16);
	u16 value = (u16)(addr & 0x0000ffff);

	return usb_control_msg_send(udev, 0, request, requesttype, value, index, data, len, RTW89_USB_CONTROL_MSG_TIMEOUT, GFP_ATOMIC);
}

static int rtw89_usb_read_sync(struct rtw89_dev *rtwdev, u32 addr, void *data, u16 len)
{
	struct rtw89_usb *rtwusb = (struct rtw89_usb *)rtwdev->priv;
	struct usb_device *udev = rtwusb->udev;

	u8 request = REALTEK_USB_VENQT_CMD_REQ;
	u8 requesttype =  REALTEK_USB_VENQT_READ;
	u16 index = (u16)((addr & 0x00ff0000) >> 16);
	u16 value = (u16)(addr & 0x0000ffff);

	return usb_control_msg_recv(udev, 0, request, requesttype, value, index, data, len, RTW89_USB_CONTROL_MSG_TIMEOUT, GFP_ATOMIC);
}

u8 rtw89_usb_ops_read8(struct rtw89_dev *rtwdev, u32 addr)
{
	u8 data;

	int ret = rtw89_usb_read_sync(rtwdev, addr, &data, 1);

	BUG_ON(ret != 0);

	rtw89_info(rtwdev, "rtw89_usb_ops_read8, addr=%x, data=%x\n", addr, data);

	return data;
}

u16 rtw89_usb_ops_read16(struct rtw89_dev *rtwdev, u32 addr)
{
	u16 data;

	int ret = rtw89_usb_read_sync(rtwdev, addr, &data, 2);

	BUG_ON(ret != 0);

	rtw89_info(rtwdev, "rtw89_usb_ops_read16, addr=%x, data=%x\n", addr, data);

	return le16_to_cpu(data);
}

u32 rtw89_usb_ops_read32(struct rtw89_dev *rtwdev, u32 addr)
{
	u32 data;

	int ret = rtw89_usb_read_sync(rtwdev, addr, &data, 4);

	BUG_ON(ret != 0);

	rtw89_info(rtwdev, "rtw89_usb_ops_read32, addr=%x, data=%x\n", addr, data);

	return le32_to_cpu(data);
}

int rtw89_usb_ops_mac_pre_init(struct rtw89_dev *rtwdev)
{
	// TODO
	rtw89_err(rtwdev, "rtw89_usb_ops_mac_pre_init: not implemented\n");
	return -ENOTSUPP;
}

void rtw89_usb_ops_write8(struct rtw89_dev *rtwdev, u32 addr, u8 data)
{
	int ret = rtw89_usb_write_sync(rtwdev, addr, &data, 1);

	rtw89_info(rtwdev, "rtw89_usb_ops_write8, addr=%x, data=%x\n", addr, data);

	if (ret) {
		rtw89_err(rtwdev, "rtw89_usb_ops_write8, addr=%x, ret=%d\n", addr, ret);
	}

	BUG_ON(ret != 0);
}

void rtw89_usb_ops_write16(struct rtw89_dev *rtwdev, u32 addr, u16 data)
{
	int ret = rtw89_usb_write_sync(rtwdev, addr, &data, 2);

	rtw89_info(rtwdev, "rtw89_usb_ops_write16, addr=%x, data=%x\n", addr, data);

	if (ret) {
		rtw89_err(rtwdev, "rtw89_usb_ops_write16, addr=%x, ret=%d\n", addr, ret);
	}

	BUG_ON(ret != 0);
}

void rtw89_usb_ops_write32(struct rtw89_dev *rtwdev, u32 addr, u32 data)
{
	int ret = rtw89_usb_write_sync(rtwdev, addr, &data, 4);

	rtw89_info(rtwdev, "rtw89_usb_ops_write32, addr=%x, data=%x\n", addr, data);

	if (ret) {
		rtw89_err(rtwdev, "rtw89_usb_ops_write32, addr=%x, ret=%d\n", addr, ret);
	}

	BUG_ON(ret != 0);
}

int rtw89_usb_ops_mac_post_init(struct rtw89_dev *rtwdev)
{
	// TODO
	rtw89_err(rtwdev, "rtw89_usb_ops_mac_post_init: not implemented\n");
	return -ENOTSUPP;
}

int rtw89_usb_ops_deinit(struct rtw89_dev *rtwdev)
{
	// TODO
	rtw89_err(rtwdev, "rtw89_usb_ops_deinit: not implemented\n");
	return -ENOTSUPP;
}


u32 rtw89_usb_check_and_reclaim_tx_resource(struct rtw89_dev *rtwdev, u8 txch)
{
	// TODO
	rtw89_err(rtwdev, "rtw89_usb_check_and_reclaim_tx_resource: not implemented\n");
	BUG();
	return 0;
}

int rtw89_usb_ops_mac_lv1_recovery(struct rtw89_dev *rtwdev, enum rtw89_lv1_rcvy_step step)
{
	// TODO
	rtw89_err(rtwdev, "rtw89_usb_ops_mac_lv1_recovery: not implemented\n");
	return -ENOTSUPP;
}

void rtw89_usb_ops_dump_err_status(struct rtw89_dev *rtwdev)
{
	// TODO
	rtw89_err(rtwdev, "rtw89_usb_ops_dump_err_status: not implemented\n");
}

int rtw89_usb_napi_poll(struct napi_struct *napi, int budget)
{
	// TODO
	return -ENOTSUPP;
}

void rtw89_usb_ops_recovery_start(struct rtw89_dev *rtwdev)
{
	// TODO
	rtw89_err(rtwdev, "rtw89_usb_ops_recovery_start: not implemented\n");
}

void rtw89_usb_ops_recovery_complete(struct rtw89_dev *rtwdev)
{
	// TODO
	rtw89_err(rtwdev, "rtw89_usb_ops_recovery_complete: not implemented\n");
}

static const struct rtw89_hci_ops rtw89_usb_ops = {
	.tx_write	= rtw89_usb_ops_tx_write,
	.tx_kick_off	= rtw89_usb_ops_tx_kick_off,
	.flush_queues	= rtw89_usb_ops_flush_queues,
	.reset		= rtw89_usb_ops_reset,
	.start		= rtw89_usb_ops_start,
	.stop		= rtw89_usb_ops_stop,
	.pause		= rtw89_usb_ops_pause,
	.switch_mode	= rtw89_usb_ops_switch_mode,
	.recalc_int_mit = rtw89_usb_recalc_int_mit,

	.read8		= rtw89_usb_ops_read8,
	.read16		= rtw89_usb_ops_read16,
	.read32		= rtw89_usb_ops_read32,
	.write8		= rtw89_usb_ops_write8,
	.write16	= rtw89_usb_ops_write16,
	.write32	= rtw89_usb_ops_write32,

	.mac_pre_init	= rtw89_usb_ops_mac_pre_init,
	.mac_post_init	= rtw89_usb_ops_mac_post_init,
	.deinit		= rtw89_usb_ops_deinit,

	.check_and_reclaim_tx_resource = rtw89_usb_check_and_reclaim_tx_resource,
	.mac_lv1_rcvy	= rtw89_usb_ops_mac_lv1_recovery,
	.dump_err_status = rtw89_usb_ops_dump_err_status,
	.napi_poll	= rtw89_usb_napi_poll,

	.recovery_start = rtw89_usb_ops_recovery_start,
	.recovery_complete = rtw89_usb_ops_recovery_complete,
};

static int rtw89_usb_populate_status(struct rtw89_dev *rtwdev)
{
	struct rtw89_usb *rtwusb = (struct rtw89_usb *)rtwdev->priv;
	enum rtw89_core_chip_id chip_id = rtwdev->chip->chip_id;
	int status_reg;
	int value;

	if (chip_id == RTL8852A || chip_id == RTL8852B)
		status_reg = R_AX_USB_STATUS;
	else if (chip_id == RTL8852C)
		status_reg = R_AX_USB_STATUS_V1;
	else
	{
		rtw89_err(rtwdev, "rtw89_usb_populate_status: Unsupported chip_id %d", chip_id);
		return -EINVAL;
	}

	value = rtwdev->hci.ops->read32(rtwdev, status_reg);

	// Yes the register name state USB2, it's actually to signal USB3.
	if ((value & B_AX_R_USB2_SEL) == B_AX_R_USB2_SEL)
	{
		rtwusb->transport_speed = USB_SPEED_SUPER;
	}
	else if ((value & B_AX_MODE_HS) == B_AX_MODE_HS)
	{
		rtwusb->transport_speed = USB_SPEED_HIGH;
	}
	else
	{
		rtwusb->transport_speed = USB_SPEED_FULL;
	}

	return 0;
}

static int rtw89_usb_parse(struct rtw89_dev *rtwdev, struct usb_interface *interface)
{
	/*struct rtw89_usb *rtwusb = (struct rtw89_usb *)rtwdev->priv;

	struct usb_interface_descriptor *interface_desc;
	struct usb_host_interface *host_interface;
	struct usb_endpoint_descriptor *endpoint;
	struct device *dev = &rtwusb->udev->dev;
	int i, j = 0, endpoints;
	u8 dir, xtype, num;
	int ret = 0;*/

	// TODO

	return 0;
}

static int rtw89_usb_interface_init(struct rtw89_dev *rtwdev, struct usb_interface *interface)
{
	struct rtw89_usb *rtwusb = (struct rtw89_usb *)rtwdev->priv;
	struct usb_device *udev = usb_get_dev(interface_to_usbdev(interface));
	int ret;

	rtwusb->udev = udev;
	rtwusb->rtwdev = rtwdev;
	ret = rtw89_usb_populate_status(rtwdev);
	if (ret) {
		rtw89_err(rtwdev, "failed to populate USB transport informations, ret=%d\n",
			ret);
		return ret;
	}

	ret = rtw89_usb_parse(rtwdev, interface);
	if (ret) {
		rtw89_err(rtwdev, "failed to check USB configuration, ret=%d\n",
			ret);
		return ret;
	}

	usb_set_intfdata(interface, rtwdev->hw);

	return ret;
}

static void rtw89_usb_interface_deinit(struct rtw89_dev *rtwdev, struct usb_interface *interface)
{
	struct rtw89_usb *rtwusb = (struct rtw89_usb *)rtwdev->priv;

	usb_put_dev(rtwusb->udev);
	usb_set_intfdata(interface, NULL);
}

int rtw89_usb_probe(struct usb_interface *interface, const struct usb_device_id *id)
{
	struct ieee80211_hw *hw;
	struct rtw89_dev *rtwdev;
	const struct rtw89_driver_info *info;
	const struct rtw89_usb_info *usb_info;
	int driver_data_size;
	int ret;

	driver_data_size = sizeof(struct rtw89_dev) + sizeof(struct rtw89_usb);
	hw = ieee80211_alloc_hw(driver_data_size, &rtw89_ops);
	if (!hw) {
		dev_err(&interface->dev, "failed to allocate hw\n");
		return -ENOMEM;
	}

	info = (const struct rtw89_driver_info *)id->driver_info;
	usb_info = info->bus.usb;

	rtwdev = hw->priv;
	rtwdev->hw = hw;
	rtwdev->dev = &interface->dev;
	rtwdev->chip = info->chip;
	rtwdev->usb_info = info->bus.usb;
	rtwdev->hci.ops = &rtw89_usb_ops;
	rtwdev->hci.type = RTW89_HCI_TYPE_USB;

	SET_IEEE80211_DEV(rtwdev->hw, &interface->dev);

	ret = rtw89_core_init(rtwdev);
	if (ret) {
		rtw89_err(rtwdev, "failed to initialise core\n");
		goto err_release_hw;
	}

	ret = rtw89_usb_interface_init(rtwdev, interface);
	if (ret) {
		rtw89_err(rtwdev, "failed to initialise usb interface\n");
		goto err_core_deinit;
	}

	// TODO: some USB specific setup here

	ret = rtw89_chip_info_setup(rtwdev);
	if (ret) {
		rtw89_err(rtwdev, "failed to setup chip information\n");
		// TODO: update me when USB specific stuffs is implemented
		goto err_usb_deinit;
	}

	ret = rtw89_core_register(rtwdev);
	if (ret) {
		rtw89_err(rtwdev, "failed to register core\n");
		// TODO: update me when USB specific stuffs is implemented
		goto err_usb_deinit;
	}

	// TODO: implement napi_poll in hci
	// rtw89_core_napi_init(rtwdev);

	return 0;

//err_unregister:
	//rtw89_core_napi_deinit(rtwdev);
	rtw89_core_unregister(rtwdev);
err_usb_deinit:
	rtw89_usb_interface_deinit(rtwdev, interface);
err_core_deinit:
	rtw89_core_deinit(rtwdev);
err_release_hw:
	ieee80211_free_hw(hw);

	return ret;
}
EXPORT_SYMBOL(rtw89_usb_probe);


void rtw89_usb_disconnect(struct usb_interface *interface)
{
	struct ieee80211_hw *hw = usb_get_intfdata(interface);
	struct rtw89_dev *rtwdev;
	struct rtw89_usb *rtwusb;

	if (!hw)
		return;

	rtwdev = (struct rtw89_dev *)hw->priv;
	rtwusb = (struct rtw89_usb *)rtwdev->priv;

	// TODO: More here if added
	//rtw89_core_napi_deinit(rtwdev);
	rtw89_core_unregister(rtwdev);

	if (rtwusb->udev->state != USB_STATE_NOTATTACHED)
		usb_reset_device(rtwusb->udev);

	rtw89_usb_interface_deinit(rtwdev, interface);
	rtw89_core_deinit(rtwdev);
	ieee80211_free_hw(hw);
}
EXPORT_SYMBOL(rtw89_usb_disconnect);

int rtw89_usb_pm_suspend(struct usb_interface *interface, pm_message_t message)
{
	// TODO
	return 0;
}
EXPORT_SYMBOL(rtw89_usb_pm_suspend);

int rtw89_usb_pm_resume(struct usb_interface *interface)
{
	// TODO
	return 0;
}
EXPORT_SYMBOL(rtw89_usb_pm_resume);

MODULE_AUTHOR("Mary-nyan	<mary@mary.zone>");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("Realtek 802.11ax wireless USB driver");
