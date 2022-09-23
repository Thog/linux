#include "usb.h"
#include "core.h"
#include "debug.h"
#include "mac.h"
#include "reg.h"
#include <linux/export.h>
#include <linux/module.h>

#define	REALTEK_USB_VENQT_READ			0xC0
#define	REALTEK_USB_VENQT_WRITE			0x40
#define REALTEK_USB_VENQT_CMD_REQ		0x05
#define RTW89_USB_CONTROL_MSG_TIMEOUT	500/* ms */

static int rtw89_usb_get_endpoint(struct rtw89_dev *rtwdev, u8 txch)
{
	int ret;

	if (rtwdev->chip->dma_ch_usb_mapping == NULL) {
		rtw89_err(rtwdev, "rtw89_usb_get_endpoint: Unsupported operation\n");
		return -EINVAL;
	}

	ret = rtwdev->chip->dma_ch_usb_mapping[txch];

	if (ret == RTW89_DMA_CH_USB_EP_INVALID) {
		rtw89_err(rtwdev, "rtw89_usb_get_endpoint: no endpoint bound for channel %d\n", txch);
		ret = -EINVAL;
	}

	return ret;
}

static void rtw89_usb_write_port_complete(struct urb *urb)
{
	struct sk_buff *skb;

	pr_err("rtw89_usb_write_port_complete: err=%d\n", urb->status);

	skb = (struct sk_buff *)urb->context;
	dev_kfree_skb_any(skb);
}

static int rtw89_usb_write_port(struct rtw89_dev *rtwdev, u8 addr, struct sk_buff *skb)
{
	struct rtw89_usb *rtwusb = (struct rtw89_usb *)rtwdev->priv;
	struct usb_device *udev = rtwusb->udev;
	int pipe;
	struct urb *urb;
	int ret;

	if (addr >= rtwusb->num_output_endpoint) {
		rtw89_err(rtwdev, "rtw89_usb_write_port: Invalid OUT endpoint addr=%d\n", addr);
		return -EINVAL;
	}

	pipe = usb_sndbulkpipe(udev, rtwusb->output_endpoint[addr]);

	rtw89_err(rtwdev, "rtw89_usb_write_port addr=%d, ep=%d\n", addr, rtwusb->output_endpoint[addr]);

	urb = usb_alloc_urb(0, GFP_ATOMIC);

	if (!urb)
		return -ENOMEM;

	usb_fill_bulk_urb(urb, udev, pipe, skb->data, (int)skb->len,
		rtw89_usb_write_port_complete, skb),
	urb->transfer_flags |= URB_ZERO_PACKET;
	ret = usb_submit_urb(urb, GFP_ATOMIC);

	usb_free_urb(urb);

	return ret;
}

static int rtw89_usb_tx_write(struct rtw89_dev *rtwdev, struct rtw89_core_tx_request *tx_req, u8 txch)
{
	struct rtw89_usb *rtwusb = (struct rtw89_usb *)rtwdev->priv;
	struct sk_buff *skb = tx_req->skb;
	int ret = 0;
	int endpoint;

	/* check the tx type and dma channel for fw cmd queue */
	if ((txch == RTW89_TXCH_CH12 ||
	     tx_req->tx_type == RTW89_CORE_TX_TYPE_FWCMD) &&
	    (txch != RTW89_TXCH_CH12 ||
	     tx_req->tx_type != RTW89_CORE_TX_TYPE_FWCMD)) {
		rtw89_err(rtwdev, "only fw cmd uses dma channel 12\n");
		return -EINVAL;
	}

	ret = rtw89_usb_get_endpoint(rtwdev, txch);

	if (ret < 0)
	{
		return ret;
	}

	endpoint = ret;

	// TODO(Mary-nyan): Unify this
	if (txch == RTW89_TXCH_CH12 || tx_req->tx_type == RTW89_CORE_TX_TYPE_FWCMD) {
		// TODO
		ret = rtw89_usb_write_port(rtwdev, endpoint, skb);
	} else {
		rtw89_err(rtwdev, "rtw89_usb_tx_write: not implemented for normal channels\n");
		ret = -ENOTSUPP;
	}

	return ret;
}

static int rtw89_usb_ops_tx_write(struct rtw89_dev *rtwdev, struct rtw89_core_tx_request *tx_req)
{
	struct rtw89_tx_desc_info *desc_info = &tx_req->desc_info;
	int ret;

	ret = rtw89_usb_tx_write(rtwdev, tx_req, desc_info->ch_dma);
	if (ret) {
		rtw89_err(rtwdev, "failed to TX Queue %d\n", desc_info->ch_dma);
		return ret;
	}

	return 0;
}

static void rtw89_usb_ops_tx_kick_off(struct rtw89_dev *rtwdev, u8 txch)
{
	// TODO
	rtw89_err(rtwdev, "rtw89_usb_ops_tx_kick_off: not implemented\n");
}

static void rtw89_usb_ops_flush_queues(struct rtw89_dev *rtwdev, u32 queues, bool drop)
{
	// TODO
	rtw89_err(rtwdev, "rtw89_usb_ops_flush_queues: not implemented\n");
}

static void rtw89_usb_ops_reset(struct rtw89_dev *rtwdev)
{
	// TODO
	rtw89_err(rtwdev, "rtw89_usb_ops_reset: not implemented\n");
}

static int rtw89_usb_ops_start(struct rtw89_dev *rtwdev)
{
	// TODO
	rtw89_err(rtwdev, "rtw89_usb_ops_start: not implemented\n");
	return -ENOTSUPP;
}

static void rtw89_usb_ops_stop(struct rtw89_dev *rtwdev)
{
	// TODO
	rtw89_err(rtwdev, "rtw89_usb_ops_stop: not implemented\n");
}

static void rtw89_usb_ops_pause(struct rtw89_dev *rtwdev, bool pause)
{
	// TODO
	rtw89_err(rtwdev, "rtw89_usb_ops_pause: not implemented\n");
}

static void rtw89_usb_ops_switch_mode(struct rtw89_dev *rtwdev, bool low_power)
{
	// TODO
	rtw89_err(rtwdev, "rtw89_usb_ops_switch_mode: not implemented\n");
}

static void rtw89_usb_recalc_int_mit(struct rtw89_dev *rtwdev)
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

static void rtw89_usb_ops_write8(struct rtw89_dev *rtwdev, u32 addr, u8 data)
{
	int ret = rtw89_usb_write_sync(rtwdev, addr, &data, 1);

	rtw89_info(rtwdev, "rtw89_usb_ops_write8, addr=%x, data=%x\n", addr, data);

	if (ret) {
		rtw89_err(rtwdev, "rtw89_usb_ops_write8, addr=%x, ret=%d\n", addr, ret);
	}

	BUG_ON(ret != 0);
}

static void rtw89_usb_ops_write16(struct rtw89_dev *rtwdev, u32 addr, u16 data)
{
	u16 val = cpu_to_le16(data);
	int ret = rtw89_usb_write_sync(rtwdev, addr, &val, 2);

	rtw89_info(rtwdev, "rtw89_usb_ops_write16, addr=%x, val=%x\n", addr, val);

	if (ret) {
		rtw89_err(rtwdev, "rtw89_usb_ops_write16, addr=%x, ret=%d\n", addr, ret);
	}

	BUG_ON(ret != 0);
}

static void rtw89_usb_ops_write32(struct rtw89_dev *rtwdev, u32 addr, u32 data)
{
	u32 val = cpu_to_le32(data);
	int ret = rtw89_usb_write_sync(rtwdev, addr, &val, 4);

	rtw89_info(rtwdev, "rtw89_usb_ops_write32, addr=%x, val=%x\n", addr, val);

	if (ret) {
		rtw89_err(rtwdev, "rtw89_usb_ops_write32, addr=%x, ret=%d\n", addr, ret);
	}

	BUG_ON(ret != 0);
}

static u32 rtw89_usb_ops_read32_cmac(struct rtw89_dev *rtwdev, u32 addr)
{
	u32 val;
	int count;

	int ret = rtw89_usb_read_sync(rtwdev, addr, &val, 4);

	BUG_ON(ret != 0);

	for (count = 0; ; count++) {
		if (val != RTW89_R32_DEAD)
			return val;
		if (count >= MAC_REG_POOL_COUNT) {
			rtw89_warn(rtwdev, "addr %#x = %#x\n", addr, val);
			return RTW89_R32_DEAD;
		}
		rtw89_usb_ops_write32(rtwdev, R_AX_CK_EN, B_AX_CMAC_ALLCKEN);

		ret = rtw89_usb_read_sync(rtwdev, addr, &val, 4);

		BUG_ON(ret != 0);
	}

	return val;
}

static u8 rtw89_usb_ops_read8(struct rtw89_dev *rtwdev, u32 addr)
{
	u8 data;
	int ret;
	u32 addr32, val32, shift;

	if (!ACCESS_CMAC(addr))
	{
		ret = rtw89_usb_read_sync(rtwdev, addr, &data, 1);
		BUG_ON(ret != 0);
	}
	else
	{
		addr32 = addr & ~0x3;
		shift = (addr & 0x3) * 8;
		val32 = rtw89_usb_ops_read32_cmac(rtwdev, addr32);
		data = val32 >> shift;
	}


	rtw89_info(rtwdev, "rtw89_usb_ops_read8, addr=%x, data=%x\n", addr, data);

	return data;
}

static u16 rtw89_usb_ops_read16(struct rtw89_dev *rtwdev, u32 addr)
{
	u16 data;
	int ret;
	u32 addr32, val32, shift;

	if (!ACCESS_CMAC(addr))
	{
		ret = rtw89_usb_read_sync(rtwdev, addr, &data, 2);
		BUG_ON(ret != 0);
	}
	else
	{
		addr32 = addr & ~0x3;
		shift = (addr & 0x3) * 8;
		val32 = rtw89_usb_ops_read32_cmac(rtwdev, addr32);
		data = val32 >> shift;
	}

	rtw89_info(rtwdev, "rtw89_usb_ops_read16, addr=%x, data=%x\n", addr, data);

	return le16_to_cpu(data);
}

static u32 rtw89_usb_ops_read32(struct rtw89_dev *rtwdev, u32 addr)
{
	u32 data;
	int ret;

	if (!ACCESS_CMAC(addr))
	{
		ret = rtw89_usb_read_sync(rtwdev, addr, &data, 4);
		BUG_ON(ret != 0);
	}
	else
	{
		data = rtw89_usb_ops_read32_cmac(rtwdev, addr);
	}

	rtw89_info(rtwdev, "rtw89_usb_ops_read32, addr=%x, data=%x\n", addr, data);

	return le32_to_cpu(data);
}

static void rtw89_usb_ctrl_hci_dma_en(struct rtw89_dev *rtwdev, u8 en)
{
	const struct rtw89_chip_info *chip = rtwdev->chip;
	u32 val32 = B_AX_HCI_TXDMA_EN | B_AX_HCI_RXDMA_EN;

	if (en == 1)
		rtw89_write32_set(rtwdev, chip->hci_func_en_addr, val32);
	else
		rtw89_write32_clr(rtwdev, chip->hci_func_en_addr, val32);
}

static int rtw89_usb_ctrl_flush_en(struct rtw89_dev *rtwdev, u8 en)
{
	enum rtw89_core_chip_id chip_id = rtwdev->chip->chip_id;
	u32 val32 = B_AX_USBRX_RST | B_AX_USBTX_RST;
	int wlan0_1_reg;

	if (chip_id == RTL8852A || chip_id == RTL8852B)
		wlan0_1_reg = R_AX_USB_WLAN0_1;
	else if (chip_id == RTL8852C)
		wlan0_1_reg = R_AX_USB_WLAN0_1_V1;
	else
	{
		rtw89_err(rtwdev, "rtw89_usb_ctrl_flush_en: Unsupported chip_id %d", chip_id);
		return -EINVAL;
	}

	if (en == 1) {
		rtw89_write32_set(rtwdev, wlan0_1_reg, val32);
	} else {
		rtw89_write32_clr(rtwdev, wlan0_1_reg, val32);
	}

	return 0;
}

static int rtw89_usb_ops_mac_pre_init(struct rtw89_dev *rtwdev)
{
	int ret;

	rtw89_write32_set(rtwdev, R_AX_USB_HOST_REQUEST_2, B_AX_R_USBIO_MODE);

	ret = rtw89_usb_ctrl_flush_en(rtwdev, 0);

	if (ret)
	{
		rtw89_err(rtwdev, "rtw89_usb_ops_mac_pre_init: error ret=%d\n", ret);
		return ret;
	}

	rtw89_usb_ctrl_hci_dma_en(rtwdev, 0);
	rtw89_usb_ctrl_hci_dma_en(rtwdev, 1);

	return 0;
}

static int rtw89_usb_ops_mac_post_init(struct rtw89_dev *rtwdev)
{
	// TODO
	rtw89_err(rtwdev, "rtw89_usb_ops_mac_post_init: not implemented\n");
	return -ENOTSUPP;
}

static int rtw89_usb_ops_deinit(struct rtw89_dev *rtwdev)
{
	// TODO
	rtw89_err(rtwdev, "rtw89_usb_ops_deinit: not implemented\n");
	return -ENOTSUPP;
}


static u32 rtw89_usb_check_and_reclaim_tx_resource(struct rtw89_dev *rtwdev, u8 txch)
{
	// TODO(Mary-nyan): Unstub
	rtw89_err(rtwdev, "rtw89_usb_check_and_reclaim_tx_resource: not implemented\n");
	return 1;
}

static int rtw89_usb_ops_mac_lv1_recovery(struct rtw89_dev *rtwdev, enum rtw89_lv1_rcvy_step step)
{
	// TODO
	rtw89_err(rtwdev, "rtw89_usb_ops_mac_lv1_recovery: not implemented\n");
	return -ENOTSUPP;
}

static void rtw89_usb_ops_dump_err_status(struct rtw89_dev *rtwdev)
{
	// TODO
	rtw89_err(rtwdev, "rtw89_usb_ops_dump_err_status: not implemented\n");
}

static int rtw89_usb_napi_poll(struct napi_struct *napi, int budget)
{
	// TODO
	return -ENOTSUPP;
}

static void rtw89_usb_ops_recovery_start(struct rtw89_dev *rtwdev)
{
	// TODO
	rtw89_err(rtwdev, "rtw89_usb_ops_recovery_start: not implemented\n");
}

static void rtw89_usb_ops_recovery_complete(struct rtw89_dev *rtwdev)
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

	value = rtw89_read32(rtwdev, status_reg);

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

static int rtw89_usb_populate_endpoints(struct rtw89_dev *rtwdev, struct usb_interface *interface)
{
	struct rtw89_usb *rtwusb = (struct rtw89_usb *)rtwdev->priv;
	struct usb_host_interface *interface_desc = interface->cur_altsetting;
	struct usb_endpoint_descriptor *endpoint;
	int i;
	int num;

	rtwusb->num_input_endpoint = 0;
	rtwusb->num_output_endpoint = 0;

	for (i = 0; i < interface_desc->desc.bNumEndpoints; ++i) {
		endpoint = &interface_desc->endpoint[i].desc;
		num = usb_endpoint_num(endpoint);

		if (usb_endpoint_dir_in(endpoint) && (usb_endpoint_xfer_bulk(endpoint) || usb_endpoint_xfer_int(endpoint))) {
			if (rtwusb->num_input_endpoint >= RTW89_EP_IN_MAX) {
				rtw89_err(rtwdev, "rtw89_usb_populate_endpoints: Too many IN endpoints!\n");
				return -EINVAL;
			}

			rtwusb->input_endpoint[rtwusb->num_input_endpoint] = num;
			rtwusb->input_endpoint_type[rtwusb->num_input_endpoint] = usb_endpoint_type(endpoint);
			rtwusb->num_input_endpoint++;
		}

		if (usb_endpoint_dir_out(endpoint) && (usb_endpoint_xfer_bulk(endpoint))) {
			if (rtwusb->num_output_endpoint >= RTW89_EP_OUT_MAX) {
				rtw89_err(rtwdev, "rtw89_usb_populate_endpoints: Too many OUT endpoints!\n");
				return -EINVAL;
			}

			rtwusb->output_endpoint[rtwusb->num_output_endpoint] = num;
			rtwusb->num_output_endpoint++;
		}
	}

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

	ret = rtw89_usb_populate_endpoints(rtwdev, interface);
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

	if (rtwusb->udev->state != USB_STATE_NOTATTACHED)
	{
		usb_reset_device(rtwusb->udev);
	}

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
