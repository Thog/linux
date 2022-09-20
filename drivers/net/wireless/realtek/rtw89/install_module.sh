#!/bin/sh

sudo modprobe mac80211
sudo insmod rtw89_core.ko
sudo insmod rtw89_usb.ko
sudo insmod rtw89_8852a.ko
sudo insmod rtw89_8852au.ko
