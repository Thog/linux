#!/bin/sh

sudo modprobe mac80211

# Remove old modules
sudo rmmod rtw89_8852au.ko
sudo rmmod rtw89_8852a.ko
sudo rmmod rtw89_usb.ko
sudo rmmod rtw89_core.ko

# Add modules
sudo insmod rtw89_core.ko
sudo insmod rtw89_usb.ko
sudo insmod rtw89_8852a.ko
sudo insmod rtw89_8852au.ko
