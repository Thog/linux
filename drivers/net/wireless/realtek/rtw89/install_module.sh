#!/bin/sh

# Remove old modules
./remove_module.sh


# Add modules
sudo modprobe mac80211
sudo insmod rtw89_core.ko
sudo insmod rtw89_usb.ko
sudo insmod rtw89_8852a.ko
sudo insmod rtw89_8852au.ko
