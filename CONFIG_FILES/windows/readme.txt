##To use openocd.exe in this folder, you need to prepare the following.

1. Install the driver from FTDI-Driver. You may need to uninstall libusb driver for OpenJTAG if you installed that before
2. Run openocd.exe -f ../openjtag.cfg -f ../<chip>.cfg


##To build openocd.exe for windows, please refer to cross_build_for_windows.sh. And the necessary libs are in FTDI-Driver and libusb-win32-bin-1.2.6.0.
