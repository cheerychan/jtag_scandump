#!/bin/bash

# 1. apt-get install mingw32
# 2. download libusb-win32 from http://sourceforge.net/projects/libusb-win32 (tested 1.2.6.0)
# 3. unpack libusb-win32 and rename the include/lusb0_usb.h as usb.h if necessary
# 4. download libftd2xx from http://www.ftdichip.com/Drivers/D2XX.htm (tested 2.10.00)
# 5. unpack libftd2xx
# 6. modify the 2 variables below according to your path
libusb_dir=/home/magee/Work/Perforce/magee/sw/soc/openocd-0.9.0/CONFIG_FILES/windows/libusb-win32-bin-1.2.6.0
libftd2xx_dir=/home/magee/Work/Perforce/magee/sw/soc/openocd-0.9.0/CONFIG_FILES/windows/FTDI-Driver
# 7. copy this script to openocd root folder and run it, or you can mannually run these commands as you need
# 8. to use this binary, the driver named libftd2xx from ftdi must be installed instead of libusb driver

# these makes pkg-config recognize the libusb in ${libusb_dir}
export PKG_CONFIG_LIBDIR=${libusb_dir}
touch ${libusb_dir}/libusb.pc

# mannually set the compiler and linker flags
export LIBUSB0_CFLAGS="-I${libusb_dir}/include"
export LIBUSB0_LIBS="-L${libusb_dir}/lib/gcc -lusb -static"
export LIBUSB1_CFLAGS=""
export LIBUSB1_LIBS=""

# configure cross-compile for openjtag
./configure --host=i586-mingw32msvc --disable-werror --with-ftd2xx-win32-zipdir=${libftd2xx_dir} --with-ftd2xx-lib=static --enable-legacy-ft2232_ftd2xx
make clean
make



