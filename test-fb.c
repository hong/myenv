#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>

//for BF simulator.
#include <fcntl.h>
#include <linux/fb.h>
#include <sys/mman.h>
static char *g_RealMemory = NULL;
static int f_fbDev = 0;
static int f_RealLineLen = 0;
static int f_BitsPerPixel = 0;
static int f_XRes = 0;
static int f_ScreenSize;
int OpenFBDevice()
{
	struct fb_var_screeninfo vinfo;
	struct fb_fix_screeninfo finfo;
	f_fbDev = open("/dev/fb0", O_RDWR);
	if (!f_fbDev) {
		printf("Error: cannot open framebuffer device.\n");
		return (1);
	}
	//printf("The framebuffer device was opened successfully.\n");

	// Get fixed screen information
	if (ioctl(f_fbDev, FBIOGET_FSCREENINFO, &finfo)) {
		printf("Error reading fixed information.\n");
		return (2);
	}
	// Get variable screen information
	if (ioctl(f_fbDev, FBIOGET_VSCREENINFO, &vinfo)) {
		printf("Error reading variable information.\n");
		return (3);
	}
	f_BitsPerPixel = vinfo.bits_per_pixel;
	f_RealLineLen = vinfo.xres * f_BitsPerPixel / 8;
	f_XRes = vinfo.xres;
	f_ScreenSize = vinfo.yres * f_RealLineLen;

	// Map the device to memory
	g_RealMemory =
	    (char *)mmap(0, f_ScreenSize, PROT_READ | PROT_WRITE, MAP_SHARED,
			 f_fbDev, 0);
	if ((long)g_RealMemory == -1) {
		printf("Error: failed to map framebuffer device to memory.\n");
		return (4);
	}
	//printf("The framebuffer device was mapped to memory successfully.\n");
}
int FBClose()
{
	munmap(g_RealMemory, f_ScreenSize);
	close(f_fbDev);
}

#define FCC(ch4) ((((int)(ch4) & 0xFF) << 24)|(((int)(ch4) & 0xFF00) << 8)|(((int)(ch4) & 0xFF0000) >> 8)|(((int)(ch4) & 0xFF000000) >> 24))
#define FCC2(ch2) ((((short)(ch2) & 0xFF) << 8)|(((short)(ch2) & 0xFF00) >>8))
char bmptest(char *filename, int x, int y)
{
	int temp;
	FILE *bmpfile;
	int i;
	int w, h;
	bmpfile = fopen(filename, "rb");
	if (bmpfile == NULL) {
		printf("can not open bmp file temp2.bmp\n");
		return 1;
	}
	fseek(bmpfile, 0x12, SEEK_SET);
	fread(&temp, sizeof(char), 4, bmpfile);
	w = FCC(temp);
	fread(&temp, sizeof(char), 4, bmpfile);
	h = FCC(temp);
	fseek(bmpfile, 0xa, SEEK_SET);
	fread(&temp, sizeof(char), 4, bmpfile);
	fseek(bmpfile, FCC(temp), SEEK_SET);
	for (i = 0; i < h; i++) {
		fread((char *)g_RealMemory + (h - 1 - i) * f_RealLineLen +
		      y * 240 * 2 + x * 2, sizeof(char), w * 2, bmpfile);
	} fclose(bmpfile);
	return 0;
}
void InitFbBlank(int x, int y, int w, int h, int pixel)
{

	// Map the device to memory
	int i, j;
	int *cleanMemory;
	for (i = 0; i < h; i++) {
		cleanMemory = (int *)(g_RealMemory + (y + i) * 240 * 2 + x * 2);
		for (j = 0; j < w / 2; j++)
			cleanMemory[j] = pixel;
	}
}
int main(int argc, char **argv)
{
	if (argv[1] == NULL) {
		printf("please input a bmp file\n");
		return 1;
	}
	OpenFBDevice();
	InitFbBlank(0, 0, 240, 320, 0x0);
	bmptest(argv[1], atoi(argv[2]), atoi(argv[3]));
	InitFbBlank(atoi(argv[2]) + 200, atoi(argv[3]), 40, 40, 0xffffffff);
	FBClose();
	return 0;
}
