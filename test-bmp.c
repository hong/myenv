#ifndef BMP_C__
#define BMP_C__

/*
 --
 newbmp(640, 480);    to create a bitmap,
 openbmp("aaa.bmp");  to open a .bmp file and create a bitmap.
 savebmp("bbb.bmp");  save the current bitmap into a ".bmp" file.
 --
 line,putpixel are available
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned short WORD;
typedef unsigned long DWORD;

typedef struct tagBmpHeader {
//  char  type[2];       /* = "BM", it is matipulated separately to make the size of this structure the multiple of 4, */
	DWORD sizeFile;		/* = offbits + sizeImage */
	DWORD reserved;		/* == 0 */
	DWORD offbits;		/* offset from start of file = 54 + size of palette */
	DWORD sizeStruct;	/* 40 */
	DWORD width, height;
	WORD planes;		/* 1 */
	WORD bitCount;		/* bits of each pixel, 256color it is 8, 24 color it is 24 */
	DWORD compression;	/* 0 */
	DWORD sizeImage;	/* (width+?)(till multiple of 4) * height��in bytes */
	DWORD xPelsPerMeter;	/* resolution in mspaint */
	DWORD yPelsPerMeter;
	DWORD colorUsed;	/* if use all, it is 0 */
	DWORD colorImportant;	/*  */
} BmpHeader;

typedef struct tagBitmap {
	size_t width;
	size_t height;
	size_t size;
	unsigned char *data;
} Bitmap;

#define RGB(r, g, b) ((((r)&0xFF)<<16) + (((g)&0xFF)<<8) + ((b)&0xFF))

#define CEIL4(x) ((((x)+3)/4)*4)

Bitmap mbmp = { 0 };
int misopen = 0;
size_t mcolor = 0;

void setcolor(size_t c)
{
	mcolor = c;
}

void closebmp(void)
{
	if (misopen) {		/* clear bitmap */
		mbmp.width = mbmp.height = 0;
		if (mbmp.data != NULL) {
			free(mbmp.data);
			mbmp.data = NULL;
		}
	}
}

/* create a new bitmap file */
int newbmp(int width, int height)
{
	if (width <= 0 || height <= 0) {
		printf("Width and height should be positve.\n");
		return 1;
	}

	if (misopen)
		closebmp();
	/* fill bmp struct */
	mbmp.width = (size_t) width;
	mbmp.height = (size_t) height;
	mbmp.size = CEIL4(mbmp.width * 3) * mbmp.height;

	if ((mbmp.data = malloc(mbmp.size)) == NULL) {
		printf("Error: alloc fail!");
		return 1;
	}
	memset(mbmp.data, 0xFF, mbmp.size);	/* make background color white */

	misopen = 1;

	return 0;
}

/* load a .bmp file to a Bitmap struct, on error return 0  */
int openbmp(char *fname)
{
	FILE *fp;
	BmpHeader head = { 0 };

	if ((fp = fopen(fname, "rb")) == NULL) {
		printf("Error: can't open bmp file \"%s\".\n", fname);
		return 1;
	}

	/* read head, and check its format */
	if (fgetc(fp) != 'B' || fgetc(fp) != 'M') {
		printf("Error: bmp file \"%s\" format error.", fname);
		goto ERR_EXIT;
	}

	/* read its infomation */
	fread(&head, sizeof head, 1, fp);
	if (head.sizeStruct != 40 || head.reserved != 0) {
		printf("Error: bmp file \"%s\" format error.", fname);
		goto ERR_EXIT;
	}

	/* check format */
	if (head.bitCount != 24) {
		printf("Sorry: bmp file \"%s\" bit count != 24", fname);
		goto ERR_EXIT;
	}

	/* close old bitmap */
	if (misopen)
		closebmp();

	/* fill the bitmap struct */
	mbmp.width = head.width;
	mbmp.height = head.height;
	mbmp.size = head.sizeImage;
	if (mbmp.size != CEIL4(mbmp.width * 3) * mbmp.height) {	/* check size */
		printf("Error: bmp file \"%s\" size do not match!\n", fname);
		goto ERR_EXIT;
	}

	/* allocate memory */
	if ((mbmp.data = realloc(mbmp.data, head.sizeImage)) == NULL) {
		printf("Error: alloc fail!");
		goto ERR_EXIT;
	}
	/* read data into memory */
	if (fread(mbmp.data, 1, mbmp.size, fp) != mbmp.size) {
		printf("Error: read data fail!");
		goto ERR_EXIT;
	}

	misopen = 1;
	fclose(fp);
	return 0;

      ERR_EXIT:
	misopen = 0;
	fclose(fp);
	return 1;
}

int savebmp(char *fname)
{
	FILE *fp;
	BmpHeader head = { 0, 0, 54, 40, 0, 0, 1, 24, 0, 0 };	/* BMP file header */

	if ((fp = fopen(fname, "wb")) == NULL) {
		printf("Error: can't save to BMP file \"%s\".\n", fname);
		return 1;
	}

	fputc('B', fp);
	fputc('M', fp);		/* write type */
	/* fill BMP file header */
	head.width = mbmp.width;
	head.height = mbmp.height;
	head.sizeImage = mbmp.size;
	head.sizeFile = mbmp.size + head.offbits;
	fwrite(&head, sizeof head, 1, fp);	/* write header */
	if (fwrite(mbmp.data, 1, mbmp.size, fp) != mbmp.size) {
		fclose(fp);
		return 1;	/* write bitmap infomation */
	}

	fclose(fp);
	return 0;
}

size_t getpixel(size_t x, size_t y)
{
	unsigned char *p;

	if (x < mbmp.width && y < mbmp.height) {
		p = mbmp.data + CEIL4(mbmp.width * 3) * y + x * 3;
		//p = mbmp.data + CEIL4(mbmp.width*3)*(mbmp.height-1-y) + x*3;
		return p[0] + p[1] * 256L + p[2] * 256L * 256L;
	}
	return 0;
}

int putpixel(size_t x, size_t y, size_t color)
{
	unsigned char *p;

	if (x < mbmp.width && y < mbmp.height) {
		p = mbmp.data + CEIL4(mbmp.width * 3) * y + x * 3;
		//p = mbmp.data + CEIL4(mbmp.width*3)*(mbmp.height-1-y) + x*3;
		p[0] = (unsigned char)(color & 0xFF);
		p[1] = (unsigned char)((color >> 8) & 0xFF);
		p[2] = (unsigned char)((color >> 16) & 0xFF);
		return 0;
	}
	return 1;
}

/* horizontal line */
static int hline(int x1, int x2, int y)
{
	int x;

	if (y < 0 || (size_t) y >= mbmp.height)
		return 0;
	if (x1 > x2) {
		x = x1;
		x1 = x2;
		x2 = x;
	}			/* make sure x1 <= x2 */
	if (x2 < 0 || (size_t) x1 >= mbmp.width)
		return 0;	/* whole line outa range */
	if (x1 < 0)
		x1 = 0;
	if ((size_t) x2 >= mbmp.width)
		x2 = mbmp.width - 1;

	for (x = x1; x <= x2; x++)
		putpixel(x, y, 1);

	return 0;
}

/* vertical line */
static int vline(int x, int y1, int y2)
{
	int y;

	if (x < 0 || (size_t) x >= mbmp.width)
		return 0;
	if (y1 > y2) {
		y = y1;
		y1 = y2;
		y2 = y;
	}
	if (y2 < 0 || (size_t) y1 >= mbmp.height)
		return 0;
	if (y1 < 0)
		y1 = 0;
	if ((size_t) y2 >= mbmp.height)
		y2 = mbmp.height - 1;

	for (y = y2; y >= y1; y--)
		putpixel(x, y, mcolor);

	return 0;
}

/*------------------------------------------------------------*/
/* Bresenham algorithm to draw a line */
int line(int x1, int y1, int x2, int y2)
{
	int x, y, xspan, yspan, xstep, ystep, overflow;

	if (y1 == y2)
		return hline(x1, x2, y1);
	else if (x1 == x2)
		return vline(x1, y1, y2);

	/* calculate xspan, xstep, yspan, ystep,
	 * to make sure xspan, yspan is positive */
	xspan = (x2 > x1) ? (x2 - x1) : (x1 - x2);
	yspan = (y2 > y1) ? (y2 - y1) : (y1 - y2);
	xstep = (x2 > x1) ? 1 : -1;
	ystep = (y2 > y1) ? 1 : -1;

	if (yspan < xspan) {
		/* ** NOTE essence part of line drawing ** */
		/*
		 * The idea is for each y, draw several x,
		 * and turn to next y.
		 *
		 * The difficulty is HOW to go to the next y efficiently,
		 * the answer is:
		 *   round(x*yspan/xspan) = (int)(x*yspan/xspan+0.5)
		 * = (yspan+yspan+...+yspan + 0.5*xspan)/xspan
		 * and to avoid * and / operations, introduce 'overflow', which
		 * is initially set to 0.5*xspan and will be added one 'yspan' for each 'x'.
		 * Turn to the next y when the 'overflow' is greater than the yspan.
		 */
		overflow = xspan / 2;
		for (x = x1, y = y1; x != x2; x += xstep) {
			putpixel(x, y, mcolor);
			if ((overflow += yspan) >= xspan) {
				overflow -= xspan;
				y += ystep;	/* turn to next y1 */
			}
		}
		putpixel(x, y, mcolor);
		/* essence END */
	} else {
		/* stop each x, at (int)(y*xspan/yspan+0.5) */
		overflow = yspan / 2;
		for (x = x1, y = y1; y != y2; y += ystep) {
			putpixel(x, y, mcolor);
			if ((overflow += xspan) >= yspan) {
				overflow -= yspan;
				x += xstep;
			}
		}
		putpixel(x, y, mcolor);
	}

	return 0;
}

/* draw a circle whose center is (ox,oy) radius = r,  r>=0 */
int circle(int ox, int oy, int r)
{
	int x, y, tmp;
	int delta, up, down;	/* delta = x*x+y*y-r*r; up, down is its limits */

	if (r < 0)
		return 1;

	x = 0;
	delta = 0;
	up = r;
	down = -r;
	/* for each y draw several x */
	for (y = r; x <= y; --y) {
		while (delta <= up) {
			putpixel(ox + x, oy + y, mcolor);
			putpixel(ox + x, oy - y, mcolor);
			putpixel(ox - x, oy + y, mcolor);
			putpixel(ox - x, oy - y, mcolor);
			putpixel(ox + y, oy + x, mcolor);
			putpixel(ox + y, oy - x, mcolor);
			putpixel(ox - y, oy + x, mcolor);
			putpixel(ox - y, oy - x, mcolor);

			delta += (x + x + 1);
			x++;
		}
		delta += (-y - y + 1);

		if ((tmp = delta - x - x + 1) > down) {
			delta = tmp;
			x--;
		}
	}
	return 0;
}

#define TEST
#ifdef TEST
int main(void)
{
	int i;
	size_t a, b, c;
#if 1
	//openbmp("out.bmp");
	newbmp(20, 20);

	for (i = 0; i < 19; i++)
		putpixel(i, 5, RGB(60, 80, 180));
	for (i = 0; i < 19; i++)
		putpixel(13, i, RGB(80, 255, 80));
	a = rand() % 20, b = rand() % 10, c = rand();
	setcolor(c);
	line(0, 0, a, b);

	savebmp("out.bmp");
	closebmp();
#else
	openbmp("/home/hong/tmp/timezone.bmp");
#endif

	return 0;
}
#endif

#endif /* end of file  BMP_C__ */
