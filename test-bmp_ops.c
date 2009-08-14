#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BI_RGB          0
#define BI_RLE8         1
#define BI_RLE4         2
#define BI_BITFIELDS    3

#define OS2INFOHEADERSIZE  12
#define WININFOHEADERSIZE  40

/* Conversion factors */
#define PDC_INCH2METER          0.0254
#define PDC_METER2INCH         39.3701

typedef struct {
	/** specifies file type must be BM (4D42h) */
	unsigned short fileType;
	/** file size in bytes (54) */
	unsigned int fileSize;
	/** must be 0 */
	unsigned short res1;
	/** must be 0 */
	unsigned short res2;
	/** offset in bytes from the header to the data (40) */
	unsigned int imageOffset;
} BITMAPFILEHEADER;

typedef struct {
	/** information header size in bytes (40) */
	unsigned int infoSize;
	/** width of the bitmap in pixels (0) */
	int imageWidth;
	/** height of the bitmap in pixels (0) */
	int imageHeight;
	/** must be 1 */
	unsigned short colourPlanes;
	/** bits per pixel, 1, 4, 8, 16, (24), 32 */
	unsigned short bitCount;
	/** compression type (0) */
	unsigned int compression;
	/** size of image in bytes (0), width x height*/
	unsigned int imageSize;
	/** number of pixels in x per meter (2834) */
	int pixelsX;
	/** number of pixels in y per meter (2834) */
	int pixelsY;
	/** number of colours used in the image (0) */
	unsigned int numColours;
	/** number of important colours (0) */
	unsigned int numImportant;
} BITMAPINFOHEADER;

/* pixel : keep channel order with readfile order */
typedef struct _PALLETTE
{
	unsigned char blue;
	unsigned char green;
	unsigned char red;
	unsigned char reserved;
} PALLETTE; 

/* load_bmp:
 *  Loads a Windows BMP file, returning a bitmap structure and storing
 *  the palette data in the specified palette (this should be an array of
 *  at least 256 RGB structures).
 *
 *  Thanks to Seymour Shlien for contributing this function.
 */
int load_bmp(const char *filename)
{
	BITMAPFILEHEADER fileheader = {0};
	BITMAPINFOHEADER infoheader = {0};
	FILE *f = NULL;
	int i = 0;

	f = fopen(filename, "rb");
	if (!f)
		return -1;

	/* read bitmap file header */
	fread(&(fileheader.fileType), sizeof(fileheader.fileType), 1, f);
	fread(&(fileheader.fileSize), sizeof(fileheader.fileSize), 1, f);
	fread(&(fileheader.res1), sizeof(fileheader.res1), 1, f);
	fread(&(fileheader.res2), sizeof(fileheader.res2), 1, f);
	fread(&(fileheader.imageOffset), sizeof(fileheader.imageOffset), 1, f);
	printf("fileType=%d\n", fileheader.fileType);
	printf("size=%d\n", fileheader.fileSize);
	printf("res1=%d\n", fileheader.res1);
	printf("res2=%d\n", fileheader.res2);
	printf("imageOffset=%d\n", fileheader.imageOffset);
	if (fileheader.fileType != 0x4d42) {
		printf("Not support\n");
		return -1;
	}

	/* read bitmap info header */
	fread(&infoheader, sizeof(infoheader), 1, f);
	printf("size=%d\n", infoheader.infoSize);
	printf("w=%d\n", infoheader.imageWidth);
	printf("h=%d\n", infoheader.imageHeight);
	printf("colourPlanes=%d\n", infoheader.colourPlanes);
	printf("bitCount=%d\n", infoheader.bitCount);
	printf("compression=%d\n", infoheader.compression);
	printf("imageSize=%d\n", infoheader.imageSize);
	printf("pixelsX=%f\n", infoheader.pixelsX * PDC_INCH2METER);
	printf("pixelsY=%f\n", infoheader.pixelsY * PDC_INCH2METER);
	printf("numColours=%d\n", infoheader.numColours);
	printf("numImportant=%d\n", infoheader.numImportant);
	if (infoheader.compression != 0) {
		printf("Not support\n");
		return -1;
	}

	/* read bitmap color palette */

	/* read bitmap data buffer */

	if (f)
		fclose(f);
	return 0;
}

int upside_down(const char *fname_s, const char *fname_t)
{
  FILE          *fp_s = NULL;    // source file handler
  FILE          *fp_t = NULL;    // target file handler 
  unsigned int  x,y;             // for loop counter
  unsigned int  width, height;   // image width, image height
  unsigned char *image_s = NULL; // source image array
  unsigned char *image_t = NULL; // target image array
  unsigned char R, G, B;         // color of R, G, B
  unsigned int y_avg;            // average of y axle
  unsigned int y_t;              // target of y axle
  
  unsigned char header[54] = {
    0x42,        // identity : B
    0x4d,        // identity : M
    0, 0, 0, 0,  // file size
    0, 0,        // reserved1
    0, 0,        // reserved2
    54, 0, 0, 0, // RGB data offset
    40, 0, 0, 0, // struct BITMAPINFOHEADER size
    0, 0, 0, 0,  // bmp width
    0, 0, 0, 0,  // bmp height
    1, 0,        // planes
    24, 0,       // bit per pixel
    0, 0, 0, 0,  // compression
    0, 0, 0, 0,  // data size
    0, 0, 0, 0,  // h resolution
    0, 0, 0, 0,  // v resolution 
    0, 0, 0, 0,  // used colors
    0, 0, 0, 0   // important colors
  };
  
  unsigned int file_size;           // file size
  unsigned int rgb_raw_data_offset; // RGB raw data offset
  
  fp_s = fopen(fname_s, "rb");
  if (fp_s == NULL) {
    printf("fopen fp_s error\n");
    return -1;
  }

  // move offset to 10 to find rgb raw data offset
  fseek(fp_s, 10, SEEK_SET);
  fread(&rgb_raw_data_offset, sizeof(unsigned int), 1, fp_s);
  // move offset to 18    to get width & height;
  fseek(fp_s, 18, SEEK_SET); 
  fread(&width,  sizeof(unsigned int), 1, fp_s);
  fread(&height, sizeof(unsigned int), 1, fp_s);
  // move offset to rgb_raw_data_offset to get RGB raw data
  fseek(fp_s, rgb_raw_data_offset, SEEK_SET);
    
  image_s = (unsigned char *)malloc((size_t)width * height * 3);
  if (image_s == NULL) {
    printf("malloc images_s error\n");
    return -1;
  }
    
  image_t = (unsigned char *)malloc((size_t)width * height * 3);
  if (image_t == NULL) {
    printf("malloc image_t error\n");
    return -1;
  }
  
  fread(image_s, sizeof(unsigned char), (size_t)(long)width * height * 3, fp_s);
  
  // vertical inverse algorithm
  y_avg = 0 + (height-1);
  
  for(y = 0; y != height; ++y) {
    for(x = 0; x != width; ++x) {
      R = *(image_s + 3 * (width * y + x) + 2);
      G = *(image_s + 3 * (width * y + x) + 1);
      B = *(image_s + 3 * (width * y + x) + 0);

	 // printf("R=%u, G=%u, B=%u\n", R, G, B);
      
      y_t = y_avg - y;
      
      *(image_t + 3 * (width * y_t + x) + 2) = R;
      *(image_t + 3 * (width * y_t + x) + 1) = G;
      *(image_t + 3 * (width * y_t + x) + 0) = B;
    }
  }
  
  // write to new bmp
  fp_t = fopen(fname_t, "wb");
  if (fp_t == NULL) {
    printf("fopen fname_t error\n");
      return -1;
    }
      
    // file size  
    file_size = width * height * 3 + rgb_raw_data_offset;
    header[2] = (unsigned char)(file_size & 0x000000ff);
    header[3] = (file_size >> 8)  & 0x000000ff;
    header[4] = (file_size >> 16) & 0x000000ff;
    header[5] = (file_size >> 24) & 0x000000ff;
    
    // width
    header[18] = width & 0x000000ff;
    header[19] = (width >> 8)  & 0x000000ff;
    header[20] = (width >> 16) & 0x000000ff;
    header[21] = (width >> 24) & 0x000000ff;
    
    // height
    header[22] = height &0x000000ff;
    header[23] = (height >> 8)  & 0x000000ff;
    header[24] = (height >> 16) & 0x000000ff;
    header[25] = (height >> 24) & 0x000000ff;
  
  // write header
  fwrite(header, sizeof(unsigned char), rgb_raw_data_offset, fp_t);
  // write image
    fwrite(image_t, sizeof(unsigned char), (size_t)(long)width * height * 3, fp_t);
    
    fclose(fp_s);
    fclose(fp_t);
    
    return 0;
}
    
int main()
{
	load_bmp("/home/hong/downloads/keyboard.bmp");

	upside_down("/home/hong/downloads/keyboard.bmp", "/tmp/ttt.bmp");

	return 0;
}
