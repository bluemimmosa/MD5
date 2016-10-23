# MD5
A MD5 algorithm function implemented.

int calculate_md5(md5_hash *_md5, unsigned char *text, uint64_t length)
function returns md5_hash in the structure tag called md5_hash having following structure
              typedef struct md5{
	                uint32_t digest[4];
	                uint32_t k[64];
	                int err;
              } md5_hash;

*text is a array to content of file or text.
length is the file size in bytes or text length.
