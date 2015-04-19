#define __KERNEL__ /* Only needed to enable some kernel-related defines */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>

struct crypt_config {
  struct dm_dev *dev;
  void *start;

  /*
   * pool for per bio private data, crypto requests and
   * encryption requeusts/buffer pages
   */
  void *io_pool;
  void *req_pool;
  void *page_pool;
  struct bio_set *bs;

  struct workqueue_struct *io_queue;
  struct workqueue_struct *crypt_queue;

  char *cipher;
  char *cipher_mode;

  struct crypt_iv_operations *iv_gen_ops;
  union {
    struct { void *hash_tfm; unsigned char *salt; } essiv;
    struct { int shift; } benbi;
    struct { struct crypto_shash *hash_tfm; unsigned char *seed[0];} lmk;
  } iv_gen_private;
  void *iv_offset;
  unsigned int iv_size;

  /*
   * Duplicated per cpu state. Access through
   * per_cpu_ptr() only.
   */
  void *cpu;
//  struct crypt_cpu __percpu *cpu;
  unsigned tfms_count;

  /*
   * Layout of each crypto request:
   *
   *   struct ablkcipher_request
   *      context
   *      padding
   *   struct dm_crypt_request
   *      padding
   *   IV
   *
   * The padding is added so that dm_crypt_request and the IV are
   * correctly aligned.
   */
  unsigned int dmreq_start;

  unsigned long flags;
  unsigned int key_size;
  unsigned int key_parts;
  unsigned char key[0];
};

#ifdef ARCH64
void *kas = (void *) 0xffff800000000000;
#else
void *kas = (void *) 0xc0000000;
#endif


int keysearch(char *mem, int size)
{
   int i,j;
   struct crypt_config *cr;
   for(i = 0; i < (size - sizeof(struct crypt_config)); i++,mem++)
     {
        cr = (struct crypt_config *) mem;
#ifdef ARCH64
        unsigned long long iv_offset = (unsigned long long)cr->iv_offset;
#else
        unsigned long iv_offset = (unsigned long)cr->iv_offset;
#endif
        if(
           ((void *) cr->dev > kas || (void *) cr->dev == NULL) &&
           //(void *) cr->start          > kas && /* check fails for 64-bit 3.7 kernels */
           (void *) cr->io_pool        > kas &&
           (void *) cr->req_pool       > kas &&
           (void *) cr->page_pool      > kas &&
           (void *) cr->bs             > kas &&
           (void *) cr->io_queue       > kas &&
           (void *) cr->crypt_queue    > kas &&
           (void *) cr->cipher         > kas &&
           (void *) cr->cipher_mode    > kas &&
           //((void *) cr->iv_gen_private.essiv.hash_tfm > kas)  && /* fails on 64-bit? */
           //(void *) cr->iv_gen_private.essiv.salt     > kas &&
           (iv_offset == 0 || (iv_offset % 8 == 0)) &&
           (cr->iv_size  == 16 || cr->iv_size  == 32) &&
           (cr->tfms_count == 1) && // || is_power_of_2(cc->tfms_count) &&
           (cr->key_parts < 65 && cr->key_parts >= 1) && /* reduces false positives */
           (cr->key_size == 16 || cr->key_size == 32 || cr->key_size == 64)) {
             if(cr->start > 0)
               printf("offset: %lu blocks\n",
                      (unsigned long int ) cr->start);
             printf("iv_size : %d\n", cr->iv_size);
             printf("keylength: %d\n",(cr->key_size * 8));
             printf("keyparts: %d\n", cr->key_parts);
             printf("flags : %ld\n", cr->flags);
             printf("key: ");
             for(j = 0; j < cr->key_size; j++)
               printf("%02X",cr->key[j]);
             printf("\n");
             /* printf("flags : %d\n", cr->flags);
             printf("start : %p\n", cr->start);
             printf("dmreq_start : %d\n", cr->dmreq_start);
             printf("count : %d\n", cr->tfms_count);
             printf("count : %d\n", cr->iv_offset);
             printf("tfmsptr %p\n", cr->tfmsptr);
             printf("private %p\n", cr->iv_private);
             printf("cpu %p\n", cr->cpu);
             printf("dev %p\n", cr->dev);
             printf("genops %p\n", cr->iv_gen_ops);
             printf("cipher %p\n", cr->cipher); */
       }
     }
   return(0);
}

int main(int argc, char **argv)
{
   int fd;
   char *mem = NULL;
   struct stat st;

   if(argc < 2)
     {
        printf("Usage: %s [memory dump file]\n",argv[0]);
        exit(-1);
     }

   if(stat(argv[1],&st) == -1)
     {
        perror("stat()");
        printf("Failed to stat %s\n",argv[1]);
        exit(-1);
     }

   fd = open(argv[1],O_RDONLY);
   if(fd == -1)
     {
        perror("open()");
        printf("Failed to open %s\n",argv[1]);
        exit(-1);
     }

   mem = mmap(0,(int)st.st_size, PROT_READ, MAP_SHARED, fd, 0);
   if(mem == ((void *) -1))
     {
        perror("mmap()");
        exit(-1);
     }

   (void)keysearch(mem,(int)st.st_size);
   return(0);
}
