#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>
#include "mem.h"

/*
 * This structure serves as the header for each allocated and free block
 * It also serves as the footer for each free block
 * The blocks are ordered in the increasing order of addresses 
 */
typedef struct blk_hdr {                         
        int size_status;
  
    /*
    * Size of the block is always a multiple of 8
    * => last two bits are always zero - can be used to store other information
    *
    * LSB -> Least Significant Bit (Last Bit)
    * SLB -> Second Last Bit 
    * LSB = 0 => free block
    * LSB = 1 => allocated/busy block
    * SLB = 0 => previous block is free
    * SLB = 1 => previous block is allocated/busy
    * 
    * When used as the footer the last two bits should be zero
    */

    /*
    * Examples:
    * 
    * For a busy block with a payload of 20 bytes (i.e. 20 bytes data + an additional 4 bytes for header)
    * Header:
    * If the previous block is allocated, size_status should be set to 27
    * If the previous block is free, size_status should be set to 25
    * 
    * For a free block of size 24 bytes (including 4 bytes for header + 4 bytes for footer)
    * Header:
    * If the previous block is allocated, size_status should be set to 26
    * If the previous block is free, size_status should be set to 24
    * Footer:
    * size_status should be 24
    * 
    */
} blk_hdr;

/* Global variable - This will always point to the first block
 * i.e. the block with the lowest address */
blk_hdr *first_blk = NULL;

/*
 * Note: 
 *  The end of the available memory can be determined using end_mark
 *  The size_status of end_mark has a value of 1
 *
 */

/* 
 * Function for allocating 'size' bytes
 * Returns address of allocated block on success 
 * Returns NULL on failure 
 * Here is what this function should accomplish 
 * - Check for sanity of size - Return NULL when appropriate 
 * - Round up size to a multiple of 8 
 * - Traverse the list of blocks and allocate the best free block which can accommodate the requested size 
 * - Also, when allocating a block - split it into two blocks
 * Tips: Be careful with pointer arithmetic 
 */                    
void* Alloc_Mem(int size) {
    if(size <= 0){//check sanity of size
    	printf("Unable to allocate");
	return NULL;
    }

    int block_size = size + sizeof(blk_hdr); //add header size into requested block size

    while((block_size % 8) != 0){
	block_size = block_size + sizeof(char);//round up block size to multiple of 8	
    }

    blk_hdr *itr = first_blk;
    blk_hdr *first_fit = NULL;
    blk_hdr *best_fit = NULL;

    while(itr->size_status != 1){ // find first acceptable location for allocation
    	int LSB = itr->size_status & 1;
	int SLB = ((itr->size_status) >> 1) & 1;
	if((LSB == 0) && ((itr->size_status - (2*SLB) - LSB) >= block_size)){
		first_fit = (blk_hdr*) ((char*)itr);
		break;
	}
	itr = (blk_hdr*) ((char*)itr + ((itr->size_status) - LSB - (2*SLB)));	
    }

    if(first_fit == NULL){ //if first_fit still NULL after searching for an open blk of memory, return NULL
    	return NULL;
    }

    best_fit = (blk_hdr*) ((char*)first_fit); //assign best fit with first acceptable location for allocation
    int SLB_best = ((best_fit->size_status) >> 1) & 1;

    while(itr->size_status != 1){ // find best fit of block_size in entire heap
    	int LSB = itr->size_status & 1;
	int SLB = ((itr->size_status) >> 1) & 1;

	if((LSB == 0) && ((itr->size_status - (2*SLB)) >= block_size)){ //block must be free and big enough
		if((itr->size_status - (2*SLB)) < (best_fit->size_status - (2*SLB_best))){ // if blk smaller than original best_fit blk
			best_fit = (blk_hdr*) ((char*)itr); //change best_fit pointer if this placement is better
        		SLB_best = ((best_fit->size_status) >> 1) & 1; //SLB of best_fit pointer
		} 
	} 
	itr = (blk_hdr*) ((char*)itr + ((itr->size_status) - LSB - (2*SLB)));
    }

    if((best_fit->size_status - (2*SLB_best)) == block_size){ //if block fits perfectly inbetween two allocated blocks
    	blk_hdr *header_alloc = (blk_hdr*) (char*)best_fit; //just set new allocated header 
	header_alloc->size_status = block_size + (2*SLB_best) + 1;
    	
	blk_hdr *next = (blk_hdr*) ((char*)header_alloc + header_alloc->size_status - (2*SLB_best) - 1); //next block
	next->size_status = next->size_status + 2; //set SLB bit of next block to 1

	itr = NULL;
	first_fit = NULL;
	best_fit = NULL;

	return ((char*)header_alloc + sizeof(blk_hdr));
    }

    blk_hdr *footer_free = (blk_hdr*) ((char*)best_fit + (best_fit->size_status) - (2*SLB_best) - sizeof(blk_hdr)); //sets footer of free block
    footer_free->size_status = ((best_fit->size_status) - (2*SLB_best) - block_size); //assign size to new footer

    blk_hdr *header_free = (blk_hdr*) ((char*)best_fit + block_size); //set header of free block
    header_free->size_status = ((best_fit->size_status) - (2*SLB_best)) - block_size + 2; //assign size to new header of free block

    blk_hdr *header_alloc = (blk_hdr*) (char*)best_fit; //set header of allocated block
    header_alloc->size_status = block_size + (2*SLB_best) + 1; //size status will represent allocated block and prev block

    itr = NULL;
    first_fit = NULL;
    best_fit = NULL;

    return ((char*)header_alloc + sizeof(blk_hdr)); //return pointer to paylod of allocated block
		
    return NULL;
}

/* 
 * Function for freeing up a previously allocated block 
 * Argument - ptr: Address of the block to be freed up 
 * Returns 0 on success 
 * Returns -1 on failure 
 * Here is what this function should accomplish 
 * - Return -1 if ptr is NULL
 * - Return -1 if ptr is not 8 byte aligned or if the block is already freed
 * - Mark the block as free 
 * - Coalesce if one or both of the immediate neighbours are free 
 */                    
int Free_Mem(void *ptr) {                        
    if(ptr == NULL){ //pointer can not be NULL
    	return -1;
    }

    int p = (int) &ptr;// assign address of ptr to int variable

    if((p % 8) != 0){ //if pointer is not a multiple of 8
    	return -1;
    }

    blk_hdr *blk = (blk_hdr*) ((char*)ptr - sizeof(blk_hdr)); // pointer to beginning of header
    
    if((blk->size_status & 1) == 0){ //if  block is already free
    	return -1;
    }

    int prev_size = 0;
    int next_size = 0;
    
    blk->size_status = blk->size_status - 1; //set LSB bit to zero
    int SLB = ((blk->size_status >> 1) & 1); //SLB bit represents status of prev block

    if(SLB == 0){ //if previous block is free
    	blk_hdr *prev_footer = (blk_hdr*) ((char*)blk - sizeof(blk_hdr)); //beginning of prev block's footer
	prev_size = prev_footer->size_status;
	prev_footer = NULL;
    }
    
    blk_hdr *blk_next = (blk_hdr*) ((char*)blk + blk->size_status - (2*SLB)); //pointer to next block
    blk_next->size_status = blk_next->size_status - 2; //set SLB bit to free

    if((blk_next->size_status & 1) == 0){ //if next block is free - LSB is zero
    	next_size = blk_next->size_status; 
    }

    blk_hdr *footer = (blk_hdr*) ((char*)blk + blk->size_status - (2*SLB) + next_size - sizeof(blk_hdr)); //set footer of free block
    footer->size_status = (blk->size_status - (2*SLB) + next_size + prev_size); //set size of footer

    blk_hdr *header = (blk_hdr*) ((char*)blk - prev_size);
    header->size_status = (blk->size_status + prev_size + next_size); //assumption that prev-prev block is allocated
    
    blk = NULL;
    blk_next = NULL;    

    return 0;
}

/*
 * Function used to initialize the memory allocator
 * Not intended to be called more than once by a program
 * Argument - sizeOfRegion: Specifies the size of the chunk which needs to be allocated
 * Returns 0 on success and -1 on failure 
 */                    
int Init_Mem(int sizeOfRegion)
{                         
    int pagesize;
    int padsize;
    int fd;
    int alloc_size;
    void* space_ptr;
    blk_hdr* end_mark;
    static int allocated_once = 0;
  
    if (0 != allocated_once) {
        fprintf(stderr, 
        "Error:mem.c: Init_Mem has allocated space during a previous call\n");
        return -1;
    }
    if (sizeOfRegion <= 0) {
        fprintf(stderr, "Error:mem.c: Requested block size is not positive\n");
        return -1;
    }

    // Get the pagesize
    pagesize = getpagesize();

    // Calculate padsize as the padding required to round up sizeOfRegion 
    // to a multiple of pagesize
    padsize = sizeOfRegion % pagesize;
    padsize = (pagesize - padsize) % pagesize;

    alloc_size = sizeOfRegion + padsize;

    // Using mmap to allocate memory
    fd = open("/dev/zero", O_RDWR);
    if (-1 == fd) {
        fprintf(stderr, "Error:mem.c: Cannot open /dev/zero\n");
        return -1;
    }
    space_ptr = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, 
                    fd, 0);
    if (MAP_FAILED == space_ptr) {
        fprintf(stderr, "Error:mem.c: mmap cannot allocate space\n");
        allocated_once = 0;
        return -1;
    }
  
     allocated_once = 1;

    // for double word alignement and end mark
    alloc_size -= 8;

    // To begin with there is only one big free block
    // initialize heap so that first block meets 
    // double word alignement requirement
    first_blk = (blk_hdr*) space_ptr + 1;
    end_mark = (blk_hdr*)((void*)first_blk + alloc_size);
  
    // Setting up the header
    first_blk->size_status = alloc_size;

    // Marking the previous block as busy
    first_blk->size_status += 2;

    // Setting up the end mark and marking it as busy
    end_mark->size_status = 1;

    // Setting up the footer
    blk_hdr *footer = (blk_hdr*) ((char*)first_blk + alloc_size - 4);
    footer->size_status = alloc_size;
  
    return 0;
}

/* 
 * Function to be used for debugging 
 * Prints out a list of all the blocks along with the following information i
 * for each block 
 * No.      : serial number of the block 
 * Status   : free/busy 
 * Prev     : status of previous block free/busy
 * t_Begin  : address of the first byte in the block (this is where the header starts) 
 * t_End    : address of the last byte in the block 
 * t_Size   : size of the block (as stored in the block header) (including the header/footer)
 */                     
void Dump_Mem() {                        
    int counter;
    char status[5];
    char p_status[5];
    char *t_begin = NULL;
    char *t_end = NULL;
    int t_size;

    blk_hdr *current = first_blk;
    counter = 1;

    int busy_size = 0;
    int free_size = 0;
    int is_busy = -1;

    fprintf(stdout, "************************************Block list***\
                    ********************************\n");
    fprintf(stdout, "No.\tStatus\tPrev\tt_Begin\t\tt_End\t\tt_Size\n");
    fprintf(stdout, "-------------------------------------------------\
                    --------------------------------\n");
  
    while (current->size_status != 1) {
        t_begin = (char*)current;
        t_size = current->size_status;
    
        if (t_size & 1) {
            // LSB = 1 => busy block
            strcpy(status, "Busy");
            is_busy = 1;
            t_size = t_size - 1;
        } else {
            strcpy(status, "Free");
            is_busy = 0;
        }

        if (t_size & 2) {
            strcpy(p_status, "Busy");
            t_size = t_size - 2;
        } else {
            strcpy(p_status, "Free");
        }

        if (is_busy) 
            busy_size += t_size;
        else 
            free_size += t_size;

        t_end = t_begin + t_size - 1;
    
        fprintf(stdout, "%d\t%s\t%s\t0x%08lx\t0x%08lx\t%d\n", counter, status, 
        p_status, (unsigned long int)t_begin, (unsigned long int)t_end, t_size);
    
        current = (blk_hdr*)((char*)current + t_size);
        counter = counter + 1;
    }

    fprintf(stdout, "---------------------------------------------------\
                    ------------------------------\n");
    fprintf(stdout, "***************************************************\
                    ******************************\n");
    fprintf(stdout, "Total busy size = %d\n", busy_size);
    fprintf(stdout, "Total free size = %d\n", free_size);
    fprintf(stdout, "Total size = %d\n", busy_size + free_size);
    fprintf(stdout, "***************************************************\
                    ******************************\n");
    fflush(stdout);

    return;
}
