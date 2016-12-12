#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "utils.h"
#include "f_xy.h"
#include "dsi.h"
#include <sys\timeb.h> 
#include "sha1.h"

u32 tadsrl_keyX[4] = {0x4E00004A, 0x4A00004E, 0, 0};
u8 tadsrl_keyY[16] = {0xcc, 0xfc, 0xa7, 0x03, 0x20, 0x61, 0xbe, 0x84, 0xd3, 0xeb, 0xa4, 0x26, 0xb8, 0x6d, 0xbe, 0xc2};
u8 sd_key[16] = {0x3d, 0xa3, 0xea, 0x33, 0x4c, 0x86, 0xa6, 0xb0, 0x2a, 0xae, 0xdb, 0x51, 0x16, 0xea, 0x92, 0x62};
char modcrypt_shared_key[8] = {'N','i','n','t','e','n','d','o'};
// middle two words are 'NINTENDO' big endian
u32 emmc_keyX_3DS[4] = {0x00000000, 0x544E494E, 0x4F444E45, 0x00000000};
u32 emmc_keyY[4] = {0x0AB9DC76,0xBD4DC4D3,0x202DDD1D,0xE1A00005};
u8 block[0x10];
int i;

typedef struct __attribute__((__packed__)) 
{
        u8  status;
        u8  start_chs[3];
        u8  partition_type;
        u8  end_chs[3];
        u32 start_sector;
        u32 num_sectors;
} mbr_partition;

// laaaaazy!
typedef struct 
{
    u8 code[446];
    mbr_partition partition[4];
    u8 signature[2];
} mbr;

void decrypt_modcrypt_area(dsi_context* ctx, u8 *buffer, unsigned int size)
{
	uint32_t len = size / 0x10;
	while(len>0)
	{
		memset(block, 0, 0x10);
		dsi_crypt_ctr_block(ctx, buffer, block);
		memcpy(buffer, block, 0x10);
		buffer+=0x10;
		len--;
	}
}

// From dsi_srl_extract
int decryptsrl(u8 *srl)
{
	u8 *keyX_ptr = NULL, *keyY_ptr = NULL;
	uint32_t offset, size;
	int verbose=0;
	u8 *header, *buffer;
	u8 key_x[16];
	u8 key_y[16];
	u8 key[16];
	dsi_context ctx;

	header = srl;

	memcpy(key_x, modcrypt_shared_key, 8);

	memcpy(&key_x[8], &header[0x0c], 4);
	key_x[12 + 0] = header[0x0c + 3];
	key_x[12 + 1] = header[0x0c + 2];
	key_x[12 + 2] = header[0x0c + 1];
	key_x[12 + 3] = header[0x0c + 0];
	memcpy(key_y, &header[0x350], 16);
	
	if((header[0x1c] & 4) || (header[0x1bf] & 0x80))
	{
		printf("Crypting dev modcrypt.\n");
	}
	else
	{
		printf("Crypting retail modcrypt.\n");
		keyX_ptr = key_x;
		keyY_ptr = key_y;
	}
	memcpy(key, header, 16);

	printf("Crypting...\n");
	if(keyX_ptr)
	{
		F_XY((uint32_t*)key, (uint32_t*)key_x, (uint32_t*)key_y);
	}
	dsi_set_key(&ctx, key);

	
	memcpy(&offset, &header[0x220], 4);
	memcpy(&size, &header[0x224], 4);
	dsi_set_ctr(&ctx, &header[0x300]);

	if(offset!=0)
	{
		printf("Modcrypt area 0: offset %x size %x\n", offset, size);
		buffer = srl + offset;
		decrypt_modcrypt_area(&ctx, buffer, size);
	}
	else
	{
		printf("Modcrypt area 0 is unused.\n");
	}


	memcpy(&offset, &header[0x228], 4);
	memcpy(&size, &header[0x22c], 4);
	dsi_set_ctr(&ctx, &header[0x314]);

	if(offset!=0)
	{
		printf("Modcrypt area 1: offset %x size %x\n", offset, size);
		buffer = srl + offset;
		decrypt_modcrypt_area(&ctx, buffer, size);
	}
	else
	{
		printf("Modcrypt area 1 is unused.\n");
	}

	printf("Done.\n");
	return 0;
}

void decrypt_boot2_section(u8* data, u32 len, bool is3DS)
{
    u8 normalkey[16] = {0};
    u8 keyX_TWLFIRM[16] = {0xE1, 0xEB, 0xDF, 0x44, 0xAB, 0x1D, 0x81, 0xE3, 0x93, 0x9A, 0x4A, 0xB5, 0x36, 0xFC, 0x3A, 0x0E};
    u8 keyX_DSi[16] = {0x4E, 0x69, 0x6E, 0x74, 0x65, 0x6E, 0x64, 0x6F, 0x20, 0x44, 0x53, 0x00, 0x01, 0x23, 0x21, 0x00};
    u8 keyY_3DS[16] = {0xAB, 0x4E, 0x18, 0xA8, 0x51, 0x16, 0x90, 0x7E, 0x9F, 0x65, 0xF0, 0xCE, 0x21, 0x7C, 0x3A, 0x70};
    u8 keyY_DSi[16] = {0xEC, 0x07, 0x00, 0x00, 0x34, 0xE2, 0x94, 0x7C, 0xC3, 0x0E, 0x81, 0x7C, 0xEC, 0x07, 0x00, 0x00};
    u32 ctr[4];
    memset(ctr, 0, 16);

    int i;

    dsi_context dsictx;
    if(is3DS == true)
        F_XY((u32*) normalkey, (u32*)keyX_TWLFIRM, (u32*)keyY_3DS);
    else
        F_XY((u32*) normalkey, (u32*)keyX_DSi, (u32*)keyY_DSi);

    ctr[0] = len;
    ctr[1] = -len;
    ctr[2] = ~len;
    printf("CTR:\n");
    hexdump(ctr,16);

    printf("Normalkey:\n");
    hexdump(normalkey,16);
    dsi_set_key(&dsictx, normalkey);
    dsi_set_ctr(&dsictx, (u8*)ctr);

    // auto-increments ctr
    for(i = 0; i < len; i+= 0x10)
       dsi_crypt_ctr_block(&dsictx, data+i, data+i);
}

void decrypt_boot2(char* in, bool is3DS)
{
    u32 offset;
    u32 len;
    u8* data;
    FILE* f_in = fopen(in,"r+b");
    FILE* f_out;
    if(f_in == NULL)
    {
        printf("Input filename invalid!");
        return;
    }
    
    // decrypt and write ARM9
    f_out = fopen("arm9.bin","wb");
    fseek(f_in, 0x220, SEEK_SET);
    fread(&offset, 1, sizeof(offset), f_in);
    fseek(f_in, 0x22C, SEEK_SET);
    fread(&len, 1, sizeof(len), f_in);
    
    fseek(f_in, offset, SEEK_SET);
    data = malloc(len);
    fread(data, 1, len, f_in);
    decrypt_boot2_section(data, len, is3DS);
    fwrite(data, 1, len, f_out);
    free(data);
    fclose(f_out);
    
    // decrypt and write ARM7
    f_out = fopen("arm7.bin","wb");
    fseek(f_in, 0x230, SEEK_SET);
    fread(&offset, 1, sizeof(offset), f_in);
    fseek(f_in, 0x23C, SEEK_SET);
    fread(&len, 1, sizeof(len), f_in);
    
    fseek(f_in, offset, SEEK_SET);
    data = malloc(len);
    fread(data, 1, len, f_in);
    decrypt_boot2_section(data, len, is3DS);
    fwrite(data, 1, len, f_out);
    fclose(f_out);
    fclose(f_in);
    free(data);
    
}

void decrypt_srl(char* in, char* out)
{
    FILE* f_in = fopen(in,"r+b");
    FILE* f_out;
    if(!strcmp(in,out))
        f_out = fopen(out,"r+b");
    else
        f_out = fopen(out,"wb");
    if(f_in == NULL)
    {
        printf("Input filename invalid!");
        return;
    }
    
    fseek(f_in, 0L, SEEK_END);
    u32 fsize = ftell(f_in);
    fseek(f_in, 0L, SEEK_SET);
    u8* srl = malloc(fsize);
    fread(srl, 1, fsize, f_in);
    
    decryptsrl(srl);
    
    fwrite(srl, 1, fsize, f_out);
    free(srl);
    fclose(f_in);
    fclose(f_out);
}

void cid_brute_3ds(u32* consoleID, u8* emmc_cid, u8* test_data, char* cidfile, bool isN3DS)
{
    dsi_context ctx;
    int i, diff;
    struct timeb start, end;
    u8 emmc_normalkey[16];
    u8 emmc_cid_hash[20];
    u8 CTR[16];
    
    u8* consoleID8 = (u8*)consoleID;
    
    if(isN3DS == true)
        consoleID[1] = 0x00000002;
    else
        consoleID[1] = 0x00000000;
    emmc_keyX_3DS[3] = consoleID[1] ^ 0x08C267B7;
    

    u8 target_bytes[16] = {0};
    sha1(emmc_cid_hash, emmc_cid, 16);
    memcpy(CTR, emmc_cid_hash, 16);
    
    // store our target ctr so we won't have to copy + increment it every iteration
    dsi_set_ctr(&ctx, (u8*)CTR);
    dsi_add_ctr(&ctx, 0x1E);
    memcpy(CTR, ctx.ctr, 16);
    
    ftime(&start);
    
    // first bit is always set, we only need to brute the bottom 7 bits
    for(i = 0x00000000; i < 0x7FFFFFFF; i++)
    {
        consoleID[0] = i;
        
        memcpy(ctx.ctr, CTR, 16);
        emmc_keyX_3DS[0] = (consoleID[0] ^ 0xB358A6AF) | 0x80000000;
        F_XY((u32*)emmc_normalkey, (u32*) emmc_keyX_3DS, (u32*) emmc_keyY);
        dsi_set_key(&ctx, emmc_normalkey);
        
        dsi_crypt_ctr_block(&ctx, test_data, block);
        
        // if this block decrypts to all zero, we've got the right consoleID.
        if(!memcmp(target_bytes, block, sizeof(target_bytes))){
            // print this as-is without endian flipping!
            printf("Got it!! ConsoleID is ");
            for(i = 0; i < 8; i++)
                printf("%02X", consoleID8[i]);
            printf("\n");
            
            if(cidfile)
            {
                FILE* f = fopen(cidfile, "w+b");
                if(!f)
                {
                    printf("Failed to write CID to %s! Continuing...\n", cidfile);
                    return;
                }
                fwrite(consoleID, 1, sizeof(consoleID), f);
                fclose(f);
            }
            break;
        }
        
        if(!(i % 0x200000))
            printf("CID 0x%08X of 0x7FFFFFFF\n",i);
    }
    ftime(&end);
    diff = (int) (1000.0 * (end.time - start.time)
        + (end.millitm - start.millitm));
    printf("Bruteforce took %u milliseconds\n", diff);
}

void nand_decrypt_3ds(u8 *emmc_cid, u32 *consoleID, char *in, char *out, bool brute_cid, char* cidfile, bool isN3DS)
{
    dsi_context ctx;
    u32 i;
    u8 emmc_normalkey[16];
    u8 emmc_cid_hash[20];
    u8 CTR[16];
    u8 brute_buf[16];
    
    if(brute_cid == true)
    {
        FILE* f_in = fopen(in,"r+b");
        fseek(f_in, 0x1E0, SEEK_SET);
        fread(brute_buf, 1, sizeof(brute_buf), f_in);
        fclose(f_in);
        cid_brute_3ds(consoleID, emmc_cid, brute_buf, cidfile, isN3DS);
    }
    
    // Prepare CTR by SHA1-hashing eMMC CID
    sha1(emmc_cid_hash, emmc_cid, 16);
    memcpy(CTR, emmc_cid_hash, 16);
    dsi_set_ctr(&ctx, (u8*)CTR);

    // Generate AES normalkey from consoleID
    emmc_keyX_3DS[0] = (consoleID[0] ^ 0xB358A6AF) | 0x80000000;
    emmc_keyX_3DS[3] = consoleID[1] ^ 0x08C267B7;
    F_XY((u32*) emmc_normalkey, (u32*) emmc_keyX_3DS, (u32*) emmc_keyY);
    dsi_set_key(&ctx, emmc_normalkey);
    
    FILE* f_in = fopen(in,"r+b");
    FILE* f_out;
    if(!strcmp(in,out))
        f_out = fopen(out,"r+b");
    else
        f_out = fopen(out,"wb");
    if(f_in == NULL)
    {
        printf("Input filename invalid!");
        return;
    }
    for(i = 0; i < 0x0B100000; i += 0x10) 
    {
        fread(block, 1, 0x10, f_in);
        dsi_crypt_ctr_block(&ctx, block, block);
        fwrite(block, 1, 0x10, f_out);
        if(i % 0x1000000 == 0)
            printf("%.2f %% complete.\n",(100.0 * i / 0x0B100000));
    }
    fclose(f_in);
    fclose(f_out);
    printf("Crypt complete!");
}

void file_copy_append(FILE* f_in, FILE* f_out, dsi_context* ctx, u8 disp_progress, u32 start_addr, u32 end_addr)
{
    u32 cur_size;
    const u32 buf_size = 0x100000;
    void* buf = malloc(buf_size);
    if(!buf)
    {
        printf("Failed to allocate %d byte buf for file operation!", buf_size);
        exit(EXIT_FAILURE);
    }
    
    fseek(f_in, start_addr, SEEK_SET);
    
    for(i = start_addr; i < end_addr; i += buf_size)
    {
        cur_size = (end_addr - i) >= buf_size ? buf_size : end_addr - i;
        fread(buf, 1, cur_size, f_in);
        
        // do CTR crypto if a ctx is supplied
        if(ctx)
            dsi_crypt_ctr(ctx, buf, buf, cur_size);
        fwrite(buf, 1, cur_size, f_out);
        
        //update progress every 16MB
        if(disp_progress && (((i - start_addr) / buf_size) % 25) == 0)
            printf("%.2f %% complete.\n",100.0 * (i - start_addr) / (end_addr - start_addr));
    }
    if(disp_progress)
        printf("100.00%% complete.\n");
    free(buf);
}

void nand_decrypt_dsi(u8 *emmc_cid, u32 *consoleID, char *in, char *out)
{
    dsi_context ctx;
    u32 i;
    u32 emmc_keyX[4];
    u8 emmc_normalkey[16];
    u8 emmc_cid_hash[20];
    u8 base_ctr[16];
    mbr mbr;
    
    // Prepare AES CTR by SHA1-hashing eMMC CID
    sha1(emmc_cid_hash, emmc_cid, 16);
    memcpy(base_ctr, emmc_cid_hash, 16);
    dsi_set_ctr(&ctx, (u8*)base_ctr);
    
    // Endian-swap the input ConsoleID (provided from tad footer)
    consoleID[1] = getbe32((u8*)consoleID);
    consoleID[0] = getbe32((u8*)consoleID+4);    
    
    // Generate AES normalkey from consoleID (which comes in reverse word order)
    emmc_keyX[0] = consoleID[0];
    emmc_keyX[1] = consoleID[0] ^ 0x24EE6906;
    emmc_keyX[2] = consoleID[1] ^ 0xE65B601D;
    emmc_keyX[3] = consoleID[1];
    F_XY((u32*) emmc_normalkey, (u32*) emmc_keyX, (u32*) emmc_keyY);
    dsi_set_key(&ctx, emmc_normalkey);
    
    FILE* f_in = fopen(in,"r+b");
    FILE* f_out;
    if(!strcmp(in,out))
        f_out = fopen(out,"r+b");
    else
        f_out = fopen(out,"wb");
    if(f_in == NULL)
    {
        printf("Input filename invalid!");
        return;
    }
    
    // get MBR from encrypted or decrypted NAND
    fread(&mbr, 1, 0x200, f_in);
    if(mbr.signature[0] != 0x55 || mbr.signature[1] != 0xAA)
    {
        dsi_crypt_ctr(&ctx, &mbr, &mbr, 0x200);
        if(mbr.signature[0] != 0x55 || mbr.signature[1] != 0xAA)
        {
            printf("MBR verification failed! Make sure your CID and consoleID are correct.");
            fclose(f_in);
            fclose(f_out);
            return;
        }
    }

    // process NAND parts (encrypted and otherwise)
    rewind(f_in);
    
    // process MBR
    dsi_set_ctr(&ctx, (u8*)base_ctr);
    file_copy_append(f_in, f_out, &ctx, 0, 0, 0x200);
    
    
    // process space before partition 1, including stage 2 bootloader etc
    file_copy_append(f_in, f_out, NULL, 0, 0x200, 0x10EE00);
    
    // process twln
    printf("Processing twln...\n");
    dsi_set_ctr(&ctx, (u8*)base_ctr);
    dsi_add_ctr(&ctx, 0x10EE00 / 0x10);
    file_copy_append(f_in, f_out, &ctx, 1, 0x10EE00, 0x0CF00000);
    
    // process space before partition 2
    file_copy_append(f_in, f_out, NULL, 0, 0x0CF00000, 0x0CF09A00);
    
    // process twlp
    printf("Processing twlp...\n");
    dsi_set_ctr(&ctx, (u8*)base_ctr);
    dsi_add_ctr(&ctx, 0x0CF09A00 / 0x10);
    file_copy_append(f_in, f_out, &ctx, 1, 0x0CF09A00, 0x0EFC0000);
    
    // process the rest, including unused (and unencrypted) third partition)
    file_copy_append(f_in, f_out, NULL, 0, 0x0EFC0000, 0x0F000000);
    
    fclose(f_in);
    fclose(f_out);
    printf("Crypt complete!");
}

/**
 * crypt system files (tickets, dev.kp) with ES Block crypto
 */
void es_crypt_file(char* in, char* out, u32 consoleID[2], bool encrypt, bool is3DS)
{
    u8 es_system_keyY[16] = {0xE5, 0xCC, 0x5A, 0x8B, 0x56, 0xD0, 0xC9, 0x72, 0x9C, 0x17, 0xE8, 0xDC, 0x39, 0x12, 0x36, 0xA9};
    u32 in_size;
    u32 write_size = 0;
    int ret = 0;
    u32 normalkey[4];
    dsi_es_context ctx;
    
    FILE* f_in = fopen(in,"r+b");
    FILE* f_out;
    if(!strcmp(in,out))
        f_out = fopen(out,"r+b");
    else
        f_out = fopen(out,"wb");
    if(f_in == NULL)
    {
        printf("Input filename invalid! %s", in);
        return;
    }
    if(f_out == NULL)
    {
        printf("Output filename invalid! %s", out);
        return;
    }
    fseek(f_in, 0, SEEK_END);
    in_size = ftell(f_in);
    rewind(f_in);
    
    void* in_data = malloc(in_size);
    if(!in_data)
    {
        printf("Failed to allocate input file buf!");
        return;
    }
    fread(in_data, 1, in_size, f_in);
    
    if(is3DS == false)
    {
        // Endian-swap the input ConsoleID (provided from tad footer)
        consoleID[1] = getbe32((u8*)consoleID);
        consoleID[0] = getbe32((u8*)consoleID+4);
    }
    // set up keys for crypto (consoleid is in reverse word order)
    tadsrl_keyX[2] = consoleID[1] ^ 0xC80C4B72;
    tadsrl_keyX[3] = consoleID[0];
    F_XY(normalkey, tadsrl_keyX, (u32*)es_system_keyY);
    dsi_es_init(&ctx, (u8*)normalkey);

    if(encrypt == false)
    {
        // decrypt!
        write_size = in_size - 0x20;
        ret = dsi_es_decrypt(&ctx, in_data, in_data + write_size, write_size);
        if(ret == -1)
        {
            printf("ES magic check failed! Is your consoleID correct?");
            return;
        }
        else if(ret == -2)
        {
            printf("Decrypted file size is incorrect!");
            return;
        }
        else if(ret == -3)
        {
            printf("MAC mismatch! Continuing...");
            return;
        }
        fwrite(in_data, 1, write_size, f_out);
        printf("ES decrypt success!");
    }
    else
    {
        // encrypt!
        u8 metablock[32];
        
        dsi_es_encrypt(&ctx, in_data, metablock, in_size);
        fwrite(in_data, 1, in_size, f_out);
        fwrite(metablock, 1, 0x20, f_out);
        printf("ES encrypt complete!");
    }
    
    fclose(f_in);
    fclose(f_out);
    free(in_data);
}

/*
 * Read a string and get a byte array or contents of a file from it
 * returns 0 on success
 */
int read_hex_file_string(char* str, u8* buf, int len)
{
    FILE* f = fopen(str, "rb");
    if(f)
    {
        fseek(f, 0L, SEEK_END);
        u32 fsize = ftell(f);
        rewind(f);
        if(fsize == len)
        {
            fread(buf, 1, len, f);
            fclose(f);
            return 0;
        }
        else
        {
            printf("Invalid file size for %s! Expected 0x%x, got 0x%x\n", str, len, fsize);
            return 1;
        }
    }
    
    if(hex2bytes(str, strlen(str), buf, len))
        return 1;
    return 0;
}

void display_help()
{
    printf("Usage: twltool <command> [args]\n");
    printf("Commands:\n");
    printf("  nandcrypt\n");
    printf("  modcrypt\n");
    printf("  boot2\n");
    printf("  syscrypt\n");
    printf("nandcrypt: (de)crypt DSi NAND\n");
    printf("  --cid [file/hex CID]          eMMC CID\n");
    printf("  --consoleid [file/hex ID]     DSi ConsoleID\n");
    printf("  --in [infile]                 Input image\n");
    printf("  --out [outfile]               Output file (optional)\n");
    printf("  --3ds                         Crypt 3DS TWLNAND\n");
    printf("    --3dsbrute                  Bruteforce 3DS ConsoleID\n");
    printf("    --cidfile [outfile]         Output name for bruteforced CID (optional)\n");
    printf("      --n3ds                    New3DS bruteforce (use with --3ds)\n");
    printf("modcrypt: (de)crypt SRL modcrypt sections\n");
    printf("  --in [infile]                 Input SRL\n");
    printf("  --out [outfile]               Output file (optional)\n");
    printf("boot2: decrypt boot2 image to arm7.bin and arm9.bin\n");
    printf("  --in [infile]                 Input image\n");
    printf("  --debug                       Crypt debug boot2 (devkits, TWL_FIRM, ...)\n");
    printf("syscrypt: crypt system files with ES block crypto (dev.kp, tickets, ...)\n");
    printf("  --in [infile]                 Input SRL\n");
    printf("  --out [outfile]               Output file (optional)\n");
    printf("  --consoleid [file/hex ID]     DSi ConsoleID\n");
    printf("  --encrypt                     Encrypt file\n");
    printf("  --3ds                         Using 3DS ConsoleID");
}

int main(int argc, char* argv[])
{
    u8 consoleID[8] = {0};
    u8 cid[16] = {0};
    char in[400] = {0};
    char out[400] = {0};
    char cidfile[400] = {0};
    bool is3DS = false;
    bool brute_cid = false;
    bool isN3DS = false;
    bool encrypt = false;
    
    printf("TWLTool v1.6\n");
    printf("  by WulfyStylez\n");
    printf("  Special thanks to CaitSith2\n\n");
    if(argc <= 1)
        display_help();
    else
    {
        if(!strcmp(argv[1], "nandcrypt"))
        {
            if(argc < 6) {
                printf("Invalid options!\n");
                display_help();
                exit(EXIT_FAILURE);
            }
            for(i = 0; i < argc; i++)
            {
                if(!strcmp(argv[i],"--consoleid")) {
                    if(read_hex_file_string(argv[i+1], consoleID, 8))
                        exit(EXIT_FAILURE);
                }
                if(!strcmp(argv[i],"--cid")) {
                    if(read_hex_file_string(argv[i+1], cid, 16))
                        exit(EXIT_FAILURE);
                }
                if(!strcmp(argv[i],"--3ds"))
                    is3DS = true;
                if(!strcmp(argv[i],"--3dsbrute"))
                    brute_cid = true;
                if(!strcmp(argv[i],"--n3ds"))
                    isN3DS = true;
                if(!strcmp(argv[i],"--in")) {
                    strcpy(in, argv[i+1]);
                }
                if(!strcmp(argv[i],"--out")) {
                    strcpy(out, argv[i+1]);
                }
                if(!strcmp(argv[i],"--cidfile")) {
                    strcpy(cidfile, argv[i+1]);
                }
            }
            if(in[0] == 0) {
                printf("Invalid filename!\n");
                display_help();
                exit(EXIT_FAILURE);
            }
            if(out[0] == 0)
                strcpy(out,in);
            if(is3DS)
                nand_decrypt_3ds(cid, (u32*)consoleID, in, out, brute_cid, cidfile, isN3DS);
            else
                nand_decrypt_dsi(cid, (u32*)consoleID, in, out);
        }
        else if(!strcmp(argv[1], "modcrypt"))
        {
            if(argc < 4) {
                printf("Invalid options!\n");
                display_help();
                exit(EXIT_FAILURE);
            }
            for(i = 0; i < argc; i++)
            {
                if(!strcmp(argv[i],"--in")) {
                    strcpy(in, argv[i+1]);
                }
                if(!strcmp(argv[i],"--out")) {
                    strcpy(out, argv[i+1]);
                }
            }
            if(in[0] == 0) {
                printf("Invalid filename!\n");
                display_help();
                exit(EXIT_FAILURE);
            }
            if(out[0] == 0)
                strcpy(out,in);
            decrypt_srl(in, out);
        }
        else if(!strcmp(argv[1], "boot2"))
        {
            if(argc < 4) {
                printf("Invalid options!\n");
                display_help();
                exit(EXIT_FAILURE);
            }
            for(i = 0; i < argc; i++)
            {
                if(!strcmp(argv[i],"--in")) {
                    strcpy(in, argv[i+1]);
                }
                if(!strcmp(argv[i],"--debug")) {
                    is3DS = 1;
                }
            }
            if(in[0] == 0) {
                printf("Invalid filename!\n");
                display_help();
                exit(EXIT_FAILURE);
            }
            decrypt_boot2(in, is3DS);
        }
        else if(!strcmp(argv[1], "syscrypt"))
        {
            if(argc < 6) {
                printf("Invalid options!\n");
                display_help();
                exit(EXIT_FAILURE);
            }
            for(i = 0; i < argc; i++)
            {
                if(!strcmp(argv[i],"--in")) {
                    strcpy(in, argv[i+1]);
                }
                if(!strcmp(argv[i],"--out")) {
                    strcpy(out, argv[i+1]);
                }
                if(!strcmp(argv[i],"--consoleid")) {
                    if(read_hex_file_string(argv[i+1], consoleID, 8))
                        exit(EXIT_FAILURE);
                }
                if(!strcmp(argv[i],"--encrypt")) {
                    encrypt = true;
                }
                if(!strcmp(argv[i],"--3ds"))
                    is3DS = true;
            }
            if(in[0] == 0) {
                printf("Invalid input filename! %s\n", in);
                display_help();
                exit(EXIT_FAILURE);
            }
            if(out[0] == 0)
                strcpy(out,in);
            es_crypt_file(in, out, (u32*)consoleID, encrypt, is3DS);
        }
        else
        {
            printf("Invalid command!\n");
            display_help();
            exit(EXIT_FAILURE);
        }
    }
    
	return 0;
}
