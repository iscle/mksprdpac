#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <memory.h>
#include <endian.h>
#include <fcntl.h>
#include <unistd.h>

typedef struct {
    char *id;
    char *file_path;
    uint16_t file_flag;
    uint8_t check_flag;
    uint8_t omit_flag;
    uint32_t addr1;
    uint32_t addr2;
} FileParam;

typedef struct {
    int16_t szVersion[24];          // packet struct version, unicode, total size is 48 bytes
    uint32_t dwSize;                // the whole packet size, 4 bytes
    int16_t szPrdName[256];         // product name, total size is 512 bytes
    int16_t szPrdVersion[256];      // product version, total size is 512 bytes
    uint32_t nFileCount;            // the number of files that will be downloaded, the file may be an operation, 4 bytes
    uint32_t dwFileOffset;          // the offset from the packet file header to the array of FILE_T struct buffer, 4 bytes
    uint32_t dwMode;                // 4 bytes
    uint32_t dwFlashType;           // 4 bytes
    uint32_t dwNandStrategy;        // 4 bytes
    uint32_t dwIsNvBackup;          // 4 bytes
    uint32_t dwNandPageType;        // 4 bytes
    int16_t szPrdAlias[100];        // 200 bytes
    uint32_t dwOmaDmProductFlag;    // 4 bytes
    uint32_t dwIsOmaDm;             // 4 bytes
    uint32_t dwIsPreload;           // 4 bytes
    uint8_t dwReserved[800];        // 800 bytes
    uint32_t dwMagic;               // 4 bytes
    uint16_t wCRC1;                 // 2 bytes
    uint16_t wCRC2;                 // 2 bytes
} PACHeader;                        // total 2124 bytes

typedef struct {
    uint32_t dwSize;            // size of this struct itself
    int16_t szFileID[256];      // file ID, such as FDL, Fdl2, NV and etc. 512 bytes
    int16_t szFileName[256];    // file name, in the packet bin file, it only stores file name. 512 bytes
    // but after unpacketing, it stores the full path of bin file
    int16_t szFileVersion[256]; // Reserved now. 512 bytes
    uint32_t nFileSize;         // file size
    uint32_t nFileFlag;         // if "0", means that it need not a file, and
    // it is only an operation or a list of operations, such as file ID is "FLASH"
    // if "1", means that it need a file
    uint32_t nCheckFlag;        // if "1", this file must be downloaded
    // if "0", this file can not be downloaded
    uint32_t dwDataOffset;      // the offset from the packet file header to this file data
    uint32_t dwCanOmitFlag;     // if "1", this file can not be downloaded and not check it as "All files"
    // in download and spupgrade tool
    uint32_t dwAddrNum;
    uint32_t dwAddr[5];         // 4*5 bytes
    uint32_t dwReserved[249];   // Reserved for future, not used now. 249*4 bytes
} FileInfoHeader;

const uint16_t crc16_table[] = {
        0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
        0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
        0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
        0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
        0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
        0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
        0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
        0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
        0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
        0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
        0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
        0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
        0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
        0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
        0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
        0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
        0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
        0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
        0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
        0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
        0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
        0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
        0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
        0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
        0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
        0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
        0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
        0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
        0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
        0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
        0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
        0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040
};

void mkutf16le(int16_t *dst, const char *src) {
    size_t i;
    for (i = 0; src[i] != '\0'; i++) {
        dst[i] = htole16((int16_t) src[i]);
    }
    dst[i] = htole16((int16_t) '\0');
}

uint32_t getFileSize(const char *filename) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0)
        return 0;
    uint32_t fileSize = lseek(fd, 0, SEEK_END);
    close(fd);
    return fileSize;
}

void writePACHeader(int fd, const char *pac_prj, const char *pac_ver, uint32_t file_count) {
    // Start writing PACHeader
    int16_t buf[256];
    uint32_t tmp = 0;

    // szVersion
    memset(buf, 0, sizeof(buf));
    mkutf16le(buf, "BP_R1.0.0");
    write(fd, buf, 48);

    // dwSize
    tmp = htole32(0);
    write(fd, &tmp, 4);

    // szPrdName
    memset(buf, 0, sizeof(buf));
    mkutf16le(buf, pac_prj);
    write(fd, buf, 512);

    // szPrdVersion
    memset(buf, 0, sizeof(buf));
    mkutf16le(buf, pac_ver);
    write(fd, buf, 512);

    // nFileCount
    tmp = htole32(file_count);
    write(fd, &tmp, 4);

    // dwFileOffset
    tmp = htole32(2124);
    write(fd, &tmp, 4);

    // dwMode
    tmp = htole32(0);
    write(fd, &tmp, 4);

    // dwFlashType
    tmp = htole32(0);
    write(fd, &tmp, 4);

    // dwNandStrategy
    tmp = htole32(0);
    write(fd, &tmp, 4);

    // dwIsNvBackup
    tmp = htole32(1);
    write(fd, &tmp, 4);

    // szPrdAlias
    memset(buf, 0, sizeof(buf));
    mkutf16le(buf, pac_prj);
    write(fd, buf, 200);

    // dwOmaDmProductFlag
    tmp = htole32(0);
    write(fd, &tmp, 4);

    // dwIsOmaDM
    tmp = htole32(1);
    write(fd, &tmp, 4);

    // dwIsPreload
    tmp = htole32(1);
    write(fd, &tmp, 4);

    // dwReserved (800 bytes)
    memset(buf, 0, sizeof(buf)); // Only 512 bytes!
    write(fd, buf, 400);
    write(fd, buf, 400);

    // dwMagic
    tmp = htole32(0xFFFAFFFA);
    write(fd, &tmp, 4);

    // wCRC1
    tmp = htole16(0);
    write(fd, &tmp, 2);

    // wCRC2
    tmp = htole16(0);
    write(fd, &tmp, 2);
    // End writing PACHeader
}

void writeFileInfoHeader(int fd, const FileParam *fp, uint32_t *offset) {
    uint32_t file_size = 0;
    uint32_t tmp;
    int16_t buf[256];

    // dwSize
    tmp = htole32(2580);
    write(fd, &tmp, 4);

    // szFileID
    memset(buf, 0, sizeof(buf));
    mkutf16le(buf, fp->id);
    write(fd, buf, 512);

    // szFileName
    memset(buf, 0, sizeof(buf));
    mkutf16le(buf, fp->file_path);
    write(fd, buf, 512);

    // szFileVersion
    memset(buf, 0, sizeof(buf));
    write(fd, buf, 512);

    // nFileSize
    if (fp->file_flag != 0 && (fp->check_flag != 0 || fp->file_flag == 2)) {
        file_size = getFileSize(fp->file_path);
        tmp = htole32(file_size);
    } else {
        tmp = htole32(0);
    }
    write(fd, &tmp, 4);

    // nFileFlag
    tmp = htole32(fp->file_flag);
    write(fd, &tmp, 4);

    // nCheckFlag
    tmp = htole32(fp->check_flag);
    write(fd, &tmp, 4);

    // dwDataOffset
    if (fp->file_flag != 0 && (fp->check_flag != 0 || fp->file_flag == 2)) {
        tmp = htole32(*offset);
    } else {
        tmp = htole32(0);
    }
    write(fd, &tmp, 4);

    // dwCanOmitFlag
    tmp = htole32(fp->omit_flag);
    write(fd, &tmp, 4);

    // dwAddrNum && dwAddr
    if (fp->file_flag != 2) {
        if (fp->addr2 != 0xFFFFFFFF) {
            // dwAddrNum
            tmp = htole32(2);
            write(fd, &tmp, 4);

            // dwAddr
            tmp = htole32(fp->addr1);
            write(fd, &tmp, 4);
            tmp = htole32(fp->addr2);
            write(fd, &tmp, 4);
            tmp = htole32(0);
            write(fd, &tmp, 4);
            write(fd, &tmp, 4);
            write(fd, &tmp, 4);
        } else {
            // dwAddrNum
            tmp = htole32(1);
            write(fd, &tmp, 4);

            // dwAddr
            tmp = htole32(fp->addr1);
            write(fd, &tmp, 4);
            tmp = htole32(0);
            write(fd, &tmp, 4);
            write(fd, &tmp, 4);
            write(fd, &tmp, 4);
            write(fd, &tmp, 4);
        }
    } else {
        // dwAddrNum && dwAddr
        tmp = htole32(0);
        write(fd, &tmp, 4);
        write(fd, &tmp, 4);
        write(fd, &tmp, 4);
        write(fd, &tmp, 4);
        write(fd, &tmp, 4);
        write(fd, &tmp, 4);
    }

    // dwReserved
    memset(buf, 0, sizeof(buf));
    write(fd, buf, 249);
    write(fd, buf, 249);
    write(fd, buf, 249);
    write(fd, buf, 249);

    *offset += file_size;
}

void writeDlFile(int fd, const FileParam *fp) {
    int fd2 = open(fp->file_path, O_RDONLY);
    if (fd < 0)
        return;

    uint8_t buf[1024 * 1024];
    uint32_t file_size = lseek(fd2, 0, SEEK_END);
    lseek(fd2, 0, SEEK_SET);
    uint32_t left = file_size;

    do {
        uint32_t len;
        if (left > sizeof(buf)) {
            len = sizeof(buf);
        } else {
            len = left;
        }
        read(fd2, buf, len);
        write(fd2, buf, len);
        left -= len;
    } while (left > 0);

    close(fd2);
}

uint16_t crc16(uint16_t crc, const uint8_t *data, size_t len) {
    while (len--)
        crc = (crc >> 8) ^ crc16_table[(crc ^ *data++) & 0xFF];
    return crc;
}

uint16_t calc_crc1(int fd) {
    uint8_t buf[2120];

    lseek(fd, 0, SEEK_SET);
    read(fd, buf, sizeof(buf));
    return crc16(0, buf, sizeof(buf));
}

uint16_t calc_crc2(int fd, uint32_t offset) {
    uint8_t buf[1024 * 1024];
    uint32_t size = offset - 2124;
    uint32_t left = size;
    uint16_t crc = 0;

    do {
        uint32_t len;
        if (left > sizeof(buf)) {
            len = sizeof(buf);
        } else {
            len = left;
        }
        read(fd, buf, len);
        crc = crc16(crc, buf, len);
        left -= len;
    } while (left > 0);

    return crc;
}

void usage(const char *progname) {
    printf("Usage: %s <pac_file> <pac_project> <pac_version> <config_file> <fdl_file> <fdl2_file> <nv_file> <bootloader_file> <ps_file> <mmires_file> <udisk_file>\n",
           progname);
}

int main(int argc, char *argv[]) {
    if (argc < 11) {
        usage(argv[0]);
        return 1;
    }

    argv++; // Get the binary name out of the way

    int fd = open(argv[0], O_CREAT | O_RDWR);
    if (fd < 0) {
        printf("Failed to open output file\n");
        return 1;
    }

    const FileParam fp1[] = {
            {
                    .id = "FDL",
                    .file_path = argv[4],
                    .file_flag = 0x0101,
                    .check_flag = 1,
                    .omit_flag = 0,
                    .addr1 = 0x40004000,
                    .addr2 = 0xFFFFFFFF
            },
            {
                    .id = "FDL2",
                    .file_path = argv[5],
                    .file_flag = 0x0101,
                    .check_flag = 1,
                    .omit_flag = 0,
                    .addr1 = 0x14000000,
                    .addr2 = 0xFFFFFFFF
            },
            {
                    .id = "NV",
                    .file_path = argv[6],
                    .file_flag = 1,
                    .check_flag = 1,
                    .omit_flag = 0,
                    .addr1 = 0x90000001,
                    .addr2 = 0xFFFFFFFF
            },
            {
                    .id = "PS",
                    .file_path = argv[8],
                    .file_flag = 1,
                    .check_flag = 1,
                    .omit_flag = 0,
                    .addr1 = 0x80000003,
                    .addr2 = 0xFFFFFFFF
            },
            {
                    .id = "MMIRes",
                    .file_path = argv[9],
                    .file_flag = 1,
                    .check_flag = 1,
                    .omit_flag = 1,
                    .addr1 = 0x90000004,
                    .addr2 = 0xFFFFFFFF
            },
            {
                    .id = "EraseUdisk",
                    .file_path = "",
                    .file_flag = 0,
                    .check_flag = 1,
                    .omit_flag = 0,
                    .addr1 = 0x90000005,
                    .addr2 = 0xFFFFFFFF
            },
            {
                    .id = "UDISK",
                    .file_path = argv[10],
                    .file_flag = 1,
                    .check_flag = 1,
                    .omit_flag = 1,
                    .addr1 = 0x90000006,
                    .addr2 = 0xFFFFFFFF
            },
            {
                    .id = "FLASH",
                    .file_path = "",
                    .file_flag = 0,
                    .check_flag = 1,
                    .omit_flag = 0,
                    .addr1 = 0x90000003,
                    .addr2 = 0xFFFFFFFF
            },
            {
                    .id = "PhaseCheck",
                    .file_path = "",
                    .file_flag = 0,
                    .check_flag = 1,
                    .omit_flag = 0,
                    .addr1 = 0x90000002,
                    .addr2 = 0xFFFFFFFF
            },
            {
                    .id = "",
                    .file_path = argv[3],
                    .file_flag = 2,
                    .check_flag = 0,
                    .omit_flag = 0,
                    .addr1 = 0x0,
                    .addr2 = 0xFFFFFFFF
            },
    };

    const FileParam fp2[] = {
            {
                    .id = "FDL",
                    .file_path = argv[4],
                    .file_flag = 0x0101,
                    .check_flag = 1,
                    .omit_flag = 0,
                    .addr1 = 0x40004000,
                    .addr2 = 0xFFFFFFFF
            },
            {
                    .id = "FDL2",
                    .file_path = argv[5],
                    .file_flag = 0x0101,
                    .check_flag = 1,
                    .omit_flag = 0,
                    .addr1 = 0x14000000,
                    .addr2 = 0xFFFFFFFF
            },
            {
                    .id = "NV",
                    .file_path = argv[6],
                    .file_flag = 1,
                    .check_flag = 1,
                    .omit_flag = 0,
                    .addr1 = 0x90000001,
                    .addr2 = 0xFFFFFFFF
            },
            {
                    .id = "BOOTLOADER",
                    .file_path = argv[7],
                    .file_flag = 1,
                    .check_flag = 1,
                    .omit_flag = 0,
                    .addr1 = 0x80000000,
                    .addr2 = 0xFFFFFFFF
            },
            {
                    .id = "PS",
                    .file_path = argv[8],
                    .file_flag = 1,
                    .check_flag = 1,
                    .omit_flag = 0,
                    .addr1 = 0x80000003,
                    .addr2 = 0xFFFFFFFF
            },
            {
                    .id = "MMIRes",
                    .file_path = argv[9],
                    .file_flag = 1,
                    .check_flag = 1,
                    .omit_flag = 1,
                    .addr1 = 0x90000004,
                    .addr2 = 0xFFFFFFFF
            },
            {
                    .id = "EraseUdisk",
                    .file_path = "",
                    .file_flag = 0,
                    .check_flag = 1,
                    .omit_flag = 0,
                    .addr1 = 0x90000005,
                    .addr2 = 0xFFFFFFFF
            },
            {
                    .id = "UDISK",
                    .file_path = argv[10],
                    .file_flag = 1,
                    .check_flag = 1,
                    .omit_flag = 1,
                    .addr1 = 0x90000006,
                    .addr2 = 0xFFFFFFFF
            },
            {
                    .id = "FLASH",
                    .file_path = "",
                    .file_flag = 0,
                    .check_flag = 1,
                    .omit_flag = 0,
                    .addr1 = 0x90000003,
                    .addr2 = 0xFFFFFFFF
            },
            {
                    .id = "PhaseCheck",
                    .file_path = "",
                    .file_flag = 0,
                    .check_flag = 1,
                    .omit_flag = 0,
                    .addr1 = 0x90000002,
                    .addr2 = 0xFFFFFFFF
            },
            {
                    .id = "",
                    .file_path = argv[3],
                    .file_flag = 2,
                    .check_flag = 0,
                    .omit_flag = 0,
                    .addr1 = 0x0,
                    .addr2 = 0xFFFFFFFF
            },
    };

    const FileParam fp3[] = {
            {
                    .id = "FDL",
                    .file_path = argv[4],
                    .file_flag = 0x0101,
                    .check_flag = 1,
                    .omit_flag = 0,
                    .addr1 = 0x40004000,
                    .addr2 = 0xFFFFFFFF
            },
            {
                    .id = "FDL2",
                    .file_path = argv[5],
                    .file_flag = 0x0101,
                    .check_flag = 1,
                    .omit_flag = 0,
                    .addr1 = 0x14000000,
                    .addr2 = 0xFFFFFFFF
            },
            {
                    .id = "NV",
                    .file_path = argv[6],
                    .file_flag = 1,
                    .check_flag = 1,
                    .omit_flag = 0,
                    .addr1 = 0x90000001,
                    .addr2 = 0xFFFFFFFF
            },
            {
                    .id = "PS",
                    .file_path = argv[8],
                    .file_flag = 1,
                    .check_flag = 1,
                    .omit_flag = 0,
                    .addr1 = 0x80000003,
                    .addr2 = 0xFFFFFFFF
            },
            {
                    .id = "MMIRes",
                    .file_path = argv[9],
                    .file_flag = 1,
                    .check_flag = 1,
                    .omit_flag = 1,
                    .addr1 = 0x90000004,
                    .addr2 = 0xFFFFFFFF
            },
            {
                    .id = "DSPCode",
                    .file_path = "",
                    .file_flag = 1,
                    .check_flag = 2,
                    .omit_flag = 1,
                    .addr1 = 0x90000009,
                    .addr2 = 0xFFFFFFFF
            },
            {
                    .id = "EraseUdisk",
                    .file_path = "",
                    .file_flag = 0,
                    .check_flag = 1,
                    .omit_flag = 0,
                    .addr1 = 0x90000005,
                    .addr2 = 0xFFFFFFFF
            },
            {
                    .id = "UDISK",
                    .file_path = argv[10],
                    .file_flag = 1,
                    .check_flag = 1,
                    .omit_flag = 1,
                    .addr1 = 0x90000006,
                    .addr2 = 0xFFFFFFFF
            },
            {
                    .id = "FLASH",
                    .file_path = "",
                    .file_flag = 0,
                    .check_flag = 1,
                    .omit_flag = 0,
                    .addr1 = 0x90000003,
                    .addr2 = 0xFFFFFFFF
            },
            {
                    .id = "PhaseCheck",
                    .file_path = "",
                    .file_flag = 0,
                    .check_flag = 1,
                    .omit_flag = 0,
                    .addr1 = 0x90000002,
                    .addr2 = 0xFFFFFFFF
            },
            {
                    .id = "",
                    .file_path = argv[3],
                    .file_flag = 2,
                    .check_flag = 0,
                    .omit_flag = 0,
                    .addr1 = 0x0,
                    .addr2 = 0xFFFFFFFF
            },
    };

    const FileParam fp4[] = {
            {
                    .id = "FDL",
                    .file_path = argv[4],
                    .file_flag = 0x0101,
                    .check_flag = 1,
                    .omit_flag = 0,
                    .addr1 = 0x40004000,
                    .addr2 = 0xFFFFFFFF
            },
            {
                    .id = "FDL2",
                    .file_path = argv[5],
                    .file_flag = 0x0101,
                    .check_flag = 1,
                    .omit_flag = 0,
                    .addr1 = 0x14000000,
                    .addr2 = 0xFFFFFFFF
            },
            {
                    .id = "NV",
                    .file_path = argv[6],
                    .file_flag = 1,
                    .check_flag = 1,
                    .omit_flag = 0,
                    .addr1 = 0x90000001,
                    .addr2 = 0xFFFFFFFF
            },
            {
                    .id = "BOOTLOADER",
                    .file_path = argv[7],
                    .file_flag = 1,
                    .check_flag = 1,
                    .omit_flag = 0,
                    .addr1 = 0x80000000,
                    .addr2 = 0xFFFFFFFF
            },
            {
                    .id = "PS",
                    .file_path = argv[8],
                    .file_flag = 1,
                    .check_flag = 1,
                    .omit_flag = 0,
                    .addr1 = 0x80000003,
                    .addr2 = 0xFFFFFFFF
            },
            {
                    .id = "MMIRes",
                    .file_path = argv[9],
                    .file_flag = 1,
                    .check_flag = 1,
                    .omit_flag = 1,
                    .addr1 = 0x90000004,
                    .addr2 = 0xFFFFFFFF
            },
            {
                    .id = "DSPCode",
                    .file_path = "",
                    .file_flag = 1,
                    .check_flag = 2,
                    .omit_flag = 1,
                    .addr1 = 0x90000009,
                    .addr2 = 0xFFFFFFFF
            },
            {
                    .id = "EraseUdisk",
                    .file_path = "",
                    .file_flag = 0,
                    .check_flag = 1,
                    .omit_flag = 0,
                    .addr1 = 0x90000005,
                    .addr2 = 0xFFFFFFFF
            },
            {
                    .id = "UDISK",
                    .file_path = argv[10],
                    .file_flag = 1,
                    .check_flag = 1,
                    .omit_flag = 1,
                    .addr1 = 0x90000006,
                    .addr2 = 0xFFFFFFFF
            },
            {
                    .id = "FLASH",
                    .file_path = "",
                    .file_flag = 0,
                    .check_flag = 1,
                    .omit_flag = 0,
                    .addr1 = 0x90000003,
                    .addr2 = 0xFFFFFFFF
            },
            {
                    .id = "PhaseCheck",
                    .file_path = "",
                    .file_flag = 0,
                    .check_flag = 1,
                    .omit_flag = 0,
                    .addr1 = 0x90000002,
                    .addr2 = 0xFFFFFFFF
            },
            {
                    .id = "",
                    .file_path = argv[3],
                    .file_flag = 2,
                    .check_flag = 0,
                    .omit_flag = 0,
                    .addr1 = 0x0,
                    .addr2 = 0xFFFFFFFF
            },
    };

    const FileParam *fp;
    int file_count;
    if (argv[7][0] == '\0' && argv[11][0] == '\0') {
        fp = fp1;
        file_count = 10;
    } else if (argv[7][0] != '\0' && argv[11][0] == '\0') {
        fp = fp2;
        file_count = 11;
    } else if (argv[7][0] == '\0' && argv[11][0] != '\0') {
        fp = fp3;
        file_count = 11;
    } else {
        fp = fp4;
        file_count = 12;
    }

    writePACHeader(fd, argv[1], argv[2], file_count);

    // Start writing files
    uint32_t offset = 2124 + (file_count * 2580);

    for (int i = 0; i < file_count; i++) {
        writeFileInfoHeader(fd, &fp[file_count], &offset);
    }

    for (int i = 0; i < file_count; i++) {
        writeDlFile(fd, &fp[file_count]);
    }
    // End writing files

    uint32_t tmp;
    // Overwrite PACHeader dwSize
    lseek(fd, 48, SEEK_SET);
    tmp = htole32(offset);
    write(fd, &tmp, 4);

    // Calculate CRC
    uint16_t crc;

    // First part CRC
    crc = calc_crc1(fd);
    lseek(fd, 2120, SEEK_SET);
    tmp = htole16(crc);
    write(fd, &tmp, 2);

    // Second part CRC
    crc = calc_crc2(fd, offset);
    lseek(fd, 2122, SEEK_SET);
    tmp = htole16(crc);
    write(fd, &tmp, 2);

    close(fd);

    printf("Header created...");

    return 0;
}
