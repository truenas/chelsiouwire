#ifndef __PLATDEF_H__
#define __PLATDEF_H__

/* Necessary typedefs to include t4_msg.h from user space */
typedef unsigned int u32, uint32_t, __u32;
typedef unsigned long long  u64, __u64;
typedef unsigned char u8, uint8_t, __u8;
typedef unsigned short u16, uint16_t, __u16;
typedef unsigned char s8;
typedef unsigned short bool, s16;
typedef unsigned long   uintptr_t;
typedef __u16 __bitwise __le16;
typedef __u16 __bitwise __be16;
typedef __u32 __bitwise __le32;
typedef __u32 __bitwise __be32;
#if defined(__GNUC__) || defined(_MSC_VER)
typedef __u64 __bitwise __le64;
typedef __u64 __bitwise __be64;
#endif

#endif /* __PLATDEF_H__ */
