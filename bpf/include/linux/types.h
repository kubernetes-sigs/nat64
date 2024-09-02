#pragma once

#ifndef NULL
#define NULL ((void *)0)
#endif

#define bool	_Bool

enum {
	false	= 0,
	true	= 1,
};

typedef __signed__ char __s8;
typedef unsigned char __u8;
typedef __s8 s8;
typedef __u8 u8;

typedef __signed__ short __s16;
typedef unsigned short __u16;
typedef __s16 s16;
typedef __u16 u16;

typedef __signed__ int __s32;
typedef unsigned int __u32;
typedef __s32 s32;
typedef __u32 u32;

typedef __signed__ long long __s64;
typedef unsigned long long __u64;
typedef __s64 s64;
typedef __u64 u64;

typedef __u16 __le16;
typedef __u16 __be16;

typedef __u32 __le32;
typedef __u32 __be32;

typedef __u64 __le64;
typedef __u64 __be64;

typedef __u16 __sum16;
typedef __u32 __wsum;

typedef long int __kernel_long_t;
typedef long unsigned int __kernel_ulong_t;
typedef __kernel_ulong_t __kernel_size_t;
typedef __kernel_long_t __kernel_ssize_t;
typedef long unsigned int uintptr_t;

typedef __kernel_size_t size_t;
typedef __kernel_ssize_t ssize_t;
typedef s32 int32_t;
typedef u32 uint32_t;

typedef __u64 __aligned_u64;

typedef __u64 __net_cookie;
typedef __u64 __sock_cookie;

#define UINT16_MAX 0xffff
