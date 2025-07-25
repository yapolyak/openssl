#! /usr/bin/env perl
# Copyright 2016-2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

#
# ====================================================================
# Written by Andy Polyakov, @dot-asm, initially for use in the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see https://github.com/dot-asm/cryptogams/.
# ====================================================================
#
# This module implements Poly1305 hash for ARMv8.
#
# June 2015
#
# Numbers are cycles per processed byte with poly1305_blocks alone.
#
#		IALU/gcc-4.9	NEON
#
# Apple A7	1.86/+5%	0.72
# Cortex-A53	2.69/+58%	1.47
# Cortex-A57	2.70/+7%	1.14
# Denver	1.64/+50%	1.18(*)
# X-Gene	2.13/+68%	2.27
# Mongoose	1.77/+75%	1.12
# Kryo		2.70/+55%	1.13
# ThunderX2	1.17/+95%	1.36
#
# (*)	estimate based on resources availability is less than 1.0,
#	i.e. measured result is worse than expected, presumably binary
#	translator is not almighty;

# $output is the last argument if it looks like a file (it has an extension)
# $flavour is the first argument if it doesn't look like a file
$output = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop : undef;
$flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\.| ? shift : undef;

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}arm-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/arm-xlate.pl" and -f $xlate) or
die "can't locate arm-xlate.pl";

open OUT,"| \"$^X\" $xlate $flavour \"$output\""
    or die "can't call $xlate: $!";
*STDOUT=*OUT;

my ($ctx,$inp,$len,$padbit) = map("x$_",(0..3));
my ($mac,$nonce)=($inp,$len);

my ($h0,$h1,$h2,$r0,$r1,$s1,$t0,$t1,$d0,$d1,$d2) = map("x$_",(4..14));

$code.=<<___;
#include "arm_arch.h"

.text

// forward "declarations" are required for Apple
.extern	OPENSSL_armcap_P
.hidden	OPENSSL_armcap_P
.globl	poly1305_init
.hidden	poly1305_init
.globl	poly1305_blocks
.hidden	poly1305_blocks
.globl	poly1305_emit
.hidden	poly1305_emit

.type	poly1305_init,%function
.align	5
poly1305_init:
	AARCH64_VALID_CALL_TARGET
	cmp	$inp,xzr
	stp	xzr,xzr,[$ctx]		// zero hash value
	stp	xzr,xzr,[$ctx,#16]	// [along with is_base2_26]

	csel	x0,xzr,x0,eq
	b.eq	.Lno_key

	adrp	x17,OPENSSL_armcap_P
	ldr	w17,[x17,#:lo12:OPENSSL_armcap_P]

	ldp	$r0,$r1,[$inp]		// load key
	mov	$s1,#0xfffffffc0fffffff
	movk	$s1,#0x0fff,lsl#48
#ifdef	__AARCH64EB__
	rev	$r0,$r0			// flip bytes
	rev	$r1,$r1
#endif
	and	$r0,$r0,$s1		// &=0ffffffc0fffffff
	and	$s1,$s1,#-4
	and	$r1,$r1,$s1		// &=0ffffffc0ffffffc
	stp	$r0,$r1,[$ctx,#32]	// save key value

	tst	w17,#ARMV7_NEON

	adrp	$d0,poly1305_blocks
	add	$d0,$d0,#:lo12:.Lpoly1305_blocks
	adrp	$r0,poly1305_blocks_neon
	add	$r0,$r0,#:lo12:.Lpoly1305_blocks_neon
	adrp	$d1,poly1305_emit
	add	$d1,$d1,#:lo12:.Lpoly1305_emit
	adrp	$r1,poly1305_emit_neon
	add	$r1,$r1,#:lo12:.Lpoly1305_emit_neon

	csel	$d0,$d0,$r0,eq
	csel	$d1,$d1,$r1,eq

	tst w17, #ARMV8_SVE2

	adrp	$r0,poly1305_blocks_sve2_2way
	add	$r0,$r0,#:lo12:.Lpoly1305_blocks_sve2_2way

	csel	$d0,$d0,$r0,eq

#ifdef	__ILP32__
	stp	w12,w13,[$len]
#else
	stp	$d0,$d1,[$len]
#endif

	mov	x0,#1
.Lno_key:
	ret
.size	poly1305_init,.-poly1305_init

.type	poly1305_blocks,%function
.align	5
poly1305_blocks:
.Lpoly1305_blocks:
	// The symbol .Lpoly1305_blocks is not a .globl symbol
	// but a pointer to it is returned by poly1305_init
	AARCH64_VALID_CALL_TARGET
	ands	$len,$len,#-16
	b.eq	.Lno_data

	ldp	$h0,$h1,[$ctx]		// load hash value
	ldp	$r0,$r1,[$ctx,#32]	// load key value
	ldr	$h2,[$ctx,#16]
	add	$s1,$r1,$r1,lsr#2	// s1 = r1 + (r1 >> 2)
	b	.Loop

.align	5
.Loop:
	ldp	$t0,$t1,[$inp],#16	// load input
	sub	$len,$len,#16
#ifdef	__AARCH64EB__
	rev	$t0,$t0
	rev	$t1,$t1
#endif
	adds	$h0,$h0,$t0		// accumulate input
	adcs	$h1,$h1,$t1

	mul	$d0,$h0,$r0		// h0*r0
	adc	$h2,$h2,$padbit
	umulh	$d1,$h0,$r0

	mul	$t0,$h1,$s1		// h1*5*r1
	umulh	$t1,$h1,$s1

	adds	$d0,$d0,$t0
	mul	$t0,$h0,$r1		// h0*r1
	adc	$d1,$d1,$t1
	umulh	$d2,$h0,$r1

	adds	$d1,$d1,$t0
	mul	$t0,$h1,$r0		// h1*r0
	adc	$d2,$d2,xzr
	umulh	$t1,$h1,$r0

	adds	$d1,$d1,$t0
	mul	$t0,$h2,$s1		// h2*5*r1
	adc	$d2,$d2,$t1
	mul	$t1,$h2,$r0		// h2*r0

	adds	$d1,$d1,$t0
	adc	$d2,$d2,$t1

	and	$t0,$d2,#-4		// final reduction
	and	$h2,$d2,#3
	add	$t0,$t0,$d2,lsr#2
	adds	$h0,$d0,$t0
	adcs	$h1,$d1,xzr
	adc	$h2,$h2,xzr

	cbnz	$len,.Loop

	stp	$h0,$h1,[$ctx]		// store hash value
	str	$h2,[$ctx,#16]

.Lno_data:
	ret
.size	poly1305_blocks,.-poly1305_blocks

.type	poly1305_emit,%function
.align	5
poly1305_emit:
.Lpoly1305_emit:
	// The symbol .poly1305_emit is not a .globl symbol
	// but a pointer to it is returned by poly1305_init
	AARCH64_VALID_CALL_TARGET
	ldp	$h0,$h1,[$ctx]		// load hash base 2^64
	ldr	$h2,[$ctx,#16]
	ldp	$t0,$t1,[$nonce]	// load nonce

	adds	$d0,$h0,#5		// compare to modulus
	adcs	$d1,$h1,xzr
	adc	$d2,$h2,xzr

	tst	$d2,#-4			// see if it's carried/borrowed

	csel	$h0,$h0,$d0,eq
	csel	$h1,$h1,$d1,eq

#ifdef	__AARCH64EB__
	ror	$t0,$t0,#32		// flip nonce words
	ror	$t1,$t1,#32
#endif
	adds	$h0,$h0,$t0		// accumulate nonce
	adc	$h1,$h1,$t1
#ifdef	__AARCH64EB__
	rev	$h0,$h0			// flip output bytes
	rev	$h1,$h1
#endif
	stp	$h0,$h1,[$mac]		// write result

	ret
.size	poly1305_emit,.-poly1305_emit
___
my ($R0,$R1,$S1,$R2,$S2,$R3,$S3,$R4,$S4) = map("v$_.4s",(0..8));
my ($IN01_0,$IN01_1,$IN01_2,$IN01_3,$IN01_4) = map("v$_.2s",(9..13));
my ($IN23_0,$IN23_1,$IN23_2,$IN23_3,$IN23_4) = map("v$_.2s",(14..18));
my ($ACC0,$ACC1,$ACC2,$ACC3,$ACC4) = map("v$_.2d",(19..23));
my ($H0,$H1,$H2,$H3,$H4) = map("v$_.2s",(24..28));
my ($T0,$T1,$MASK) = map("v$_",(29..31));

my ($in2,$zeros)=("x16","x17");
my $is_base2_26 = $zeros;		# borrow

$code.=<<___;
.type	poly1305_mult,%function
.align	5
poly1305_mult:
	mul	$d0,$h0,$r0		// h0*r0
	umulh	$d1,$h0,$r0

	mul	$t0,$h1,$s1		// h1*5*r1
	umulh	$t1,$h1,$s1

	adds	$d0,$d0,$t0
	mul	$t0,$h0,$r1		// h0*r1
	adc	$d1,$d1,$t1
	umulh	$d2,$h0,$r1

	adds	$d1,$d1,$t0
	mul	$t0,$h1,$r0		// h1*r0
	adc	$d2,$d2,xzr
	umulh	$t1,$h1,$r0

	adds	$d1,$d1,$t0
	mul	$t0,$h2,$s1		// h2*5*r1
	adc	$d2,$d2,$t1
	mul	$t1,$h2,$r0		// h2*r0

	adds	$d1,$d1,$t0
	adc	$d2,$d2,$t1

	and	$t0,$d2,#-4		// final reduction
	and	$h2,$d2,#3
	add	$t0,$t0,$d2,lsr#2
	adds	$h0,$d0,$t0
	adcs	$h1,$d1,xzr
	adc	$h2,$h2,xzr

	ret
.size	poly1305_mult,.-poly1305_mult

.type	poly1305_splat,%function
.align	5
poly1305_splat:
	and	x12,$h0,#0x03ffffff	// base 2^64 -> base 2^26
	ubfx	x13,$h0,#26,#26
	extr	x14,$h1,$h0,#52
	and	x14,x14,#0x03ffffff
	ubfx	x15,$h1,#14,#26
	extr	x16,$h2,$h1,#40

	str	w12,[$ctx,#16*0]	// r0
	add	w12,w13,w13,lsl#2	// r1*5
	str	w13,[$ctx,#16*1]	// r1
	add	w13,w14,w14,lsl#2	// r2*5
	str	w12,[$ctx,#16*2]	// s1
	str	w14,[$ctx,#16*3]	// r2
	add	w14,w15,w15,lsl#2	// r3*5
	str	w13,[$ctx,#16*4]	// s2
	str	w15,[$ctx,#16*5]	// r3
	add	w15,w16,w16,lsl#2	// r4*5
	str	w14,[$ctx,#16*6]	// s3
	str	w16,[$ctx,#16*7]	// r4
	str	w15,[$ctx,#16*8]	// s4

	ret
.size	poly1305_splat,.-poly1305_splat

.type	poly1305_blocks_neon,%function
.align	5
poly1305_blocks_neon:
.Lpoly1305_blocks_neon:
	// The symbol .Lpoly1305_blocks_neon is not a .globl symbol
	// but a pointer to it is returned by poly1305_init
	AARCH64_VALID_CALL_TARGET
	ldr	$is_base2_26,[$ctx,#24]
	cmp	$len,#128
	b.hs	.Lblocks_neon
	cbz	$is_base2_26,.Lpoly1305_blocks

.Lblocks_neon:
	AARCH64_SIGN_LINK_REGISTER
	stp	x29,x30,[sp,#-80]!
	add	x29,sp,#0

	ands	$len,$len,#-16
	b.eq	.Lno_data_neon

	cbz	$is_base2_26,.Lbase2_64_neon

	ldp	w10,w11,[$ctx]		// load hash value base 2^26
	ldp	w12,w13,[$ctx,#8]
	ldr	w14,[$ctx,#16]

	tst	$len,#31
	b.eq	.Leven_neon

	ldp	$r0,$r1,[$ctx,#32]	// load key value

	add	$h0,x10,x11,lsl#26	// base 2^26 -> base 2^64
	lsr	$h1,x12,#12
	adds	$h0,$h0,x12,lsl#52
	add	$h1,$h1,x13,lsl#14
	adc	$h1,$h1,xzr
	lsr	$h2,x14,#24
	adds	$h1,$h1,x14,lsl#40
	adc	$d2,$h2,xzr		// can be partially reduced...

	ldp	$d0,$d1,[$inp],#16	// load input
	sub	$len,$len,#16
	add	$s1,$r1,$r1,lsr#2	// s1 = r1 + (r1 >> 2)

	and	$t0,$d2,#-4		// ... so reduce
	and	$h2,$d2,#3
	add	$t0,$t0,$d2,lsr#2
	adds	$h0,$h0,$t0
	adcs	$h1,$h1,xzr
	adc	$h2,$h2,xzr

#ifdef	__AARCH64EB__
	rev	$d0,$d0
	rev	$d1,$d1
#endif
	adds	$h0,$h0,$d0		// accumulate input
	adcs	$h1,$h1,$d1
	adc	$h2,$h2,$padbit

	bl	poly1305_mult
	ldr	x30,[sp,#8]

	cbz	$padbit,.Lstore_base2_64_neon

	and	x10,$h0,#0x03ffffff	// base 2^64 -> base 2^26
	ubfx	x11,$h0,#26,#26
	extr	x12,$h1,$h0,#52
	and	x12,x12,#0x03ffffff
	ubfx	x13,$h1,#14,#26
	extr	x14,$h2,$h1,#40

	cbnz	$len,.Leven_neon

	stp	w10,w11,[$ctx]		// store hash value base 2^26
	stp	w12,w13,[$ctx,#8]
	str	w14,[$ctx,#16]
	b	.Lno_data_neon

.align	4
.Lstore_base2_64_neon:
	stp	$h0,$h1,[$ctx]		// store hash value base 2^64
	stp	$h2,xzr,[$ctx,#16]	// note that is_base2_26 is zeroed
	b	.Lno_data_neon

.align	4
.Lbase2_64_neon:
	ldp	$r0,$r1,[$ctx,#32]	// load key value

	ldp	$h0,$h1,[$ctx]		// load hash value base 2^64
	ldr	$h2,[$ctx,#16]

	tst	$len,#31
	b.eq	.Linit_neon

	ldp	$d0,$d1,[$inp],#16	// load input
	sub	$len,$len,#16
	add	$s1,$r1,$r1,lsr#2	// s1 = r1 + (r1 >> 2)
#ifdef	__AARCH64EB__
	rev	$d0,$d0
	rev	$d1,$d1
#endif
	adds	$h0,$h0,$d0		// accumulate input
	adcs	$h1,$h1,$d1
	adc	$h2,$h2,$padbit

	bl	poly1305_mult

.Linit_neon:
	and	x10,$h0,#0x03ffffff	// base 2^64 -> base 2^26
	ubfx	x11,$h0,#26,#26
	extr	x12,$h1,$h0,#52
	and	x12,x12,#0x03ffffff
	ubfx	x13,$h1,#14,#26
	extr	x14,$h2,$h1,#40

	stp	d8,d9,[sp,#16]		// meet ABI requirements
	stp	d10,d11,[sp,#32]
	stp	d12,d13,[sp,#48]
	stp	d14,d15,[sp,#64]

	fmov	${H0},x10
	fmov	${H1},x11
	fmov	${H2},x12
	fmov	${H3},x13
	fmov	${H4},x14

	////////////////////////////////// initialize r^n table
	mov	$h0,$r0			// r^1
	add	$s1,$r1,$r1,lsr#2	// s1 = r1 + (r1 >> 2)
	mov	$h1,$r1
	mov	$h2,xzr
	add	$ctx,$ctx,#48+12
	bl	poly1305_splat

	bl	poly1305_mult		// r^2
	sub	$ctx,$ctx,#4
	bl	poly1305_splat

	bl	poly1305_mult		// r^3
	sub	$ctx,$ctx,#4
	bl	poly1305_splat

	bl	poly1305_mult		// r^4
	sub	$ctx,$ctx,#4
	bl	poly1305_splat
	ldr	x30,[sp,#8]

	add	$in2,$inp,#32
	adrp	$zeros,.Lzeros
	add	$zeros,$zeros,:lo12:.Lzeros
	subs	$len,$len,#64
	csel	$in2,$zeros,$in2,lo

	mov	x4,#1
	stur	x4,[$ctx,#-24]		// set is_base2_26
	sub	$ctx,$ctx,#48		// restore original $ctx
	b	.Ldo_neon

.align	4
.Leven_neon:
	add	$in2,$inp,#32
	adrp	$zeros,.Lzeros
	add	$zeros,$zeros,:lo12:.Lzeros
	subs	$len,$len,#64
	csel	$in2,$zeros,$in2,lo

	stp	d8,d9,[sp,#16]		// meet ABI requirements
	stp	d10,d11,[sp,#32]
	stp	d12,d13,[sp,#48]
	stp	d14,d15,[sp,#64]

	fmov	${H0},x10
	fmov	${H1},x11
	fmov	${H2},x12
	fmov	${H3},x13
	fmov	${H4},x14

.Ldo_neon:
	ldp	x8,x12,[$in2],#16	// inp[2:3] (or zero)
	ldp	x9,x13,[$in2],#48

	lsl	$padbit,$padbit,#24
	add	x15,$ctx,#48

#ifdef	__AARCH64EB__
	rev	x8,x8
	rev	x12,x12
	rev	x9,x9
	rev	x13,x13
#endif
	and	x4,x8,#0x03ffffff	// base 2^64 -> base 2^26
	and	x5,x9,#0x03ffffff
	ubfx	x6,x8,#26,#26
	ubfx	x7,x9,#26,#26
	add	x4,x4,x5,lsl#32		// bfi	x4,x5,#32,#32
	extr	x8,x12,x8,#52
	extr	x9,x13,x9,#52
	add	x6,x6,x7,lsl#32		// bfi	x6,x7,#32,#32
	fmov	$IN23_0,x4
	and	x8,x8,#0x03ffffff
	and	x9,x9,#0x03ffffff
	ubfx	x10,x12,#14,#26
	ubfx	x11,x13,#14,#26
	add	x12,$padbit,x12,lsr#40
	add	x13,$padbit,x13,lsr#40
	add	x8,x8,x9,lsl#32		// bfi	x8,x9,#32,#32
	fmov	$IN23_1,x6
	add	x10,x10,x11,lsl#32	// bfi	x10,x11,#32,#32
	add	x12,x12,x13,lsl#32	// bfi	x12,x13,#32,#32
	fmov	$IN23_2,x8
	fmov	$IN23_3,x10
	fmov	$IN23_4,x12

	ldp	x8,x12,[$inp],#16	// inp[0:1]
	ldp	x9,x13,[$inp],#48

	ld1	{$R0,$R1,$S1,$R2},[x15],#64
	ld1	{$S2,$R3,$S3,$R4},[x15],#64
	ld1	{$S4},[x15]

#ifdef	__AARCH64EB__
	rev	x8,x8
	rev	x12,x12
	rev	x9,x9
	rev	x13,x13
#endif
	and	x4,x8,#0x03ffffff	// base 2^64 -> base 2^26
	and	x5,x9,#0x03ffffff
	ubfx	x6,x8,#26,#26
	ubfx	x7,x9,#26,#26
	add	x4,x4,x5,lsl#32		// bfi	x4,x5,#32,#32
	extr	x8,x12,x8,#52
	extr	x9,x13,x9,#52
	add	x6,x6,x7,lsl#32		// bfi	x6,x7,#32,#32
	fmov	$IN01_0,x4
	and	x8,x8,#0x03ffffff
	and	x9,x9,#0x03ffffff
	ubfx	x10,x12,#14,#26
	ubfx	x11,x13,#14,#26
	add	x12,$padbit,x12,lsr#40
	add	x13,$padbit,x13,lsr#40
	add	x8,x8,x9,lsl#32		// bfi	x8,x9,#32,#32
	fmov	$IN01_1,x6
	add	x10,x10,x11,lsl#32	// bfi	x10,x11,#32,#32
	add	x12,x12,x13,lsl#32	// bfi	x12,x13,#32,#32
	movi	$MASK.2d,#-1
	fmov	$IN01_2,x8
	fmov	$IN01_3,x10
	fmov	$IN01_4,x12
	ushr	$MASK.2d,$MASK.2d,#38

	b.ls	.Lskip_loop

.align	4
.Loop_neon:
	////////////////////////////////////////////////////////////////
	// ((inp[0]*r^4+inp[2]*r^2+inp[4])*r^4+inp[6]*r^2
	// ((inp[1]*r^4+inp[3]*r^2+inp[5])*r^3+inp[7]*r
	//   \___________________/
	// ((inp[0]*r^4+inp[2]*r^2+inp[4])*r^4+inp[6]*r^2+inp[8])*r^2
	// ((inp[1]*r^4+inp[3]*r^2+inp[5])*r^4+inp[7]*r^2+inp[9])*r
	//   \___________________/ \____________________/
	//
	// Note that we start with inp[2:3]*r^2. This is because it
	// doesn't depend on reduction in previous iteration.
	////////////////////////////////////////////////////////////////
	// d4 = h0*r4 + h1*r3   + h2*r2   + h3*r1   + h4*r0
	// d3 = h0*r3 + h1*r2   + h2*r1   + h3*r0   + h4*5*r4
	// d2 = h0*r2 + h1*r1   + h2*r0   + h3*5*r4 + h4*5*r3
	// d1 = h0*r1 + h1*r0   + h2*5*r4 + h3*5*r3 + h4*5*r2
	// d0 = h0*r0 + h1*5*r4 + h2*5*r3 + h3*5*r2 + h4*5*r1

	subs	$len,$len,#64
	umull	$ACC4,$IN23_0,${R4}[2]
	csel	$in2,$zeros,$in2,lo
	umull	$ACC3,$IN23_0,${R3}[2]
	umull	$ACC2,$IN23_0,${R2}[2]
	 ldp	x8,x12,[$in2],#16	// inp[2:3] (or zero)
	umull	$ACC1,$IN23_0,${R1}[2]
	 ldp	x9,x13,[$in2],#48
	umull	$ACC0,$IN23_0,${R0}[2]
#ifdef	__AARCH64EB__
	 rev	x8,x8
	 rev	x12,x12
	 rev	x9,x9
	 rev	x13,x13
#endif

	umlal	$ACC4,$IN23_1,${R3}[2]
	 and	x4,x8,#0x03ffffff	// base 2^64 -> base 2^26
	umlal	$ACC3,$IN23_1,${R2}[2]
	 and	x5,x9,#0x03ffffff
	umlal	$ACC2,$IN23_1,${R1}[2]
	 ubfx	x6,x8,#26,#26
	umlal	$ACC1,$IN23_1,${R0}[2]
	 ubfx	x7,x9,#26,#26
	umlal	$ACC0,$IN23_1,${S4}[2]
	 add	x4,x4,x5,lsl#32		// bfi	x4,x5,#32,#32

	umlal	$ACC4,$IN23_2,${R2}[2]
	 extr	x8,x12,x8,#52
	umlal	$ACC3,$IN23_2,${R1}[2]
	 extr	x9,x13,x9,#52
	umlal	$ACC2,$IN23_2,${R0}[2]
	 add	x6,x6,x7,lsl#32		// bfi	x6,x7,#32,#32
	umlal	$ACC1,$IN23_2,${S4}[2]
	 fmov	$IN23_0,x4
	umlal	$ACC0,$IN23_2,${S3}[2]
	 and	x8,x8,#0x03ffffff

	umlal	$ACC4,$IN23_3,${R1}[2]
	 and	x9,x9,#0x03ffffff
	umlal	$ACC3,$IN23_3,${R0}[2]
	 ubfx	x10,x12,#14,#26
	umlal	$ACC2,$IN23_3,${S4}[2]
	 ubfx	x11,x13,#14,#26
	umlal	$ACC1,$IN23_3,${S3}[2]
	 add	x8,x8,x9,lsl#32		// bfi	x8,x9,#32,#32
	umlal	$ACC0,$IN23_3,${S2}[2]
	 fmov	$IN23_1,x6

	add	$IN01_2,$IN01_2,$H2
	 add	x12,$padbit,x12,lsr#40
	umlal	$ACC4,$IN23_4,${R0}[2]
	 add	x13,$padbit,x13,lsr#40
	umlal	$ACC3,$IN23_4,${S4}[2]
	 add	x10,x10,x11,lsl#32	// bfi	x10,x11,#32,#32
	umlal	$ACC2,$IN23_4,${S3}[2]
	 add	x12,x12,x13,lsl#32	// bfi	x12,x13,#32,#32
	umlal	$ACC1,$IN23_4,${S2}[2]
	 fmov	$IN23_2,x8
	umlal	$ACC0,$IN23_4,${S1}[2]
	 fmov	$IN23_3,x10

	////////////////////////////////////////////////////////////////
	// (hash+inp[0:1])*r^4 and accumulate

	add	$IN01_0,$IN01_0,$H0
	 fmov	$IN23_4,x12
	umlal	$ACC3,$IN01_2,${R1}[0]
	 ldp	x8,x12,[$inp],#16	// inp[0:1]
	umlal	$ACC0,$IN01_2,${S3}[0]
	 ldp	x9,x13,[$inp],#48
	umlal	$ACC4,$IN01_2,${R2}[0]
	umlal	$ACC1,$IN01_2,${S4}[0]
	umlal	$ACC2,$IN01_2,${R0}[0]
#ifdef	__AARCH64EB__
	 rev	x8,x8
	 rev	x12,x12
	 rev	x9,x9
	 rev	x13,x13
#endif

	add	$IN01_1,$IN01_1,$H1
	umlal	$ACC3,$IN01_0,${R3}[0]
	umlal	$ACC4,$IN01_0,${R4}[0]
	 and	x4,x8,#0x03ffffff	// base 2^64 -> base 2^26
	umlal	$ACC2,$IN01_0,${R2}[0]
	 and	x5,x9,#0x03ffffff
	umlal	$ACC0,$IN01_0,${R0}[0]
	 ubfx	x6,x8,#26,#26
	umlal	$ACC1,$IN01_0,${R1}[0]
	 ubfx	x7,x9,#26,#26

	add	$IN01_3,$IN01_3,$H3
	 add	x4,x4,x5,lsl#32		// bfi	x4,x5,#32,#32
	umlal	$ACC3,$IN01_1,${R2}[0]
	 extr	x8,x12,x8,#52
	umlal	$ACC4,$IN01_1,${R3}[0]
	 extr	x9,x13,x9,#52
	umlal	$ACC0,$IN01_1,${S4}[0]
	 add	x6,x6,x7,lsl#32		// bfi	x6,x7,#32,#32
	umlal	$ACC2,$IN01_1,${R1}[0]
	 fmov	$IN01_0,x4
	umlal	$ACC1,$IN01_1,${R0}[0]
	 and	x8,x8,#0x03ffffff

	add	$IN01_4,$IN01_4,$H4
	 and	x9,x9,#0x03ffffff
	umlal	$ACC3,$IN01_3,${R0}[0]
	 ubfx	x10,x12,#14,#26
	umlal	$ACC0,$IN01_3,${S2}[0]
	 ubfx	x11,x13,#14,#26
	umlal	$ACC4,$IN01_3,${R1}[0]
	 add	x8,x8,x9,lsl#32		// bfi	x8,x9,#32,#32
	umlal	$ACC1,$IN01_3,${S3}[0]
	 fmov	$IN01_1,x6
	umlal	$ACC2,$IN01_3,${S4}[0]
	 add	x12,$padbit,x12,lsr#40

	umlal	$ACC3,$IN01_4,${S4}[0]
	 add	x13,$padbit,x13,lsr#40
	umlal	$ACC0,$IN01_4,${S1}[0]
	 add	x10,x10,x11,lsl#32	// bfi	x10,x11,#32,#32
	umlal	$ACC4,$IN01_4,${R0}[0]
	 add	x12,x12,x13,lsl#32	// bfi	x12,x13,#32,#32
	umlal	$ACC1,$IN01_4,${S2}[0]
	 fmov	$IN01_2,x8
	umlal	$ACC2,$IN01_4,${S3}[0]
	 fmov	$IN01_3,x10
	 fmov	$IN01_4,x12

	/////////////////////////////////////////////////////////////////
	// lazy reduction as discussed in "NEON crypto" by D.J. Bernstein
	// and P. Schwabe
	//
	// [see discussion in poly1305-armv4 module]

	ushr	$T0.2d,$ACC3,#26
	xtn	$H3,$ACC3
	 ushr	$T1.2d,$ACC0,#26
	 and	$ACC0,$ACC0,$MASK.2d
	add	$ACC4,$ACC4,$T0.2d	// h3 -> h4
	bic	$H3,#0xfc,lsl#24	// &=0x03ffffff
	 add	$ACC1,$ACC1,$T1.2d	// h0 -> h1

	ushr	$T0.2d,$ACC4,#26
	xtn	$H4,$ACC4
	 ushr	$T1.2d,$ACC1,#26
	 xtn	$H1,$ACC1
	bic	$H4,#0xfc,lsl#24
	 add	$ACC2,$ACC2,$T1.2d	// h1 -> h2

	add	$ACC0,$ACC0,$T0.2d
	shl	$T0.2d,$T0.2d,#2
	 shrn	$T1.2s,$ACC2,#26
	 xtn	$H2,$ACC2
	add	$ACC0,$ACC0,$T0.2d	// h4 -> h0
	 bic	$H1,#0xfc,lsl#24
	 add	$H3,$H3,$T1.2s		// h2 -> h3
	 bic	$H2,#0xfc,lsl#24

	shrn	$T0.2s,$ACC0,#26
	xtn	$H0,$ACC0
	 ushr	$T1.2s,$H3,#26
	 bic	$H3,#0xfc,lsl#24
	 bic	$H0,#0xfc,lsl#24
	add	$H1,$H1,$T0.2s		// h0 -> h1
	 add	$H4,$H4,$T1.2s		// h3 -> h4

	b.hi	.Loop_neon

.Lskip_loop:
	dup	$IN23_2,${IN23_2}[0]
	add	$IN01_2,$IN01_2,$H2

	////////////////////////////////////////////////////////////////
	// multiply (inp[0:1]+hash) or inp[2:3] by r^2:r^1

	adds	$len,$len,#32
	b.ne	.Long_tail

	dup	$IN23_2,${IN01_2}[0]
	add	$IN23_0,$IN01_0,$H0
	add	$IN23_3,$IN01_3,$H3
	add	$IN23_1,$IN01_1,$H1
	add	$IN23_4,$IN01_4,$H4

.Long_tail:
	dup	$IN23_0,${IN23_0}[0]
	umull2	$ACC0,$IN23_2,${S3}
	umull2	$ACC3,$IN23_2,${R1}
	umull2	$ACC4,$IN23_2,${R2}
	umull2	$ACC2,$IN23_2,${R0}
	umull2	$ACC1,$IN23_2,${S4}

	dup	$IN23_1,${IN23_1}[0]
	umlal2	$ACC0,$IN23_0,${R0}
	umlal2	$ACC2,$IN23_0,${R2}
	umlal2	$ACC3,$IN23_0,${R3}
	umlal2	$ACC4,$IN23_0,${R4}
	umlal2	$ACC1,$IN23_0,${R1}

	dup	$IN23_3,${IN23_3}[0]
	umlal2	$ACC0,$IN23_1,${S4}
	umlal2	$ACC3,$IN23_1,${R2}
	umlal2	$ACC2,$IN23_1,${R1}
	umlal2	$ACC4,$IN23_1,${R3}
	umlal2	$ACC1,$IN23_1,${R0}

	dup	$IN23_4,${IN23_4}[0]
	umlal2	$ACC3,$IN23_3,${R0}
	umlal2	$ACC4,$IN23_3,${R1}
	umlal2	$ACC0,$IN23_3,${S2}
	umlal2	$ACC1,$IN23_3,${S3}
	umlal2	$ACC2,$IN23_3,${S4}

	umlal2	$ACC3,$IN23_4,${S4}
	umlal2	$ACC0,$IN23_4,${S1}
	umlal2	$ACC4,$IN23_4,${R0}
	umlal2	$ACC1,$IN23_4,${S2}
	umlal2	$ACC2,$IN23_4,${S3}

	b.eq	.Lshort_tail

	////////////////////////////////////////////////////////////////
	// (hash+inp[0:1])*r^4:r^3 and accumulate

	add	$IN01_0,$IN01_0,$H0
	umlal	$ACC3,$IN01_2,${R1}
	umlal	$ACC0,$IN01_2,${S3}
	umlal	$ACC4,$IN01_2,${R2}
	umlal	$ACC1,$IN01_2,${S4}
	umlal	$ACC2,$IN01_2,${R0}

	add	$IN01_1,$IN01_1,$H1
	umlal	$ACC3,$IN01_0,${R3}
	umlal	$ACC0,$IN01_0,${R0}
	umlal	$ACC4,$IN01_0,${R4}
	umlal	$ACC1,$IN01_0,${R1}
	umlal	$ACC2,$IN01_0,${R2}

	add	$IN01_3,$IN01_3,$H3
	umlal	$ACC3,$IN01_1,${R2}
	umlal	$ACC0,$IN01_1,${S4}
	umlal	$ACC4,$IN01_1,${R3}
	umlal	$ACC1,$IN01_1,${R0}
	umlal	$ACC2,$IN01_1,${R1}

	add	$IN01_4,$IN01_4,$H4
	umlal	$ACC3,$IN01_3,${R0}
	umlal	$ACC0,$IN01_3,${S2}
	umlal	$ACC4,$IN01_3,${R1}
	umlal	$ACC1,$IN01_3,${S3}
	umlal	$ACC2,$IN01_3,${S4}

	umlal	$ACC3,$IN01_4,${S4}
	umlal	$ACC0,$IN01_4,${S1}
	umlal	$ACC4,$IN01_4,${R0}
	umlal	$ACC1,$IN01_4,${S2}
	umlal	$ACC2,$IN01_4,${S3}

.Lshort_tail:
	////////////////////////////////////////////////////////////////
	// horizontal add

	addp	$ACC3,$ACC3,$ACC3
	 ldp	d8,d9,[sp,#16]		// meet ABI requirements
	addp	$ACC0,$ACC0,$ACC0
	 ldp	d10,d11,[sp,#32]
	addp	$ACC4,$ACC4,$ACC4
	 ldp	d12,d13,[sp,#48]
	addp	$ACC1,$ACC1,$ACC1
	 ldp	d14,d15,[sp,#64]
	addp	$ACC2,$ACC2,$ACC2

	////////////////////////////////////////////////////////////////
	// lazy reduction, but without narrowing

	ushr	$T0.2d,$ACC3,#26
	and	$ACC3,$ACC3,$MASK.2d
	 ushr	$T1.2d,$ACC0,#26
	 and	$ACC0,$ACC0,$MASK.2d

	add	$ACC4,$ACC4,$T0.2d	// h3 -> h4
	 add	$ACC1,$ACC1,$T1.2d	// h0 -> h1

	ushr	$T0.2d,$ACC4,#26
	and	$ACC4,$ACC4,$MASK.2d
	 ushr	$T1.2d,$ACC1,#26
	 and	$ACC1,$ACC1,$MASK.2d
	 add	$ACC2,$ACC2,$T1.2d	// h1 -> h2

	add	$ACC0,$ACC0,$T0.2d
	shl	$T0.2d,$T0.2d,#2
	 ushr	$T1.2d,$ACC2,#26
	 and	$ACC2,$ACC2,$MASK.2d
	add	$ACC0,$ACC0,$T0.2d	// h4 -> h0
	 add	$ACC3,$ACC3,$T1.2d	// h2 -> h3

	ushr	$T0.2d,$ACC0,#26
	and	$ACC0,$ACC0,$MASK.2d
	 ushr	$T1.2d,$ACC3,#26
	 and	$ACC3,$ACC3,$MASK.2d
	add	$ACC1,$ACC1,$T0.2d	// h0 -> h1
	 add	$ACC4,$ACC4,$T1.2d	// h3 -> h4

	////////////////////////////////////////////////////////////////
	// write the result, can be partially reduced

	st4	{$ACC0,$ACC1,$ACC2,$ACC3}[0],[$ctx],#16
	st1	{$ACC4}[0],[$ctx]

.Lno_data_neon:
	ldr	x29,[sp],#80
	AARCH64_VALIDATE_LINK_REGISTER
	ret
.size	poly1305_blocks_neon,.-poly1305_blocks_neon

.type	poly1305_emit_neon,%function
.align	5
poly1305_emit_neon:
.Lpoly1305_emit_neon:
	// The symbol .Lpoly1305_emit_neon is not a .globl symbol
	// but a pointer to it is returned by poly1305_init
	AARCH64_VALID_CALL_TARGET
	ldr	$is_base2_26,[$ctx,#24]
	cbz	$is_base2_26,poly1305_emit

	ldp	w10,w11,[$ctx]		// load hash value base 2^26
	ldp	w12,w13,[$ctx,#8]
	ldr	w14,[$ctx,#16]

	add	$h0,x10,x11,lsl#26	// base 2^26 -> base 2^64
	lsr	$h1,x12,#12
	adds	$h0,$h0,x12,lsl#52
	add	$h1,$h1,x13,lsl#14
	adc	$h1,$h1,xzr
	lsr	$h2,x14,#24
	adds	$h1,$h1,x14,lsl#40
	adc	$h2,$h2,xzr		// can be partially reduced...

	ldp	$t0,$t1,[$nonce]	// load nonce

	and	$d0,$h2,#-4		// ... so reduce
	add	$d0,$d0,$h2,lsr#2
	and	$h2,$h2,#3
	adds	$h0,$h0,$d0
	adcs	$h1,$h1,xzr
	adc	$h2,$h2,xzr

	adds	$d0,$h0,#5		// compare to modulus
	adcs	$d1,$h1,xzr
	adc	$d2,$h2,xzr

	tst	$d2,#-4			// see if it's carried/borrowed

	csel	$h0,$h0,$d0,eq
	csel	$h1,$h1,$d1,eq

#ifdef	__AARCH64EB__
	ror	$t0,$t0,#32		// flip nonce words
	ror	$t1,$t1,#32
#endif
	adds	$h0,$h0,$t0		// accumulate nonce
	adc	$h1,$h1,$t1
#ifdef	__AARCH64EB__
	rev	$h0,$h0			// flip output bytes
	rev	$h1,$h1
#endif
	stp	$h0,$h1,[$mac]		// write result

	ret
.size	poly1305_emit_neon,.-poly1305_emit_neon
___

# --- SVE2 Section ---
$code .= ".arch armv8-a+sve2\n";

my ($SVE_R0,$SVE_R1,$SVE_S1,$SVE_R2,$SVE_S2,$SVE_R3,$SVE_S3,$SVE_R4,$SVE_S4) = map("z$_.s",(0..8));
my ($SVE_IN01_0,$SVE_IN01_1,$SVE_IN01_2,$SVE_IN01_3,$SVE_IN01_4) = map("z$_.s",(9..13));
my ($SVE_IN23_0,$SVE_IN23_1,$SVE_IN23_2,$SVE_IN23_3,$SVE_IN23_4) = map("z$_.s",(14..18));
my ($SVE_ACC0,$SVE_ACC1,$SVE_ACC2,$SVE_ACC3,$SVE_ACC4) = map("z$_.d",(19..23));
my ($SVE_H0,$SVE_H1,$SVE_H2,$SVE_H3,$SVE_H4) = map("z$_.s",(24..28));
my ($SVE_T0,$SVE_T1,$SVE_MASK) = map("z$_",(29..31));

$code.=<<___;
.type	poly1305_blocks_sve2_2way,%function
.align	5
poly1305_blocks_sve2_2way:
.Lpoly1305_blocks_sve2_2way:
	// This is the SVE2 implementation for the 2-way poly1305 parallelism, 
	//  requiring 128-bit registers. We don't expect it to be more efficient than Neon.
	AARCH64_VALID_CALL_TARGET
	ldr	$is_base2_26,[$ctx,#24]
	cmp	$len,#128
	b.hs	.Lblocks_sve2_2way
	cbz	$is_base2_26,.Lpoly1305_blocks	// branch to scalar code, but only if not in base 2^26 already

.Lblocks_sve2_2way:      // This is all exactly the same as in the Neon case
	AARCH64_SIGN_LINK_REGISTER
	stp	x29,x30,[sp,#-80]!
	add	x29,sp,#0

	ands	$len,$len,#-16
	b.eq	.Lno_data_sve2_2way

	cbz	$is_base2_26,.Lbase2_64_sve2_2way

	ldp	w10,w11,[$ctx]		// load hash value base 2^26
	ldp	w12,w13,[$ctx,#8]
	ldr	w14,[$ctx,#16]

	tst	$len,#31	// Take care of the first term (proceed if there is an odd number of terms, branch if even)
	b.eq	.Leven_sve2_2way

	ldp	$r0,$r1,[$ctx,#32]	// load key value

	add	$h0,x10,x11,lsl#26	// base 2^26 -> base 2^64
	lsr	$h1,x12,#12
	adds	$h0,$h0,x12,lsl#52
	add	$h1,$h1,x13,lsl#14
	adc	$h1,$h1,xzr
	lsr	$h2,x14,#24
	adds	$h1,$h1,x14,lsl#40
	adc	$d2,$h2,xzr		// can be partially reduced...

	ldp	$d0,$d1,[$inp],#16	// load input
	sub	$len,$len,#16
	add	$s1,$r1,$r1,lsr#2	// s1 = r1 + (r1 >> 2)

	and	$t0,$d2,#-4		// ... so reduce
	and	$h2,$d2,#3
	add	$t0,$t0,$d2,lsr#2
	adds	$h0,$h0,$t0
	adcs	$h1,$h1,xzr
	adc	$h2,$h2,xzr

#ifdef	__AARCH64EB__
	rev	$d0,$d0
	rev	$d1,$d1
#endif
	adds	$h0,$h0,$d0		// accumulate input
	adcs	$h1,$h1,$d1
	adc	$h2,$h2,$padbit

	bl	poly1305_mult
	ldr	x30,[sp,#8]

	cbz	$padbit,.Lstore_base2_64_sve2_2way

	and	x10,$h0,#0x03ffffff	// base 2^64 -> base 2^26
	ubfx	x11,$h0,#26,#26
	extr	x12,$h1,$h0,#52
	and	x12,x12,#0x03ffffff
	ubfx	x13,$h1,#14,#26
	extr	x14,$h2,$h1,#40

	cbnz	$len,.Leven_sve2_2way

	stp	w10,w11,[$ctx]		// store hash value base 2^26
	stp	w12,w13,[$ctx,#8]
	str	w14,[$ctx,#16]
	b	.Lno_data_sve2_2way

.align	4
.Lstore_base2_64_sve2_2way:
	stp	$h0,$h1,[$ctx]		// store hash value base 2^64
	stp	$h2,xzr,[$ctx,#16]	// note that is_base2_26 is zeroed
	b	.Lno_data_sve2_2way

.align	4
.Lbase2_64_sve2_2way:
	ldp	$r0,$r1,[$ctx,#32]	// load key value

	ldp	$h0,$h1,[$ctx]		// load hash value base 2^64
	ldr	$h2,[$ctx,#16]

	tst	$len,#31
	b.eq	.Linit_sve2_2way

	ldp	$d0,$d1,[$inp],#16	// load input
	sub	$len,$len,#16
	add	$s1,$r1,$r1,lsr#2	// s1 = r1 + (r1 >> 2)
#ifdef	__AARCH64EB__
	rev	$d0,$d0
	rev	$d1,$d1
#endif
	adds	$h0,$h0,$d0		// accumulate input
	adcs	$h1,$h1,$d1
	adc	$h2,$h2,$padbit

	bl	poly1305_mult

.Linit_sve2_2way:
	and	x10,$h0,#0x03ffffff	// base 2^64 -> base 2^26
	ubfx	x11,$h0,#26,#26
	extr	x12,$h1,$h0,#52
	and	x12,x12,#0x03ffffff
	ubfx	x13,$h1,#14,#26
	extr	x14,$h2,$h1,#40

	stp	d8,d9,[sp,#16]		// meet ABI requirements
	stp	d10,d11,[sp,#32]
	stp	d12,d13,[sp,#48]
	stp	d14,d15,[sp,#64]

    // See if below can somehow be interleaved with above instructions for better perf.
	eor 	z24.d,z24.d,z24.d  // H0
	eor 	z25.d,z25.d,z25.d  // H1
	eor 	z26.d,z26.d,z26.d  // H2
	eor 	z27.d,z27.d,z27.d  // H3
	eor 	z28.d,z28.d,z28.d  // H4

	// Latency 5, throughput 1??? 
	// Alternative: ptrue to set preds and cpy (but same latency and throughput).
	// Could just use Neon's fmov here.... 
    insr    $SVE_H0, w10
    insr    $SVE_H1, w11
    insr    $SVE_H2, w12
    insr    $SVE_H3, w13
    insr    $SVE_H4, w14

	////////////////////////////////// initialize r^n table
	mov	$h0,$r0			// r^1
	add	$s1,$r1,$r1,lsr#2	// s1 = r1 + (r1 >> 2)
	mov	$h1,$r1
	mov	$h2,xzr
	add	$ctx,$ctx,#48+12
	bl	poly1305_splat

	bl	poly1305_mult		// r^2
	sub	$ctx,$ctx,#8        // re-ordering original Neon order
	bl	poly1305_splat

	bl	poly1305_mult		// r^3
	add	$ctx,$ctx,#4
	bl	poly1305_splat

	bl	poly1305_mult		// r^4
	sub	$ctx,$ctx,#8
	bl	poly1305_splat
	ldr	x30,[sp,#8]

	add	$in2,$inp,#32
	adrp	$zeros,.Lzeros
	add	$zeros,$zeros,:lo12:.Lzeros
	subs	$len,$len,#64
	csel	$in2,$zeros,$in2,lo

	mov	x4,#1
	stur	x4,[$ctx,#-24]		// set is_base2_26
	sub	$ctx,$ctx,#48		// restore original $ctx
	b	.Ldo_sve2_2way

.align	4
.Leven_sve2_2way:
	add	$in2,$inp,#32
	adrp	$zeros,.Lzeros
	add	$zeros,$zeros,:lo12:.Lzeros
	subs	$len,$len,#64
	csel	$in2,$zeros,$in2,lo

	stp	d8,d9,[sp,#16]		// meet ABI requirements
	stp	d10,d11,[sp,#32]
	stp	d12,d13,[sp,#48]
	stp	d14,d15,[sp,#64]

	eor 	z24.d,z24.d,z24.d  // H0
	eor 	z25.d,z25.d,z25.d  // H1
	eor 	z26.d,z26.d,z26.d  // H2
	eor 	z27.d,z27.d,z27.d  // H3
	eor 	z28.d,z28.d,z28.d  // H4

	// Latency 5, throughput 1??? 
	// Alternative: ptrue to set preds and cpy (but same latency and throughput).
	// Could just use Neon's fmov here.... 
    insr    $SVE_H0, w10
    insr    $SVE_H1, w11
    insr    $SVE_H2, w12
    insr    $SVE_H3, w13
    insr    $SVE_H4, w14

.Ldo_sve2_2way:
	ldp	x8,x12,[$in2],#16	// inp[2:3] (or zero)
	ldp	x9,x13,[$in2],#48

	lsl	$padbit,$padbit,#24
	add	x15,$ctx,#48

	eor 	z14.d,z14.d,z14.d  // IN23_0
	eor 	z15.d,z15.d,z15.d  // IN23_1
	eor 	z16.d,z16.d,z16.d  // IN23_2
	eor 	z17.d,z17.d,z17.d  // IN23_3
	eor 	z18.d,z18.d,z18.d  // IN23_4

	// Also this:
    ptrue   p0.b, ALL               // Set all-true predicate
    ptrue   p1.s, VL1               // Predicate for lane 1
    ptrue   p3.s, VL3               // Predicate for first 3 lanes
    ptrue   p2.s, VL2               // Predicate for first 2 lanes
    eor     p3.b, p0/z, p3.b, p2.b  // p3 now activates only lane 3

#ifdef	__AARCH64EB__
	rev	x8,x8
	rev	x12,x12
	rev	x9,x9
	rev	x13,x13
#endif

    // Below I use `CPY from scalar` instruction - 
	//  it has latency of 5 and throughput of 1
	//  instead, I might try using `fmov` to SIMD and
	//  then `CPY from SIMD&fp` - the first has latency 3 and throughput 1,
	//  wile the second has latency 2 and throughput 4 (or even 6 on x925).
	// But it is hardly better, and increases number ot instructions...
    and 	w4, w8, #0x03ffffff         // w4 = limb 0 from stream 0 (inp[2]) - need to check it's OK to use single-word reg here!
    and 	w5, w9, #0x03ffffff         // w5 = limb 0 from stream 1 (inp[3])
    cpy 	$SVE_IN23_0, p1/m, w4       // Insert limb 0 (stream 0) into lane 0
    cpy 	$SVE_IN23_0, p3/m, w5       // Insert limb 0 (stream 1) into lane 2 - need to interleave

    ubfx	x6, x8, #26, #26            // w6 = limb 1 from stream 0 (inp[2])
    ubfx	x7, x9, #26, #26            // w7 = limb 1 from stream 1 (inp[3])
    cpy 	$SVE_IN23_1, p1/m, w6       // Insert limb 1 (stream 0) into lane 0
    cpy 	$SVE_IN23_1, p3/m, w7       // Insert limb 1 (stream 1) into lane 2 - need to interleave

    extr	x8, x12, x8, #52            // Reconstruct bits for limb 2 from stream 0
    extr	x9, x13, x9, #52            // Reconstruct bits for limb 2 from stream 1
    and 	w8, w8, #0x03ffffff         // w8 = limb 2 from stream 0
    and 	w9, w9, #0x03ffffff         // w9 = limb 2 from stream 1
    cpy 	$SVE_IN23_2, p1/m, w8       // Insert limb 2 (stream 0) into lane 0
    cpy 	$SVE_IN23_2, p3/m, w9       // Insert limb 2 (stream 1) into lane 2 - need to interleave

    ubfx	x10, x12, #14, #26          // w10 = limb 3 from stream 0
    ubfx	x11, x13, #14, #26          // w11 = limb 3 from stream 1
    cpy 	$SVE_IN23_3, p1/m, w10      // Insert limb 3 (stream 0) into lane 0
    cpy 	$SVE_IN23_3, p3/m, w11      // Insert limb 3 (stream 1) into lane 2 - need to interleave

	add		x12,$padbit,x12,lsr#40      // w12 = limb 4 from stream 0
	add		x13,$padbit,x13,lsr#40      // w13 = limb 4 from stream 0
    cpy		$SVE_IN23_4, p1/m, w12      // Insert limb 3 (stream 0) into lane 0
    cpy		$SVE_IN23_4, p3/m, w13      // Insert limb 3 (stream 1) into lane 2 - need to interleave

	ldp		x8,x12,[$inp],#16	        // inp[0:1]
	ldp		x9,x13,[$inp],#48

    // interleave with above?
	eor 	z9.d,z9.d,z9.d     // IN01_0
	eor 	z10.d,z10.d,z10.d  // IN01_1
	eor 	z11.d,z11.d,z11.d  // IN01_2
	eor 	z12.d,z12.d,z12.d  // IN01_3
	eor 	z13.d,z13.d,z13.d  // IN01_4

	// while LD4W { <Zt1>.S, <Zt2>.S, <Zt3>.S, <Zt4>.S }, <Pg>/Z, [<Xn|SP>{, #<imm>, MUL VL}]
	// exists in FEAT_SVE, it de-interleaves - I will need to re-write poly1305_splat (or just usage below?...)
	// Contiguous load exists in FEAT_SVE2v1, this should be possible in the future:
	// LD1W { <Zt1>.S-<Zt2>.S }, <PNg>/Z, [<Xn|SP>{, #<imm>, MUL VL}]
	// For now I will have to live with the following (interleave interleave?):
    ld1w    { $SVE_R0 }, p0/z, [x15]            
    ld1w    { $SVE_R1 }, p0/z, [x15, #1, MUL VL]
    ld1w    { $SVE_S1 }, p0/z, [x15, #2, MUL VL]
    ld1w    { $SVE_R2 }, p0/z, [x15, #3, MUL VL]
    ld1w    { $SVE_S2 }, p0/z, [x15, #4, MUL VL]
    ld1w    { $SVE_R3 }, p0/z, [x15, #5, MUL VL]
    ld1w    { $SVE_S3 }, p0/z, [x15, #6, MUL VL]
    ld1w    { $SVE_R4 }, p0/z, [x15, #7, MUL VL]
	add     x15, x15, #128     // [x15, #8, MUL VL] would be out of bounds..
    ld1w    { $SVE_S4 }, p0/z, [x15]

#ifdef	__AARCH64EB__
	rev	x8,x8
	rev	x12,x12
	rev	x9,x9
	rev	x13,x13
#endif

    and 	w4, w8, #0x03ffffff         // w4 = limb 0 from stream 0 (inp[0]) - need to check it's OK to use single-word reg here!
    and 	w5, w9, #0x03ffffff         // w5 = limb 0 from stream 1 (inp[1])
    cpy 	$SVE_IN01_0, p1/m, w4       // Insert limb 0 (stream 0) into lane 0
    cpy 	$SVE_IN01_0, p3/m, w5       // Insert limb 0 (stream 1) into lane 2 - need to interleave

    ubfx	x6, x8, #26, #26            // w6 = limb 1 from stream 0
    ubfx	x7, x9, #26, #26            // w7 = limb 1 from stream 1
    cpy 	$SVE_IN01_1, p1/m, w6       // Insert limb 1 (stream 0) into lane 0
    cpy 	$SVE_IN01_1, p3/m, w7       // Insert limb 1 (stream 1) into lane 2 - need to interleave

    extr	x8, x12, x8, #52            // Reconstruct bits for limb 2 from stream 0
    extr	x9, x13, x9, #52            // Reconstruct bits for limb 2 from stream 1
    and 	w8, w8, #0x03ffffff         // w8 = limb 2 from stream 0
    and 	w9, w9, #0x03ffffff         // w9 = limb 2 from stream 1
    cpy 	$SVE_IN01_2, p1/m, w8       // Insert limb 2 (stream 0) into lane 0
    cpy 	$SVE_IN01_2, p3/m, w9       // Insert limb 2 (stream 1) into lane 2 - need to interleave

    ubfx	x10, x12, #14, #26          // w10 = limb 3 from stream 0
    ubfx	x11, x13, #14, #26          // w11 = limb 3 from stream 1
    cpy 	$SVE_IN01_3, p1/m, w10      // Insert limb 3 (stream 0) into lane 0
    cpy 	$SVE_IN01_3, p3/m, w11      // Insert limb 3 (stream 1) into lane 2 - need to interleave

	add		x12,$padbit,x12,lsr#40      // w12 = limb 4 from stream 0
	add		x13,$padbit,x13,lsr#40      // w13 = limb 4 from stream 0
	dup		${SVE_MASK}.d,#-1
    cpy		$SVE_IN01_4, p1/m, w12      // Insert limb 3 (stream 0) into lane 0
    cpy		$SVE_IN01_4, p3/m, w13      // Insert limb 3 (stream 1) into lane 2 - need to interleave
	lsr		${SVE_MASK}.d,${SVE_MASK}.d,#38

	b.ls	.Lskip_loop_sve2_2way

.align	4
.Loop_sve2_2way:
	////////////////////////////////////////////////////////////////
	// ((inp[0]*r^4+inp[2]*r^2+inp[4])*r^4+inp[6]*r^2
	// ((inp[1]*r^4+inp[3]*r^2+inp[5])*r^3+inp[7]*r
	//   \___________________/
	// ((inp[0]*r^4+inp[2]*r^2+inp[4])*r^4+inp[6]*r^2+inp[8])*r^2
	// ((inp[1]*r^4+inp[3]*r^2+inp[5])*r^4+inp[7]*r^2+inp[9])*r
	//   \___________________/ \____________________/
	//
	// Note that we start with inp[2:3]*r^2. This is because it
	// doesn't depend on reduction in previous iteration.
	////////////////////////////////////////////////////////////////
	// d4 = h0*r4 + h1*r3   + h2*r2   + h3*r1   + h4*r0
	// d3 = h0*r3 + h1*r2   + h2*r1   + h3*r0   + h4*5*r4
	// d2 = h0*r2 + h1*r1   + h2*r0   + h3*5*r4 + h4*5*r3
	// d1 = h0*r1 + h1*r0   + h2*5*r4 + h3*5*r3 + h4*5*r2
	// d0 = h0*r0 + h1*5*r4 + h2*5*r3 + h3*5*r2 + h4*5*r1

	subs	$len,$len,#64
	umullb  $SVE_ACC4,$SVE_IN23_0,${SVE_R4}[1]  // remember - order changed from Neon impl.
	csel	$in2,$zeros,$in2,lo
	umullb	$SVE_ACC3,$SVE_IN23_0,${SVE_R3}[1]
	umullb	$SVE_ACC2,$SVE_IN23_0,${SVE_R2}[1]
	 ldp	x8,x12,[$in2],#16	                // inp[2:3] (or zero)
	umullb	$SVE_ACC1,$SVE_IN23_0,${SVE_R1}[1]
	 ldp	x9,x13,[$in2],#48
	umullb	$SVE_ACC0,$SVE_IN23_0,${SVE_R0}[1]

#ifdef	__AARCH64EB__
	 rev	x8,x8
	 rev	x12,x12
	 rev	x9,x9
	 rev	x13,x13
#endif

	umlalb	$SVE_ACC4,$SVE_IN23_1,${SVE_R3}[1]
     and    w4, w8, #0x03ffffff
	umlalb	$SVE_ACC3,$SVE_IN23_1,${SVE_R2}[1]
     and    w5, w9, #0x03ffffff
	umlalb	$SVE_ACC2,$SVE_IN23_1,${SVE_R1}[1]
     cpy    $SVE_IN23_0, p1/m, w4
	umlalb	$SVE_ACC1,$SVE_IN23_1,${SVE_R0}[1]
     cpy    $SVE_IN23_0, p3/m, w5                // need to interleave better?
	umlalb	$SVE_ACC0,$SVE_IN23_1,${SVE_S4}[1]

     ubfx   x6, x8, #26, #26
	umlalb	$SVE_ACC4,$SVE_IN23_2,${SVE_R2}[1]
	 ubfx   x7, x9, #26, #26
	umlalb	$SVE_ACC3,$SVE_IN23_2,${SVE_R1}[1]
	 cpy    $SVE_IN23_1, p1/m, w6                // too soon?
	umlalb	$SVE_ACC2,$SVE_IN23_2,${SVE_R0}[1]
	 cpy    $SVE_IN23_1, p3/m, w7
	umlalb	$SVE_ACC1,$SVE_IN23_2,${SVE_S4}[1]
	 extr   x8, x12, x8, #52                     // starting the next limb...
	umlalb	$SVE_ACC0,$SVE_IN23_2,${SVE_S3}[1]

     extr   x9, x13, x9, #52
	umlalb	$SVE_ACC4,$SVE_IN23_3,${SVE_R1}[1]
	 and    w8, w8, #0x03ffffff
	umlalb	$SVE_ACC3,$SVE_IN23_3,${SVE_R0}[1]
	 and    w9, w9, #0x03ffffff
	umlalb	$SVE_ACC2,$SVE_IN23_3,${SVE_S4}[1]
	 cpy    $SVE_IN23_2, p1/m, w8                // too soon?
	umlalb	$SVE_ACC1,$SVE_IN23_3,${SVE_S3}[1]
	 cpy    $SVE_IN23_2, p3/m, w9
	umlalb	$SVE_ACC0,$SVE_IN23_3,${SVE_S2}[1]

	add		$SVE_IN01_2,$SVE_IN01_2,$SVE_H2
	 ubfx   x10, x12, #14, #26
	umlalb	$SVE_ACC4,$SVE_IN23_4,${SVE_R0}[1]
	 ubfx   x11, x13, #14, #26
	umlalb	$SVE_ACC3,$SVE_IN23_4,${SVE_S4}[1]
	 cpy    $SVE_IN23_3, p1/m, w10               // too soon?
	umlalb	$SVE_ACC2,$SVE_IN23_4,${SVE_S3}[1]
	 cpy    $SVE_IN23_3, p3/m, w11
	umlalb	$SVE_ACC1,$SVE_IN23_4,${SVE_S2}[1]
	 add	   x12,$padbit,x12,lsr#40            // Start next limb...
	umlalb	$SVE_ACC0,$SVE_IN23_4,${SVE_S1}[1]
	 add	   x13,$padbit,x13,lsr#40

	////////////////////////////////////////////////////////////////
	// (hash+inp[0:1])*r^4 and accumulate

	// Here R1-S3 index remains unchanged from Neon impl.
	add		$SVE_IN01_0,$SVE_IN01_0,$SVE_H0
	 cpy    $SVE_IN23_4, p1/m, w12
	umlalb	$SVE_ACC3,$SVE_IN01_2,${SVE_R1}[0]  // Not sure why start from 01_2 here, should be easier to start from 01_0
	 cpy    $SVE_IN23_4, p3/m, w13
	umlalb	$SVE_ACC0,$SVE_IN01_2,${SVE_S3}[0]
	 ldp	x8,x12,[$inp],#16	                  // inp[0:1]
	umlalb	$SVE_ACC4,$SVE_IN01_2,${SVE_R2}[0]
	 ldp	x9,x13,[$inp],#48
	umlalb	$SVE_ACC1,$SVE_IN01_2,${SVE_S4}[0]
	umlalb	$SVE_ACC2,$SVE_IN01_2,${SVE_R0}[0]

#ifdef	__AARCH64EB__
	 rev	x8,x8
	 rev	x12,x12
	 rev	x9,x9
	 rev	x13,x13
#endif

	add		$SVE_IN01_1,$SVE_IN01_1,$SVE_H1
	 and    w4, w8, #0x03ffffff
	umlalb	$SVE_ACC3,$SVE_IN01_0,${SVE_R3}[0]
	 and    w5, w9, #0x03ffffff
	umlalb	$SVE_ACC4,$SVE_IN01_0,${SVE_R4}[0]
	 ubfx   x6, x8, #26, #26                       // here I am postponing copying into IN01...
	umlalb	$SVE_ACC2,$SVE_IN01_0,${SVE_R2}[0]
	 ubfx   x7, x9, #26, #26
	umlalb	$SVE_ACC0,$SVE_IN01_0,${SVE_R0}[0]
	 extr   x8, x12, x8, #52                       // starting lobe 3 already...
	umlalb	$SVE_ACC1,$SVE_IN01_0,${SVE_R1}[0]
	 extr   x9, x13, x9, #52

	add		$SVE_IN01_3,$SVE_IN01_3,$SVE_H3
	 and    w8, w8, #0x03ffffff
	umlalb	$SVE_ACC3,$SVE_IN01_1,${SVE_R2}[0]
	 and    w9, w9, #0x03ffffff
	umlalb	$SVE_ACC4,$SVE_IN01_1,${SVE_R3}[0]
	 cpy    $SVE_IN01_0, p1/m, w4
	umlalb	$SVE_ACC0,$SVE_IN01_1,${SVE_S4}[0]
	 cpy    $SVE_IN01_0, p3/m, w5                   // interleave more?
	umlalb	$SVE_ACC2,$SVE_IN01_1,${SVE_R1}[0]
	 ubfx   x10, x12, #14, #26
	umlalb	$SVE_ACC1,$SVE_IN01_1,${SVE_R0}[0]
	 ubfx   x11, x13, #14, #26

	add		$SVE_IN01_4,$SVE_IN01_4,$SVE_H4
	 cpy    $SVE_IN01_2, p1/m, w8
	umlalb	$SVE_ACC3,$SVE_IN01_3,${SVE_R0}[0]
	 cpy    $SVE_IN01_2, p3/m, w9
	umlalb	$SVE_ACC0,$SVE_IN01_3,${SVE_S2}[0]
	 add	   x12,$padbit,x12,lsr#40
	umlalb	$SVE_ACC4,$SVE_IN01_3,${SVE_R1}[0]
	 add	   x13,$padbit,x13,lsr#40
	umlalb	$SVE_ACC1,$SVE_IN01_3,${SVE_S3}[0]
	 cpy    $SVE_IN01_1, p1/m, w6
	umlalb	$SVE_ACC2,$SVE_IN01_3,${SVE_S4}[0]
	 cpy    $SVE_IN01_1, p3/m, w7

	umlalb	$SVE_ACC3,$SVE_IN01_4,${SVE_S4}[0]
	 cpy    $SVE_IN01_3, p1/m, w10                 // too many copies in a row - should restructure
	umlalb	$SVE_ACC0,$SVE_IN01_4,${SVE_S1}[0]
	 cpy    $SVE_IN01_3, p3/m, w11
	umlalb	$SVE_ACC4,$SVE_IN01_4,${SVE_R0}[0]
	umlalb	$SVE_ACC1,$SVE_IN01_4,${SVE_S2}[0]
	umlalb	$SVE_ACC2,$SVE_IN01_4,${SVE_S3}[0]
	 cpy    $SVE_IN01_4, p1/m, w12
	 cpy    $SVE_IN01_4, p3/m, w13

	/////////////////////////////////////////////////////////////////
	// lazy reduction as discussed in "NEON crypto" by D.J. Bernstein
	// and P. Schwabe

	lsr		${SVE_T0}.d,$SVE_ACC3,#26
	trn1	$SVE_H3,z22.s,z24.s					// reproducing Neon's `xtn` - treat ACC3 as a .s vector
	lsr		${SVE_T1}.d,$SVE_ACC0,#26
	and 	$SVE_ACC0,$SVE_ACC0,${SVE_MASK}.d
	add		$SVE_ACC4,$SVE_ACC4,${SVE_T0}.d	    // h3 -> h4
	// Neon's bic is replaced with &=$SVE_MASK (because of using even-indexed elements)
	and 	z27.d,z27.d,${SVE_MASK}.d			// refer to SVE_H3 as .d
	add		$SVE_ACC1,$SVE_ACC1,${SVE_T1}.d	    // h0 -> h1

    lsr		${SVE_T0}.d,$SVE_ACC4,#26
	trn1	$SVE_H4,z23.s,z24.s					// reproducing Neon's `xtn` - treat ACC4 as a .s vector
    lsr		${SVE_T1}.d,$SVE_ACC1,#26
	trn1	$SVE_H1,z20.s,z24.s					// reproducing Neon's `xtn` - treat ACC1 as a .s vector
	and 	z28.d,z28.d,${SVE_MASK}.d			// refer to SVE_H4 as .d
	add		$SVE_ACC2,$SVE_ACC2,${SVE_T1}.d	    // h1 -> h2

	add		$SVE_ACC0,$SVE_ACC0,${SVE_T0}.d
	lsl 	${SVE_T0}.d,${SVE_T0}.d,#2
	shrnb	${SVE_T1}.s,$SVE_ACC2,#26			// check it's OK
	trn1	$SVE_H2,z21.s,z24.s					// reproducing Neon's `xtn` - treat ACC2 as a .s vector
	add 	$SVE_ACC0,$SVE_ACC0,${SVE_T0}.d		// h4 -> h0
	and 	z25.d,z25.d,${SVE_MASK}.d			// refer to SVE_H1 as .d
	add 	$SVE_H3,$SVE_H3,${SVE_T1}.s			// h2 -> h3
	and 	z26.d,z26.d,${SVE_MASK}.d			// refer to SVE_H2 as .d

    shrnb	${SVE_T0}.s,$SVE_ACC0,#26
	trn1	$SVE_H0,z19.s,z24.s					// reproducing Neon's `xtn` - treat ACC0 as a .s vector - re-writing H0 here...
    lsr 	${SVE_T1}.s,$SVE_H3,#26
	and 	z27.d,z27.d,${SVE_MASK}.d			// refer to SVE_H3 as .d
	add		$SVE_H1,$SVE_H1,${SVE_T0}.s			// h0 -> h1
	and 	z24.d,z24.d,${SVE_MASK}.d			// refer to SVE_H0 as .d
	add		$SVE_H4,$SVE_H4,${SVE_T1}.s			// h3 -> h4

	b.hi	.Loop_sve2_2way

.Lskip_loop_sve2_2way:
    trn1	$SVE_IN23_2,$SVE_IN23_2,$SVE_IN23_2
	add		$SVE_IN01_2,$SVE_IN01_2,$SVE_H2

	////////////////////////////////////////////////////////////////
	// multiply (inp[0:1]+hash) or inp[2:3] by r^2:r^1

	adds	$len,$len,#32
	b.ne	.Long_tail_sve2_2way

    trn1	$SVE_IN23_2,$SVE_IN01_2,$SVE_IN01_2
	add		$SVE_IN23_0,$SVE_IN01_0,$SVE_H0
	add		$SVE_IN23_3,$SVE_IN01_3,$SVE_H3
	add		$SVE_IN23_1,$SVE_IN01_1,$SVE_H1
	add		$SVE_IN23_4,$SVE_IN01_4,$SVE_H4

.Long_tail_sve2_2way:
    trn1	$SVE_IN23_0,$SVE_IN23_0,$SVE_IN23_0
	umullt	$SVE_ACC0,$SVE_IN23_2,$SVE_S3
	umullt	$SVE_ACC3,$SVE_IN23_2,$SVE_R1
	umullt	$SVE_ACC4,$SVE_IN23_2,$SVE_R2
	umullt	$SVE_ACC2,$SVE_IN23_2,$SVE_R0
	umullt	$SVE_ACC1,$SVE_IN23_2,$SVE_S4

    trn1	$SVE_IN23_1,$SVE_IN23_1,$SVE_IN23_1
	umlalt	$SVE_ACC0,$SVE_IN23_0,$SVE_R0
	umlalt	$SVE_ACC2,$SVE_IN23_0,$SVE_R2
	umlalt	$SVE_ACC3,$SVE_IN23_0,$SVE_R3
	umlalt	$SVE_ACC4,$SVE_IN23_0,$SVE_R4
	umlalt	$SVE_ACC1,$SVE_IN23_0,$SVE_R1

    trn1	$SVE_IN23_3,$SVE_IN23_3,$SVE_IN23_3
	umlalt	$SVE_ACC0,$SVE_IN23_1,$SVE_S4
	umlalt	$SVE_ACC3,$SVE_IN23_1,$SVE_R2
	umlalt	$SVE_ACC2,$SVE_IN23_1,$SVE_R1
	umlalt	$SVE_ACC4,$SVE_IN23_1,$SVE_R3
	umlalt	$SVE_ACC1,$SVE_IN23_1,$SVE_R0

    trn1	$SVE_IN23_4,$SVE_IN23_4,$SVE_IN23_4
	umlalt	$SVE_ACC3,$SVE_IN23_3,$SVE_R0
	umlalt	$SVE_ACC4,$SVE_IN23_3,$SVE_R1
	umlalt	$SVE_ACC0,$SVE_IN23_3,$SVE_S2
	umlalt	$SVE_ACC1,$SVE_IN23_3,$SVE_S3
	umlalt	$SVE_ACC2,$SVE_IN23_3,$SVE_S4

	umlalt	$SVE_ACC3,$SVE_IN23_4,$SVE_S4
	umlalt	$SVE_ACC0,$SVE_IN23_4,$SVE_S1
	umlalt	$SVE_ACC4,$SVE_IN23_4,$SVE_R0
	umlalt	$SVE_ACC1,$SVE_IN23_4,$SVE_S2
	umlalt	$SVE_ACC2,$SVE_IN23_4,$SVE_S3

	b.eq	.Lshort_tail_sve2_2way

	////////////////////////////////////////////////////////////////
	// (hash+inp[0:1])*r^4:r^3 and accumulate

	add		$SVE_IN01_0,$SVE_IN01_0,$SVE_H0
	umlalb	$SVE_ACC3,$SVE_IN01_2,$SVE_R1
	umlalb	$SVE_ACC0,$SVE_IN01_2,$SVE_S3
	umlalb	$SVE_ACC4,$SVE_IN01_2,$SVE_R2
	umlalb	$SVE_ACC1,$SVE_IN01_2,$SVE_S4
	umlalb	$SVE_ACC2,$SVE_IN01_2,$SVE_R0

	add		$SVE_IN01_1,$SVE_IN01_1,$SVE_H1
	umlalb	$SVE_ACC3,$SVE_IN01_0,$SVE_R3
	umlalb	$SVE_ACC0,$SVE_IN01_0,$SVE_R0
	umlalb	$SVE_ACC4,$SVE_IN01_0,$SVE_R4
	umlalb	$SVE_ACC1,$SVE_IN01_0,$SVE_R1
	umlalb	$SVE_ACC2,$SVE_IN01_0,$SVE_R2

	add		$SVE_IN01_3,$SVE_IN01_3,$SVE_H3
	umlalb	$SVE_ACC3,$SVE_IN01_1,$SVE_R2
	umlalb	$SVE_ACC0,$SVE_IN01_1,$SVE_S4
	umlalb	$SVE_ACC4,$SVE_IN01_1,$SVE_R3
	umlalb	$SVE_ACC1,$SVE_IN01_1,$SVE_R0
	umlalb	$SVE_ACC2,$SVE_IN01_1,$SVE_R1

	add		$SVE_IN01_4,$SVE_IN01_4,$SVE_H4
	umlalb	$SVE_ACC3,$SVE_IN01_3,$SVE_R0
	umlalb	$SVE_ACC0,$SVE_IN01_3,$SVE_S2
	umlalb	$SVE_ACC4,$SVE_IN01_3,$SVE_R1
	umlalb	$SVE_ACC1,$SVE_IN01_3,$SVE_S3
	umlalb	$SVE_ACC2,$SVE_IN01_3,$SVE_S4

	umlalb	$SVE_ACC3,$SVE_IN01_4,$SVE_S4
	umlalb	$SVE_ACC0,$SVE_IN01_4,$SVE_S1
	umlalb	$SVE_ACC4,$SVE_IN01_4,$SVE_R0
	umlalb	$SVE_ACC1,$SVE_IN01_4,$SVE_S2
	umlalb	$SVE_ACC2,$SVE_IN01_4,$SVE_S3

.Lshort_tail_sve2_2way:
	////////////////////////////////////////////////////////////////
	// horizontal add

	//In Neon implementation, one effectively using lower 64 bits of vector registers here.
	//Here and below I use hard-coded FP registers, could introduce new variables...

	uaddv   d22, p0, $SVE_ACC3
	 ldp	d8,d9,[sp,#16]		// meet ABI requirements
	uaddv   d19, p0, $SVE_ACC0
	 ldp	d10,d11,[sp,#32]
	uaddv   d23, p0, $SVE_ACC4
	 ldp	d12,d13,[sp,#48]
	uaddv   d20, p0, $SVE_ACC1
	 ldp	d14,d15,[sp,#64]
	uaddv   d21, p0, $SVE_ACC2

	////////////////////////////////////////////////////////////////
	// lazy reduction, but without narrowing

	// Since results were accumulated in the lower 64 bits, I can refer to them as FP/aSIMD reg-s.

	ushr	d29,d22,#26
	and		v22.8b,v22.8b,v31.8b
	ushr	d30,d19,#26
	and		v19.8b,v19.8b,v31.8b

	add 	d23,d23,d29				// h3 -> h4
	add 	d20,d20,d30				// h0 -> h1

	ushr	d29,d23,#26
	and		v23.8b,v23.8b,v31.8b
	ushr	d30,d20,#26
	and		v20.8b,v20.8b,v31.8b
	add		d21,d21,d30				// h1 -> h2

	add 	d19,d19,d29
	shl 	d29,d29,#2
	ushr	d30,d21,#26
	and		v21.8b,v21.8b,v31.8b
	add 	d19,d19,d29				// h4 -> h0
	add 	d22,d22,d30				// h2 -> h3

    ushr	d29,d19,#26
	and		v19.8b,v19.8b,v31.8b
	ushr 	d30,d22,#26
	and		v22.8b,v22.8b,v31.8b
	add 	d20,d20,d29				// h0 -> h1
	add 	d23,d23,d30				// h3 -> h4

	////////////////////////////////////////////////////////////////
	// write the result, can be partially reduced

	stp 	s19,s20,[$ctx],#8
	stp 	s21,s22,[$ctx],#8
	str 	s23,[$ctx]
	
.Lno_data_sve2_2way:
	ldr	x29,[sp],#80
	AARCH64_VALIDATE_LINK_REGISTER
	ret
.size	poly1305_blocks_sve2_2way,.-poly1305_blocks_sve2_2way

.rodata

.align	5
.Lzeros:
.long	0,0,0,0,0,0,0,0
.asciz	"Poly1305 for ARMv8, CRYPTOGAMS by <https://github.com/dot-asm>"
.align	2
___

foreach (split("\n",$code)) {
	s/\b(shrn\s+v[0-9]+)\.[24]d/$1.2s/			or
	s/\b(fmov\s+)v([0-9]+)[^,]*,\s*x([0-9]+)/$1d$2,x$3/	or
	(m/\bdup\b/ and (s/\.[24]s/.2d/g or 1))			or
	(m/\b(eor|and)/ and (s/\.[248][sdh]/.16b/g or 1))	or
	(m/\bum(ul|la)l\b/ and (s/\.4s/.2s/g or 1))		or
	(m/\bum(ul|la)l2\b/ and (s/\.2s/.4s/g or 1))		or
	(m/\bst[1-4]\s+{[^}]+}\[/ and (s/\.[24]d/.s/g or 1));

	s/\.[124]([sd])\[/.$1\[/;

	print $_,"\n";
}
close STDOUT or die "error closing STDOUT: $!";
