#!/usr/bin/env perl

# ====================================================================
# Written by Andy Polyakov <appro@openssl.org> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================

# October 2005.
#
# Montgomery multiplication routine for x86_64. While it gives modest
# 9% improvement of rsa4096 sign on Opteron, rsa512 sign runs more
# than twice, >2x, as fast. Most common rsa1024 sign is improved by
# respectful 50%. It remains to be seen if loop unrolling and
# dedicated squaring routine can provide further improvement...

# July 2011.
#
# Add dedicated squaring procedure. Performance improvement varies
# from platform to platform, but in average it's ~5%/15%/25%/33%
# for 512-/1024-/2048-/4096-bit RSA *sign* benchmarks respectively.

# August 2011.
#
# Unroll and modulo-schedule inner loops in such manner that they
# are "fallen through" for input lengths of 8, which is critical for
# 1024-bit RSA *sign*. Average performance improvement in comparison
# to *initial* version of this module from 2005 is ~0%/30%/40%/45%
# for 512-/1024-/2048-/4096-bit RSA *sign* benchmarks respectively.

# June 2013.
#
# Optimize reduction in squaring procedure and improve 1024+-bit RSA
# sign performance by 10-16% on Intel Sandy Bridge and later
# (virtually same on non-Intel processors).

# August 2013.
#
# Add MULX/ADOX/ADCX code path.

$flavour = shift;
$output  = shift;
if ($flavour =~ /\./) { $output = $flavour; undef $flavour; }

$win64=0; $win64=1 if ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}x86_64-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/x86_64-xlate.pl" and -f $xlate) or
die "can't locate x86_64-xlate.pl";

open OUT,"| \"$^X\" $xlate $flavour $output";
*STDOUT=*OUT;

if (`$ENV{CC} -Wa,-v -c -o /dev/null -x assembler /dev/null 2>&1`
		=~ /GNU assembler version ([2-9]\.[0-9]+)/) {
	$addx = ($1>=2.23);
}

if (!$addx && $win64 && ($flavour =~ /nasm/ || $ENV{ASM} =~ /nasm/) &&
	    `nasm -v 2>&1` =~ /NASM version ([2-9]\.[0-9]+)/) {
	$addx = ($1>=2.10);
}

if (!$addx && $win64 && ($flavour =~ /masm/ || $ENV{ASM} =~ /ml64/) &&
	    `ml64 2>&1` =~ /Version ([0-9]+)\./) {
	$addx = ($1>=12);
}

# int bn_mul_mont(
$rp="%rdi";	# BN_ULONG *rp,
$ap="%rsi";	# const BN_ULONG *ap,
$bp="%rdx";	# const BN_ULONG *bp,
$np="%rcx";	# const BN_ULONG *np,
$n0="%r8";	# const BN_ULONG *n0,
$num="%r9";	# int num);
$lo0="%r10";
$hi0="%r11";
$hi1="%r13";
$i="%r14";
$j="%r15";
$m0="%rbx";
$m1="%rbp";

$code=<<___;
.text

.extern	OPENSSL_ia32cap_P

.globl	bn_mul_mont
.type	bn_mul_mont,\@function,6
.align	16
bn_mul_mont:
	test	\$3,${num}d
	jnz	.Lmul_enter
	cmp	\$8,${num}d
	jb	.Lmul_enter
___
$code.=<<___ if ($addx);
	mov	OPENSSL_ia32cap_P+8(%rip),%r11d
___
$code.=<<___;
	cmp	$ap,$bp
	jne	.Lmul4x_enter
	test	\$7,${num}d
	jz	.Lsqr8x_enter
	jmp	.Lmul4x_enter

.align	16
.Lmul_enter:
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14
	push	%r15

	mov	${num}d,${num}d
	lea	2($num),%r10
	mov	%rsp,%r11
	neg	%r10
	lea	(%rsp,%r10,8),%rsp	# tp=alloca(8*(num+2))
	and	\$-1024,%rsp		# minimize TLB usage

	mov	%r11,8(%rsp,$num,8)	# tp[num+1]=%rsp
.Lmul_body:
	mov	$bp,%r12		# reassign $bp
___
		$bp="%r12";
$code.=<<___;
	mov	($n0),$n0		# pull n0[0] value
	mov	($bp),$m0		# m0=bp[0]
	mov	($ap),%rax

	xor	$i,$i			# i=0
	xor	$j,$j			# j=0

	mov	$n0,$m1
	mulq	$m0			# ap[0]*bp[0]
	mov	%rax,$lo0
	mov	($np),%rax

	imulq	$lo0,$m1		# "tp[0]"*n0
	mov	%rdx,$hi0

	mulq	$m1			# np[0]*m1
	add	%rax,$lo0		# discarded
	mov	8($ap),%rax
	adc	\$0,%rdx
	mov	%rdx,$hi1

	lea	1($j),$j		# j++
	jmp	.L1st_enter

.align	16
.L1st:
	add	%rax,$hi1
	mov	($ap,$j,8),%rax
	adc	\$0,%rdx
	add	$hi0,$hi1		# np[j]*m1+ap[j]*bp[0]
	mov	$lo0,$hi0
	adc	\$0,%rdx
	mov	$hi1,-16(%rsp,$j,8)	# tp[j-1]
	mov	%rdx,$hi1

.L1st_enter:
	mulq	$m0			# ap[j]*bp[0]
	add	%rax,$hi0
	mov	($np,$j,8),%rax
	adc	\$0,%rdx
	lea	1($j),$j		# j++
	mov	%rdx,$lo0

	mulq	$m1			# np[j]*m1
	cmp	$num,$j
	jne	.L1st

	add	%rax,$hi1
	mov	($ap),%rax		# ap[0]
	adc	\$0,%rdx
	add	$hi0,$hi1		# np[j]*m1+ap[j]*bp[0]
	adc	\$0,%rdx
	mov	$hi1,-16(%rsp,$j,8)	# tp[j-1]
	mov	%rdx,$hi1
	mov	$lo0,$hi0

	xor	%rdx,%rdx
	add	$hi0,$hi1
	adc	\$0,%rdx
	mov	$hi1,-8(%rsp,$num,8)
	mov	%rdx,(%rsp,$num,8)	# store upmost overflow bit

	lea	1($i),$i		# i++
	jmp	.Louter
.align	16
.Louter:
	mov	($bp,$i,8),$m0		# m0=bp[i]
	xor	$j,$j			# j=0
	mov	$n0,$m1
	mov	(%rsp),$lo0
	mulq	$m0			# ap[0]*bp[i]
	add	%rax,$lo0		# ap[0]*bp[i]+tp[0]
	mov	($np),%rax
	adc	\$0,%rdx

	imulq	$lo0,$m1		# tp[0]*n0
	mov	%rdx,$hi0

	mulq	$m1			# np[0]*m1
	add	%rax,$lo0		# discarded
	mov	8($ap),%rax
	adc	\$0,%rdx
	mov	8(%rsp),$lo0		# tp[1]
	mov	%rdx,$hi1

	lea	1($j),$j		# j++
	jmp	.Linner_enter

.align	16
.Linner:
	add	%rax,$hi1
	mov	($ap,$j,8),%rax
	adc	\$0,%rdx
	add	$lo0,$hi1		# np[j]*m1+ap[j]*bp[i]+tp[j]
	mov	(%rsp,$j,8),$lo0
	adc	\$0,%rdx
	mov	$hi1,-16(%rsp,$j,8)	# tp[j-1]
	mov	%rdx,$hi1

.Linner_enter:
	mulq	$m0			# ap[j]*bp[i]
	add	%rax,$hi0
	mov	($np,$j,8),%rax
	adc	\$0,%rdx
	add	$hi0,$lo0		# ap[j]*bp[i]+tp[j]
	mov	%rdx,$hi0
	adc	\$0,$hi0
	lea	1($j),$j		# j++

	mulq	$m1			# np[j]*m1
	cmp	$num,$j
	jne	.Linner

	add	%rax,$hi1
	mov	($ap),%rax		# ap[0]
	adc	\$0,%rdx
	add	$lo0,$hi1		# np[j]*m1+ap[j]*bp[i]+tp[j]
	mov	(%rsp,$j,8),$lo0
	adc	\$0,%rdx
	mov	$hi1,-16(%rsp,$j,8)	# tp[j-1]
	mov	%rdx,$hi1

	xor	%rdx,%rdx
	add	$hi0,$hi1
	adc	\$0,%rdx
	add	$lo0,$hi1		# pull upmost overflow bit
	adc	\$0,%rdx
	mov	$hi1,-8(%rsp,$num,8)
	mov	%rdx,(%rsp,$num,8)	# store upmost overflow bit

	lea	1($i),$i		# i++
	cmp	$num,$i
	jb	.Louter

	xor	$i,$i			# i=0 and clear CF!
	mov	(%rsp),%rax		# tp[0]
	lea	(%rsp),$ap		# borrow ap for tp
	mov	$num,$j			# j=num
	jmp	.Lsub
.align	16
.Lsub:	sbb	($np,$i,8),%rax
	mov	%rax,($rp,$i,8)		# rp[i]=tp[i]-np[i]
	mov	8($ap,$i,8),%rax	# tp[i+1]
	lea	1($i),$i		# i++
	dec	$j			# doesnn't affect CF!
	jnz	.Lsub

	sbb	\$0,%rax		# handle upmost overflow bit
	xor	$i,$i
	and	%rax,$ap
	not	%rax
	mov	$rp,$np
	and	%rax,$np
	mov	$num,$j			# j=num
	or	$np,$ap			# ap=borrow?tp:rp
.align	16
.Lcopy:					# copy or in-place refresh
	mov	($ap,$i,8),%rax
	mov	$i,(%rsp,$i,8)		# zap temporary vector
	mov	%rax,($rp,$i,8)		# rp[i]=tp[i]
	lea	1($i),$i
	sub	\$1,$j
	jnz	.Lcopy

	mov	8(%rsp,$num,8),%rsi	# restore %rsp
	mov	\$1,%rax
	mov	(%rsi),%r15
	mov	8(%rsi),%r14
	mov	16(%rsi),%r13
	mov	24(%rsi),%r12
	mov	32(%rsi),%rbp
	mov	40(%rsi),%rbx
	lea	48(%rsi),%rsp
.Lmul_epilogue:
	ret
.size	bn_mul_mont,.-bn_mul_mont
___
{{{
my @A=("%r10","%r11");
my @N=("%r13","%rdi");
$code.=<<___;
.type	bn_mul4x_mont,\@function,6
.align	16
bn_mul4x_mont:
.Lmul4x_enter:
___
$code.=<<___ if ($addx);
	and	\$0x80100,%r11d
	cmp	\$0x80100,%r11d
	je	.Lmulx4x_enter
___
$code.=<<___;
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14
	push	%r15

	mov	${num}d,${num}d
	lea	4($num),%r10
	mov	%rsp,%r11
	neg	%r10
	lea	(%rsp,%r10,8),%rsp	# tp=alloca(8*(num+4))
	and	\$-1024,%rsp		# minimize TLB usage

	mov	%r11,8(%rsp,$num,8)	# tp[num+1]=%rsp
.Lmul4x_body:
	mov	$rp,16(%rsp,$num,8)	# tp[num+2]=$rp
	mov	%rdx,%r12		# reassign $bp
___
		$bp="%r12";
$code.=<<___;
	mov	($n0),$n0		# pull n0[0] value
	mov	($bp),$m0		# m0=bp[0]
	mov	($ap),%rax

	xor	$i,$i			# i=0
	xor	$j,$j			# j=0

	mov	$n0,$m1
	mulq	$m0			# ap[0]*bp[0]
	mov	%rax,$A[0]
	mov	($np),%rax

	imulq	$A[0],$m1		# "tp[0]"*n0
	mov	%rdx,$A[1]

	mulq	$m1			# np[0]*m1
	add	%rax,$A[0]		# discarded
	mov	8($ap),%rax
	adc	\$0,%rdx
	mov	%rdx,$N[1]

	mulq	$m0
	add	%rax,$A[1]
	mov	8($np),%rax
	adc	\$0,%rdx
	mov	%rdx,$A[0]

	mulq	$m1
	add	%rax,$N[1]
	mov	16($ap),%rax
	adc	\$0,%rdx
	add	$A[1],$N[1]
	lea	4($j),$j		# j++
	adc	\$0,%rdx
	mov	$N[1],(%rsp)
	mov	%rdx,$N[0]
	jmp	.L1st4x
.align	16
.L1st4x:
	mulq	$m0			# ap[j]*bp[0]
	add	%rax,$A[0]
	mov	-16($np,$j,8),%rax
	adc	\$0,%rdx
	mov	%rdx,$A[1]

	mulq	$m1			# np[j]*m1
	add	%rax,$N[0]
	mov	-8($ap,$j,8),%rax
	adc	\$0,%rdx
	add	$A[0],$N[0]		# np[j]*m1+ap[j]*bp[0]
	adc	\$0,%rdx
	mov	$N[0],-24(%rsp,$j,8)	# tp[j-1]
	mov	%rdx,$N[1]

	mulq	$m0			# ap[j]*bp[0]
	add	%rax,$A[1]
	mov	-8($np,$j,8),%rax
	adc	\$0,%rdx
	mov	%rdx,$A[0]

	mulq	$m1			# np[j]*m1
	add	%rax,$N[1]
	mov	($ap,$j,8),%rax
	adc	\$0,%rdx
	add	$A[1],$N[1]		# np[j]*m1+ap[j]*bp[0]
	adc	\$0,%rdx
	mov	$N[1],-16(%rsp,$j,8)	# tp[j-1]
	mov	%rdx,$N[0]

	mulq	$m0			# ap[j]*bp[0]
	add	%rax,$A[0]
	mov	($np,$j,8),%rax
	adc	\$0,%rdx
	mov	%rdx,$A[1]

	mulq	$m1			# np[j]*m1
	add	%rax,$N[0]
	mov	8($ap,$j,8),%rax
	adc	\$0,%rdx
	add	$A[0],$N[0]		# np[j]*m1+ap[j]*bp[0]
	adc	\$0,%rdx
	mov	$N[0],-8(%rsp,$j,8)	# tp[j-1]
	mov	%rdx,$N[1]

	mulq	$m0			# ap[j]*bp[0]
	add	%rax,$A[1]
	mov	8($np,$j,8),%rax
	adc	\$0,%rdx
	lea	4($j),$j		# j++
	mov	%rdx,$A[0]

	mulq	$m1			# np[j]*m1
	add	%rax,$N[1]
	mov	-16($ap,$j,8),%rax
	adc	\$0,%rdx
	add	$A[1],$N[1]		# np[j]*m1+ap[j]*bp[0]
	adc	\$0,%rdx
	mov	$N[1],-32(%rsp,$j,8)	# tp[j-1]
	mov	%rdx,$N[0]
	cmp	$num,$j
	jb	.L1st4x

	mulq	$m0			# ap[j]*bp[0]
	add	%rax,$A[0]
	mov	-16($np,$j,8),%rax
	adc	\$0,%rdx
	mov	%rdx,$A[1]

	mulq	$m1			# np[j]*m1
	add	%rax,$N[0]
	mov	-8($ap,$j,8),%rax
	adc	\$0,%rdx
	add	$A[0],$N[0]		# np[j]*m1+ap[j]*bp[0]
	adc	\$0,%rdx
	mov	$N[0],-24(%rsp,$j,8)	# tp[j-1]
	mov	%rdx,$N[1]

	mulq	$m0			# ap[j]*bp[0]
	add	%rax,$A[1]
	mov	-8($np,$j,8),%rax
	adc	\$0,%rdx
	mov	%rdx,$A[0]

	mulq	$m1			# np[j]*m1
	add	%rax,$N[1]
	mov	($ap),%rax		# ap[0]
	adc	\$0,%rdx
	add	$A[1],$N[1]		# np[j]*m1+ap[j]*bp[0]
	adc	\$0,%rdx
	mov	$N[1],-16(%rsp,$j,8)	# tp[j-1]
	mov	%rdx,$N[0]

	xor	$N[1],$N[1]
	add	$A[0],$N[0]
	adc	\$0,$N[1]
	mov	$N[0],-8(%rsp,$j,8)
	mov	$N[1],(%rsp,$j,8)	# store upmost overflow bit

	lea	1($i),$i		# i++
.align	4
.Louter4x:
	mov	($bp,$i,8),$m0		# m0=bp[i]
	xor	$j,$j			# j=0
	mov	(%rsp),$A[0]
	mov	$n0,$m1
	mulq	$m0			# ap[0]*bp[i]
	add	%rax,$A[0]		# ap[0]*bp[i]+tp[0]
	mov	($np),%rax
	adc	\$0,%rdx

	imulq	$A[0],$m1		# tp[0]*n0
	mov	%rdx,$A[1]

	mulq	$m1			# np[0]*m1
	add	%rax,$A[0]		# "$N[0]", discarded
	mov	8($ap),%rax
	adc	\$0,%rdx
	mov	%rdx,$N[1]

	mulq	$m0			# ap[j]*bp[i]
	add	%rax,$A[1]
	mov	8($np),%rax
	adc	\$0,%rdx
	add	8(%rsp),$A[1]		# +tp[1]
	adc	\$0,%rdx
	mov	%rdx,$A[0]

	mulq	$m1			# np[j]*m1
	add	%rax,$N[1]
	mov	16($ap),%rax
	adc	\$0,%rdx
	add	$A[1],$N[1]		# np[j]*m1+ap[j]*bp[i]+tp[j]
	lea	4($j),$j		# j+=2
	adc	\$0,%rdx
	mov	$N[1],(%rsp)		# tp[j-1]
	mov	%rdx,$N[0]
	jmp	.Linner4x
.align	16
.Linner4x:
	mulq	$m0			# ap[j]*bp[i]
	add	%rax,$A[0]
	mov	-16($np,$j,8),%rax
	adc	\$0,%rdx
	add	-16(%rsp,$j,8),$A[0]	# ap[j]*bp[i]+tp[j]
	adc	\$0,%rdx
	mov	%rdx,$A[1]

	mulq	$m1			# np[j]*m1
	add	%rax,$N[0]
	mov	-8($ap,$j,8),%rax
	adc	\$0,%rdx
	add	$A[0],$N[0]
	adc	\$0,%rdx
	mov	$N[0],-24(%rsp,$j,8)	# tp[j-1]
	mov	%rdx,$N[1]

	mulq	$m0			# ap[j]*bp[i]
	add	%rax,$A[1]
	mov	-8($np,$j,8),%rax
	adc	\$0,%rdx
	add	-8(%rsp,$j,8),$A[1]
	adc	\$0,%rdx
	mov	%rdx,$A[0]

	mulq	$m1			# np[j]*m1
	add	%rax,$N[1]
	mov	($ap,$j,8),%rax
	adc	\$0,%rdx
	add	$A[1],$N[1]
	adc	\$0,%rdx
	mov	$N[1],-16(%rsp,$j,8)	# tp[j-1]
	mov	%rdx,$N[0]

	mulq	$m0			# ap[j]*bp[i]
	add	%rax,$A[0]
	mov	($np,$j,8),%rax
	adc	\$0,%rdx
	add	(%rsp,$j,8),$A[0]	# ap[j]*bp[i]+tp[j]
	adc	\$0,%rdx
	mov	%rdx,$A[1]

	mulq	$m1			# np[j]*m1
	add	%rax,$N[0]
	mov	8($ap,$j,8),%rax
	adc	\$0,%rdx
	add	$A[0],$N[0]
	adc	\$0,%rdx
	mov	$N[0],-8(%rsp,$j,8)	# tp[j-1]
	mov	%rdx,$N[1]

	mulq	$m0			# ap[j]*bp[i]
	add	%rax,$A[1]
	mov	8($np,$j,8),%rax
	adc	\$0,%rdx
	add	8(%rsp,$j,8),$A[1]
	adc	\$0,%rdx
	lea	4($j),$j		# j++
	mov	%rdx,$A[0]

	mulq	$m1			# np[j]*m1
	add	%rax,$N[1]
	mov	-16($ap,$j,8),%rax
	adc	\$0,%rdx
	add	$A[1],$N[1]
	adc	\$0,%rdx
	mov	$N[1],-32(%rsp,$j,8)	# tp[j-1]
	mov	%rdx,$N[0]
	cmp	$num,$j
	jb	.Linner4x

	mulq	$m0			# ap[j]*bp[i]
	add	%rax,$A[0]
	mov	-16($np,$j,8),%rax
	adc	\$0,%rdx
	add	-16(%rsp,$j,8),$A[0]	# ap[j]*bp[i]+tp[j]
	adc	\$0,%rdx
	mov	%rdx,$A[1]

	mulq	$m1			# np[j]*m1
	add	%rax,$N[0]
	mov	-8($ap,$j,8),%rax
	adc	\$0,%rdx
	add	$A[0],$N[0]
	adc	\$0,%rdx
	mov	$N[0],-24(%rsp,$j,8)	# tp[j-1]
	mov	%rdx,$N[1]

	mulq	$m0			# ap[j]*bp[i]
	add	%rax,$A[1]
	mov	-8($np,$j,8),%rax
	adc	\$0,%rdx
	add	-8(%rsp,$j,8),$A[1]
	adc	\$0,%rdx
	lea	1($i),$i		# i++
	mov	%rdx,$A[0]

	mulq	$m1			# np[j]*m1
	add	%rax,$N[1]
	mov	($ap),%rax		# ap[0]
	adc	\$0,%rdx
	add	$A[1],$N[1]
	adc	\$0,%rdx
	mov	$N[1],-16(%rsp,$j,8)	# tp[j-1]
	mov	%rdx,$N[0]

	xor	$N[1],$N[1]
	add	$A[0],$N[0]
	adc	\$0,$N[1]
	add	(%rsp,$num,8),$N[0]	# pull upmost overflow bit
	adc	\$0,$N[1]
	mov	$N[0],-8(%rsp,$j,8)
	mov	$N[1],(%rsp,$j,8)	# store upmost overflow bit

	cmp	$num,$i
	jb	.Louter4x
___
{
my @ri=("%rax","%rdx",$m0,$m1);
$code.=<<___;
	mov	16(%rsp,$num,8),$rp	# restore $rp
	mov	0(%rsp),@ri[0]		# tp[0]
	pxor	%xmm0,%xmm0
	mov	8(%rsp),@ri[1]		# tp[1]
	shr	\$2,$num		# num/=4
	lea	(%rsp),$ap		# borrow ap for tp
	xor	$i,$i			# i=0 and clear CF!

	sub	0($np),@ri[0]
	mov	16($ap),@ri[2]		# tp[2]
	mov	24($ap),@ri[3]		# tp[3]
	sbb	8($np),@ri[1]
	lea	-1($num),$j		# j=num/4-1
	jmp	.Lsub4x
.align	16
.Lsub4x:
	mov	@ri[0],0($rp,$i,8)	# rp[i]=tp[i]-np[i]
	mov	@ri[1],8($rp,$i,8)	# rp[i]=tp[i]-np[i]
	sbb	16($np,$i,8),@ri[2]
	mov	32($ap,$i,8),@ri[0]	# tp[i+1]
	mov	40($ap,$i,8),@ri[1]
	sbb	24($np,$i,8),@ri[3]
	mov	@ri[2],16($rp,$i,8)	# rp[i]=tp[i]-np[i]
	mov	@ri[3],24($rp,$i,8)	# rp[i]=tp[i]-np[i]
	sbb	32($np,$i,8),@ri[0]
	mov	48($ap,$i,8),@ri[2]
	mov	56($ap,$i,8),@ri[3]
	sbb	40($np,$i,8),@ri[1]
	lea	4($i),$i		# i++
	dec	$j			# doesnn't affect CF!
	jnz	.Lsub4x

	mov	@ri[0],0($rp,$i,8)	# rp[i]=tp[i]-np[i]
	mov	32($ap,$i,8),@ri[0]	# load overflow bit
	sbb	16($np,$i,8),@ri[2]
	mov	@ri[1],8($rp,$i,8)	# rp[i]=tp[i]-np[i]
	sbb	24($np,$i,8),@ri[3]
	mov	@ri[2],16($rp,$i,8)	# rp[i]=tp[i]-np[i]

	sbb	\$0,@ri[0]		# handle upmost overflow bit
	mov	@ri[3],24($rp,$i,8)	# rp[i]=tp[i]-np[i]
	xor	$i,$i			# i=0
	and	@ri[0],$ap
	not	@ri[0]
	mov	$rp,$np
	and	@ri[0],$np
	lea	-1($num),$j
	or	$np,$ap			# ap=borrow?tp:rp

	movdqu	($ap),%xmm1
	movdqa	%xmm0,(%rsp)
	movdqu	%xmm1,($rp)
	jmp	.Lcopy4x
.align	16
.Lcopy4x:					# copy or in-place refresh
	movdqu	16($ap,$i),%xmm2
	movdqu	32($ap,$i),%xmm1
	movdqa	%xmm0,16(%rsp,$i)
	movdqu	%xmm2,16($rp,$i)
	movdqa	%xmm0,32(%rsp,$i)
	movdqu	%xmm1,32($rp,$i)
	lea	32($i),$i
	dec	$j
	jnz	.Lcopy4x

	shl	\$2,$num
	movdqu	16($ap,$i),%xmm2
	movdqa	%xmm0,16(%rsp,$i)
	movdqu	%xmm2,16($rp,$i)
___
}
$code.=<<___;
	mov	8(%rsp,$num,8),%rsi	# restore %rsp
	mov	\$1,%rax
	mov	(%rsi),%r15
	mov	8(%rsi),%r14
	mov	16(%rsi),%r13
	mov	24(%rsi),%r12
	mov	32(%rsi),%rbp
	mov	40(%rsi),%rbx
	lea	48(%rsi),%rsp
.Lmul4x_epilogue:
	ret
.size	bn_mul4x_mont,.-bn_mul4x_mont
___
}}}
{{{
######################################################################
# void bn_sqr8x_mont(
my $rptr="%rdi";	# const BN_ULONG *rptr,
my $aptr="%rsi";	# const BN_ULONG *aptr,
my $bptr="%rdx";	# not used
my $nptr="%rcx";	# const BN_ULONG *nptr,
my $n0  ="%r8";		# const BN_ULONG *n0);
my $num ="%r9";		# int num, has to be divisible by 8

my ($i,$j,$tptr)=("%rbp","%rcx",$rptr);
my @A0=("%r10","%r11");
my @A1=("%r12","%r13");
my ($a0,$a1,$ai)=("%r14","%r15","%rbx");

$code.=<<___	if ($addx);
.extern	bn_sqrx8x_internal		# see x86_64-mont5 module
___
$code.=<<___;
.extern	bn_sqr8x_internal		# see x86_64-mont5 module

.type	bn_sqr8x_mont,\@function,6
.align	32
bn_sqr8x_mont:
.Lsqr8x_enter:
	mov	%rsp,%rax
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14
	push	%r15

	mov	${num}d,%r10d
	shl	\$3,${num}d		# convert $num to bytes
	shl	\$3+2,%r10		# 4*$num
	neg	$num

	##############################################################
	# ensure that stack frame doesn't alias with $aptr modulo
	# 4096. this is done to allow memory disambiguation logic
	# do its job.
	#
	lea	-64(%rsp,$num,4),%r11
	mov	($n0),$n0		# *n0
	sub	$aptr,%r11
	and	\$4095,%r11
	cmp	%r11,%r10
	jb	.Lsqr8x_sp_alt
	sub	%r11,%rsp		# align with $aptr
	lea	-64(%rsp,$num,4),%rsp	# alloca(frame+4*$num)
	jmp	.Lsqr8x_sp_done

.align	32
.Lsqr8x_sp_alt:
	lea	4096-64(,$num,4),%r10	# 4096-frame-4*$num
	lea	-64(%rsp,$num,4),%rsp	# alloca(frame+4*$num)
	sub	%r10,%r11
	mov	\$0,%r10
	cmovc	%r10,%r11
	sub	%r11,%rsp
.Lsqr8x_sp_done:
	and	\$-64,%rsp
	mov	$num,%r10	
	neg	$num

	lea	64(%rsp,$num,2),%r11	# copy of modulus
	mov	$n0,  32(%rsp)
	mov	%rax, 40(%rsp)		# save original %rsp
.Lsqr8x_body:

	mov	$num,$i
	movq	%r11, %xmm2		# save pointer to modulus copy
	shr	\$3+2,$i
	mov	OPENSSL_ia32cap_P+8(%rip),%eax
	jmp	.Lsqr8x_copy_n

.align	32
.Lsqr8x_copy_n:
	movq	8*0($nptr),%xmm0
	movq	8*1($nptr),%xmm1
	movq	8*2($nptr),%xmm3
	movq	8*3($nptr),%xmm4
	lea	8*4($nptr),$nptr
	movdqa	%xmm0,16*0(%r11)
	movdqa	%xmm1,16*1(%r11)
	movdqa	%xmm3,16*2(%r11)
	movdqa	%xmm4,16*3(%r11)
	lea	16*4(%r11),%r11
	dec	$i
	jnz	.Lsqr8x_copy_n

	pxor	%xmm0,%xmm0
	movq	$rptr,%xmm1		# save $rptr
	movq	%r10, %xmm3		# -$num
___
$code.=<<___ if ($addx);
	and	\$0x80100,%eax
	cmp	\$0x80100,%eax
	jne	.Lsqr8x_nox

	call	bn_sqrx8x_internal	# see x86_64-mont5 module

	pxor	%xmm0,%xmm0
	lea	48(%rsp),%rax
	lea	64(%rsp,$num,2),%rdx
	shr	\$3+2,$num
	mov	40(%rsp),%rsi		# restore %rsp
	jmp	.Lsqr8x_zero

.align	32
.Lsqr8x_nox:
___
$code.=<<___;
	call	bn_sqr8x_internal	# see x86_64-mont5 module

	pxor	%xmm0,%xmm0
	lea	48(%rsp),%rax
	lea	64(%rsp,$num,2),%rdx
	shr	\$3+2,$num
	mov	40(%rsp),%rsi		# restore %rsp
	jmp	.Lsqr8x_zero

.align	32
.Lsqr8x_zero:
	movdqa	%xmm0,16*0(%rax)	# wipe t
	movdqa	%xmm0,16*1(%rax)
	movdqa	%xmm0,16*2(%rax)
	movdqa	%xmm0,16*3(%rax)
	lea	16*4(%rax),%rax
	movdqa	%xmm0,16*0(%rdx)	# wipe n
	movdqa	%xmm0,16*1(%rdx)
	movdqa	%xmm0,16*2(%rdx)
	movdqa	%xmm0,16*3(%rdx)
	lea	16*4(%rdx),%rdx
	dec	$num
	jnz	.Lsqr8x_zero

	mov	\$1,%rax
	mov	-48(%rsi),%r15
	mov	-40(%rsi),%r14
	mov	-32(%rsi),%r13
	mov	-24(%rsi),%r12
	mov	-16(%rsi),%rbp
	mov	-8(%rsi),%rbx
	lea	(%rsi),%rsp
.Lsqr8x_epilogue:
	ret
.size	bn_sqr8x_mont,.-bn_sqr8x_mont
___
}}}

if ($addx) {{{
my $bp="%rdx";	# original value

$code.=<<___;
.type	bn_mulx4x_mont,\@function,6
.align	32
bn_mulx4x_mont:
.Lmulx4x_enter:
	mov	%rsp,%rax
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14
	push	%r15

	shl	\$3,${num}d		# convert $num to bytes
	.byte	0x67
	xor	%r10,%r10
	sub	$num,%r10		# -$num
	mov	($n0),$n0		# *n0
	lea	-72(%rsp,%r10),%rsp	# alloca(frame+$num+8)
	lea	($bp,$num),%r10
	and	\$-128,%rsp
	##############################################################
	# Stack layout
	# +0	num
	# +8	off-loaded &b[i]
	# +16	end of b[num]
	# +24	saved n0
	# +32	saved rp
	# +40	saved %rsp
	# +48	inner counter
	# +56
	# +64	tmp[num+1]
	#
	mov	$num,0(%rsp)		# save $num
	shr	\$5,$num
	mov	%r10,16(%rsp)		# end of b[num]
	sub	\$1,$num
	mov	$n0, 24(%rsp)		# save *n0
	mov	$rp, 32(%rsp)		# save $rp
	mov	%rax,40(%rsp)		# save original %rsp
	mov	$num,48(%rsp)		# inner counter
	jmp	.Lmulx4x_body

.align	32
.Lmulx4x_body:
___
my ($aptr, $bptr, $nptr, $tptr, $mi,  $bi,  $zero, $num)=
   ("%rsi","%rdi","%rcx","%rbx","%r8","%r9","%rbp","%rax");
my $rptr=$bptr;
$code.=<<___;
	lea	8($bp),$bptr
	mov	($bp),%rdx		# b[0], $bp==%rdx actually
	lea	64+32(%rsp),$tptr
	mov	%rdx,$bi

	mulx	0*8($aptr),$mi,%rax	# a[0]*b[0]
	mulx	1*8($aptr),%r11,%r14	# a[1]*b[0]
	add	%rax,%r11
	mov	$bptr,8(%rsp)		# off-load &b[i]
	mulx	2*8($aptr),%r12,%r13	# ...
	adc	%r14,%r12
	adc	\$0,%r13

	mov	$mi,$bptr		# borrow $bptr
	imulq	24(%rsp),$mi		# "t[0]"*n0
	xor	$zero,$zero		# cf=0, of=0

	mulx	3*8($aptr),%rax,%r14
	 mov	$mi,%rdx
	lea	4*8($aptr),$aptr
	adcx	%rax,%r13
	adcx	$zero,%r14		# cf=0

	mulx	0*8($nptr),%rax,%r10
	adcx	%rax,$bptr		# discarded
	adox	%r11,%r10
	mulx	1*8($nptr),%rax,%r11
	adcx	%rax,%r10
	adox	%r12,%r11
	.byte	0xc4,0x62,0xfb,0xf6,0xa1,0x10,0x00,0x00,0x00	# mulx	2*8($nptr),%rax,%r12
	mov	48(%rsp),$bptr		# counter value
	mov	%r10,-4*8($tptr)
	adcx	%rax,%r11
	adox	%r13,%r12
	mulx	3*8($nptr),%rax,%r15
	 mov	$bi,%rdx
	mov	%r11,-3*8($tptr)
	adcx	%rax,%r12
	adox	$zero,%r15		# of=0
	lea	4*8($nptr),$nptr
	mov	%r12,-2*8($tptr)

	jmp	.Lmulx4x_1st

.align	32
.Lmulx4x_1st:
	adcx	$zero,%r15		# cf=0, modulo-scheduled
	mulx	0*8($aptr),%r10,%rax	# a[4]*b[0]
	adcx	%r14,%r10
	mulx	1*8($aptr),%r11,%r14	# a[5]*b[0]
	adcx	%rax,%r11
	mulx	2*8($aptr),%r12,%rax	# ...
	adcx	%r14,%r12
	mulx	3*8($aptr),%r13,%r14
	 .byte	0x67,0x67
	 mov	$mi,%rdx
	adcx	%rax,%r13
	adcx	$zero,%r14		# cf=0
	lea	4*8($aptr),$aptr
	lea	4*8($tptr),$tptr

	adox	%r15,%r10
	mulx	0*8($nptr),%rax,%r15
	adcx	%rax,%r10
	adox	%r15,%r11
	mulx	1*8($nptr),%rax,%r15
	adcx	%rax,%r11
	adox	%r15,%r12
	mulx	2*8($nptr),%rax,%r15
	mov	%r10,-5*8($tptr)
	adcx	%rax,%r12
	mov	%r11,-4*8($tptr)
	adox	%r15,%r13
	mulx	3*8($nptr),%rax,%r15
	 mov	$bi,%rdx
	mov	%r12,-3*8($tptr)
	adcx	%rax,%r13
	adox	$zero,%r15
	lea	4*8($nptr),$nptr
	mov	%r13,-2*8($tptr)

	dec	$bptr			# of=0, pass cf
	jnz	.Lmulx4x_1st

	mov	0(%rsp),$num		# load num
	mov	8(%rsp),$bptr		# re-load &b[i]
	adc	$zero,%r15		# modulo-scheduled
	add	%r15,%r14
	sbb	%r15,%r15		# top-most carry
	mov	%r14,-1*8($tptr)
	jmp	.Lmulx4x_outer

.align	32
.Lmulx4x_outer:
	mov	($bptr),%rdx		# b[i]
	lea	8($bptr),$bptr		# b++
	sub	$num,$aptr		# rewind $aptr
	mov	%r15,($tptr)		# save top-most carry
	lea	64+4*8(%rsp),$tptr
	sub	$num,$nptr		# rewind $nptr

	mulx	0*8($aptr),$mi,%r11	# a[0]*b[i]
	xor	%ebp,%ebp		# xor	$zero,$zero	# cf=0, of=0
	mov	%rdx,$bi
	mulx	1*8($aptr),%r14,%r12	# a[1]*b[i]
	adox	-4*8($tptr),$mi
	adcx	%r14,%r11
	mulx	2*8($aptr),%r15,%r13	# ...
	adox	-3*8($tptr),%r11
	adcx	%r15,%r12
	adox	$zero,%r12
	adcx	$zero,%r13

	mov	$bptr,8(%rsp)		# off-load &b[i]
	.byte	0x67
	mov	$mi,%r15
	imulq	24(%rsp),$mi		# "t[0]"*n0
	xor	%ebp,%ebp		# xor	$zero,$zero	# cf=0, of=0

	mulx	3*8($aptr),%rax,%r14
	 mov	$mi,%rdx
	adox	-2*8($tptr),%r12
	adcx	%rax,%r13
	adox	-1*8($tptr),%r13
	adcx	$zero,%r14
	lea	4*8($aptr),$aptr
	adox	$zero,%r14

	mulx	0*8($nptr),%rax,%r10
	adcx	%rax,%r15		# discarded
	adox	%r11,%r10
	mulx	1*8($nptr),%rax,%r11
	adcx	%rax,%r10
	adox	%r12,%r11
	mulx	2*8($nptr),%rax,%r12
	mov	%r10,-4*8($tptr)
	adcx	%rax,%r11
	adox	%r13,%r12
	mulx	3*8($nptr),%rax,%r15
	 mov	$bi,%rdx
	mov	%r11,-3*8($tptr)
	lea	4*8($nptr),$nptr
	adcx	%rax,%r12
	adox	$zero,%r15		# of=0
	mov	48(%rsp),$bptr		# counter value
	mov	%r12,-2*8($tptr)

	jmp	.Lmulx4x_inner

.align	32
.Lmulx4x_inner:
	mulx	0*8($aptr),%r10,%rax	# a[4]*b[i]
	adcx	$zero,%r15		# cf=0, modulo-scheduled
	adox	%r14,%r10
	mulx	1*8($aptr),%r11,%r14	# a[5]*b[i]
	adcx	0*8($tptr),%r10
	adox	%rax,%r11
	mulx	2*8($aptr),%r12,%rax	# ...
	adcx	1*8($tptr),%r11
	adox	%r14,%r12
	mulx	3*8($aptr),%r13,%r14
	 mov	$mi,%rdx
	adcx	2*8($tptr),%r12
	adox	%rax,%r13
	adcx	3*8($tptr),%r13
	adox	$zero,%r14		# of=0
	lea	4*8($aptr),$aptr
	lea	4*8($tptr),$tptr
	adcx	$zero,%r14		# cf=0

	adox	%r15,%r10
	mulx	0*8($nptr),%rax,%r15
	adcx	%rax,%r10
	adox	%r15,%r11
	mulx	1*8($nptr),%rax,%r15
	adcx	%rax,%r11
	adox	%r15,%r12
	mulx	2*8($nptr),%rax,%r15
	mov	%r10,-5*8($tptr)
	adcx	%rax,%r12
	adox	%r15,%r13
	mulx	3*8($nptr),%rax,%r15
	 mov	$bi,%rdx
	mov	%r11,-4*8($tptr)
	mov	%r12,-3*8($tptr)
	adcx	%rax,%r13
	adox	$zero,%r15
	lea	4*8($nptr),$nptr
	mov	%r13,-2*8($tptr)

	dec	$bptr			# of=0, pass cf
	jnz	.Lmulx4x_inner

	mov	0(%rsp),$num		# load num
	mov	8(%rsp),$bptr		# re-load &b[i]
	adc	$zero,%r15		# modulo-scheduled
	sub	0*8($tptr),$zero	# pull top-most carry
	adc	%r15,%r14
	mov	-8($nptr),$mi
	sbb	%r15,%r15		# top-most carry
	mov	%r14,-1*8($tptr)

	cmp	16(%rsp),$bptr
	jne	.Lmulx4x_outer

	sub	%r14,$mi		# compare top-most words
	sbb	$mi,$mi
	or	$mi,%r15

	neg	$num
	xor	%rdx,%rdx
	mov	32(%rsp),$rptr		# restore rp
	lea	64(%rsp),$tptr

	pxor	%xmm0,%xmm0
	mov	0*8($nptr,$num),%r8
	mov	1*8($nptr,$num),%r9
	neg	%r8
	jmp	.Lmulx4x_sub_entry

.align	32
.Lmulx4x_sub:
	mov	0*8($nptr,$num),%r8
	mov	1*8($nptr,$num),%r9
	not	%r8
.Lmulx4x_sub_entry:
	mov	2*8($nptr,$num),%r10
	not	%r9
	and	%r15,%r8
	mov	3*8($nptr,$num),%r11
	not	%r10
	and	%r15,%r9
	not	%r11
	and	%r15,%r10
	and	%r15,%r11

	neg	%rdx			# mov %rdx,%cf
	adc	0*8($tptr),%r8
	adc	1*8($tptr),%r9
	movdqa	%xmm0,($tptr)
	adc	2*8($tptr),%r10
	adc	3*8($tptr),%r11
	movdqa	%xmm0,16($tptr)
	lea	4*8($tptr),$tptr
	sbb	%rdx,%rdx		# mov %cf,%rdx

	mov	%r8,0*8($rptr)
	mov	%r9,1*8($rptr)
	mov	%r10,2*8($rptr)
	mov	%r11,3*8($rptr)
	lea	4*8($rptr),$rptr

	add	\$32,$num
	jnz	.Lmulx4x_sub

	mov	40(%rsp),%rsi		# restore %rsp
	mov	\$1,%rax
	mov	-48(%rsi),%r15
	mov	-40(%rsi),%r14
	mov	-32(%rsi),%r13
	mov	-24(%rsi),%r12
	mov	-16(%rsi),%rbp
	mov	-8(%rsi),%rbx
	lea	(%rsi),%rsp
.Lmulx4x_epilogue:
	ret
.size	bn_mulx4x_mont,.-bn_mulx4x_mont
___
}}}
$code.=<<___;
.asciz	"Montgomery Multiplication for x86_64, CRYPTOGAMS by <appro\@openssl.org>"
.align	16
___

# EXCEPTION_DISPOSITION handler (EXCEPTION_RECORD *rec,ULONG64 frame,
#		CONTEXT *context,DISPATCHER_CONTEXT *disp)
if ($win64) {
$rec="%rcx";
$frame="%rdx";
$context="%r8";
$disp="%r9";

$code.=<<___;
.extern	__imp_RtlVirtualUnwind
.type	mul_handler,\@abi-omnipotent
.align	16
mul_handler:
	push	%rsi
	push	%rdi
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	pushfq
	sub	\$64,%rsp

	mov	120($context),%rax	# pull context->Rax
	mov	248($context),%rbx	# pull context->Rip

	mov	8($disp),%rsi		# disp->ImageBase
	mov	56($disp),%r11		# disp->HandlerData

	mov	0(%r11),%r10d		# HandlerData[0]
	lea	(%rsi,%r10),%r10	# end of prologue label
	cmp	%r10,%rbx		# context->Rip<end of prologue label
	jb	.Lcommon_seh_tail

	mov	152($context),%rax	# pull context->Rsp

	mov	4(%r11),%r10d		# HandlerData[1]
	lea	(%rsi,%r10),%r10	# epilogue label
	cmp	%r10,%rbx		# context->Rip>=epilogue label
	jae	.Lcommon_seh_tail

	mov	192($context),%r10	# pull $num
	mov	8(%rax,%r10,8),%rax	# pull saved stack pointer
	lea	48(%rax),%rax

	mov	-8(%rax),%rbx
	mov	-16(%rax),%rbp
	mov	-24(%rax),%r12
	mov	-32(%rax),%r13
	mov	-40(%rax),%r14
	mov	-48(%rax),%r15
	mov	%rbx,144($context)	# restore context->Rbx
	mov	%rbp,160($context)	# restore context->Rbp
	mov	%r12,216($context)	# restore context->R12
	mov	%r13,224($context)	# restore context->R13
	mov	%r14,232($context)	# restore context->R14
	mov	%r15,240($context)	# restore context->R15

	jmp	.Lcommon_seh_tail
.size	mul_handler,.-mul_handler

.type	sqr_handler,\@abi-omnipotent
.align	16
sqr_handler:
	push	%rsi
	push	%rdi
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	pushfq
	sub	\$64,%rsp

	mov	120($context),%rax	# pull context->Rax
	mov	248($context),%rbx	# pull context->Rip

	mov	8($disp),%rsi		# disp->ImageBase
	mov	56($disp),%r11		# disp->HandlerData

	mov	0(%r11),%r10d		# HandlerData[0]
	lea	(%rsi,%r10),%r10	# end of prologue label
	cmp	%r10,%rbx		# context->Rip<.Lsqr_body
	jb	.Lcommon_seh_tail

	mov	152($context),%rax	# pull context->Rsp

	mov	4(%r11),%r10d		# HandlerData[1]
	lea	(%rsi,%r10),%r10	# epilogue label
	cmp	%r10,%rbx		# context->Rip>=.Lsqr_epilogue
	jae	.Lcommon_seh_tail

	mov	40(%rax),%rax		# pull saved stack pointer

	mov	-8(%rax),%rbx
	mov	-16(%rax),%rbp
	mov	-24(%rax),%r12
	mov	-32(%rax),%r13
	mov	-40(%rax),%r14
	mov	-48(%rax),%r15
	mov	%rbx,144($context)	# restore context->Rbx
	mov	%rbp,160($context)	# restore context->Rbp
	mov	%r12,216($context)	# restore context->R12
	mov	%r13,224($context)	# restore context->R13
	mov	%r14,232($context)	# restore context->R14
	mov	%r15,240($context)	# restore context->R15

.Lcommon_seh_tail:
	mov	8(%rax),%rdi
	mov	16(%rax),%rsi
	mov	%rax,152($context)	# restore context->Rsp
	mov	%rsi,168($context)	# restore context->Rsi
	mov	%rdi,176($context)	# restore context->Rdi

	mov	40($disp),%rdi		# disp->ContextRecord
	mov	$context,%rsi		# context
	mov	\$154,%ecx		# sizeof(CONTEXT)
	.long	0xa548f3fc		# cld; rep movsq

	mov	$disp,%rsi
	xor	%rcx,%rcx		# arg1, UNW_FLAG_NHANDLER
	mov	8(%rsi),%rdx		# arg2, disp->ImageBase
	mov	0(%rsi),%r8		# arg3, disp->ControlPc
	mov	16(%rsi),%r9		# arg4, disp->FunctionEntry
	mov	40(%rsi),%r10		# disp->ContextRecord
	lea	56(%rsi),%r11		# &disp->HandlerData
	lea	24(%rsi),%r12		# &disp->EstablisherFrame
	mov	%r10,32(%rsp)		# arg5
	mov	%r11,40(%rsp)		# arg6
	mov	%r12,48(%rsp)		# arg7
	mov	%rcx,56(%rsp)		# arg8, (NULL)
	call	*__imp_RtlVirtualUnwind(%rip)

	mov	\$1,%eax		# ExceptionContinueSearch
	add	\$64,%rsp
	popfq
	pop	%r15
	pop	%r14
	pop	%r13
	pop	%r12
	pop	%rbp
	pop	%rbx
	pop	%rdi
	pop	%rsi
	ret
.size	sqr_handler,.-sqr_handler

.section	.pdata
.align	4
	.rva	.LSEH_begin_bn_mul_mont
	.rva	.LSEH_end_bn_mul_mont
	.rva	.LSEH_info_bn_mul_mont

	.rva	.LSEH_begin_bn_mul4x_mont
	.rva	.LSEH_end_bn_mul4x_mont
	.rva	.LSEH_info_bn_mul4x_mont

	.rva	.LSEH_begin_bn_sqr8x_mont
	.rva	.LSEH_end_bn_sqr8x_mont
	.rva	.LSEH_info_bn_sqr8x_mont
___
$code.=<<___ if ($addx);
	.rva	.LSEH_begin_bn_mulx4x_mont
	.rva	.LSEH_end_bn_mulx4x_mont
	.rva	.LSEH_info_bn_mulx4x_mont
___
$code.=<<___;
.section	.xdata
.align	8
.LSEH_info_bn_mul_mont:
	.byte	9,0,0,0
	.rva	mul_handler
	.rva	.Lmul_body,.Lmul_epilogue	# HandlerData[]
.LSEH_info_bn_mul4x_mont:
	.byte	9,0,0,0
	.rva	mul_handler
	.rva	.Lmul4x_body,.Lmul4x_epilogue	# HandlerData[]
.LSEH_info_bn_sqr8x_mont:
	.byte	9,0,0,0
	.rva	sqr_handler
	.rva	.Lsqr8x_body,.Lsqr8x_epilogue	# HandlerData[]
___
$code.=<<___ if ($addx);
.LSEH_info_bn_mulx4x_mont:
	.byte	9,0,0,0
	.rva	sqr_handler
	.rva	.Lmulx4x_body,.Lmulx4x_epilogue	# HandlerData[]
___
}

print $code;
close STDOUT;
