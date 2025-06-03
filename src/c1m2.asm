
c1m2.out:     file format elf64-x86-64


Disassembly of section .init:

00000000000004f0 <_init>:
 4f0:	48 83 ec 08          	sub    $0x8,%rsp
 4f4:	48 8b 05 ed 0a 20 00 	mov    0x200aed(%rip),%rax        # 200fe8 <__gmon_start__>
 4fb:	48 85 c0             	test   %rax,%rax
 4fe:	74 02                	je     502 <_init+0x12>
 500:	ff d0                	callq  *%rax
 502:	48 83 c4 08          	add    $0x8,%rsp
 506:	c3                   	retq   

Disassembly of section .plt:

0000000000000510 <.plt>:
 510:	ff 35 aa 0a 20 00    	pushq  0x200aaa(%rip)        # 200fc0 <_GLOBAL_OFFSET_TABLE_+0x8>
 516:	ff 25 ac 0a 20 00    	jmpq   *0x200aac(%rip)        # 200fc8 <_GLOBAL_OFFSET_TABLE_+0x10>
 51c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000000520 <putchar@plt>:
 520:	ff 25 aa 0a 20 00    	jmpq   *0x200aaa(%rip)        # 200fd0 <putchar@GLIBC_2.2.5>
 526:	68 00 00 00 00       	pushq  $0x0
 52b:	e9 e0 ff ff ff       	jmpq   510 <.plt>

Disassembly of section .plt.got:

0000000000000530 <__cxa_finalize@plt>:
 530:	ff 25 c2 0a 20 00    	jmpq   *0x200ac2(%rip)        # 200ff8 <__cxa_finalize@GLIBC_2.2.5>
 536:	66 90                	xchg   %ax,%ax

Disassembly of section .text:

0000000000000540 <_start>:
 540:	31 ed                	xor    %ebp,%ebp
 542:	49 89 d1             	mov    %rdx,%r9
 545:	5e                   	pop    %rsi
 546:	48 89 e2             	mov    %rsp,%rdx
 549:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
 54d:	50                   	push   %rax
 54e:	54                   	push   %rsp
 54f:	4c 8d 05 8a 03 00 00 	lea    0x38a(%rip),%r8        # 8e0 <__libc_csu_fini>
 556:	48 8d 0d 13 03 00 00 	lea    0x313(%rip),%rcx        # 870 <__libc_csu_init>
 55d:	48 8d 3d e6 00 00 00 	lea    0xe6(%rip),%rdi        # 64a <main>
 564:	ff 15 76 0a 20 00    	callq  *0x200a76(%rip)        # 200fe0 <__libc_start_main@GLIBC_2.2.5>
 56a:	f4                   	hlt    
 56b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000000570 <deregister_tm_clones>:
 570:	48 8d 3d 99 0a 20 00 	lea    0x200a99(%rip),%rdi        # 201010 <__TMC_END__>
 577:	55                   	push   %rbp
 578:	48 8d 05 91 0a 20 00 	lea    0x200a91(%rip),%rax        # 201010 <__TMC_END__>
 57f:	48 39 f8             	cmp    %rdi,%rax
 582:	48 89 e5             	mov    %rsp,%rbp
 585:	74 19                	je     5a0 <deregister_tm_clones+0x30>
 587:	48 8b 05 4a 0a 20 00 	mov    0x200a4a(%rip),%rax        # 200fd8 <_ITM_deregisterTMCloneTable>
 58e:	48 85 c0             	test   %rax,%rax
 591:	74 0d                	je     5a0 <deregister_tm_clones+0x30>
 593:	5d                   	pop    %rbp
 594:	ff e0                	jmpq   *%rax
 596:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
 59d:	00 00 00 
 5a0:	5d                   	pop    %rbp
 5a1:	c3                   	retq   
 5a2:	0f 1f 40 00          	nopl   0x0(%rax)
 5a6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
 5ad:	00 00 00 

00000000000005b0 <register_tm_clones>:
 5b0:	48 8d 3d 59 0a 20 00 	lea    0x200a59(%rip),%rdi        # 201010 <__TMC_END__>
 5b7:	48 8d 35 52 0a 20 00 	lea    0x200a52(%rip),%rsi        # 201010 <__TMC_END__>
 5be:	55                   	push   %rbp
 5bf:	48 29 fe             	sub    %rdi,%rsi
 5c2:	48 89 e5             	mov    %rsp,%rbp
 5c5:	48 c1 fe 03          	sar    $0x3,%rsi
 5c9:	48 89 f0             	mov    %rsi,%rax
 5cc:	48 c1 e8 3f          	shr    $0x3f,%rax
 5d0:	48 01 c6             	add    %rax,%rsi
 5d3:	48 d1 fe             	sar    %rsi
 5d6:	74 18                	je     5f0 <register_tm_clones+0x40>
 5d8:	48 8b 05 11 0a 20 00 	mov    0x200a11(%rip),%rax        # 200ff0 <_ITM_registerTMCloneTable>
 5df:	48 85 c0             	test   %rax,%rax
 5e2:	74 0c                	je     5f0 <register_tm_clones+0x40>
 5e4:	5d                   	pop    %rbp
 5e5:	ff e0                	jmpq   *%rax
 5e7:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
 5ee:	00 00 
 5f0:	5d                   	pop    %rbp
 5f1:	c3                   	retq   
 5f2:	0f 1f 40 00          	nopl   0x0(%rax)
 5f6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
 5fd:	00 00 00 

0000000000000600 <__do_global_dtors_aux>:
 600:	80 3d 09 0a 20 00 00 	cmpb   $0x0,0x200a09(%rip)        # 201010 <__TMC_END__>
 607:	75 2f                	jne    638 <__do_global_dtors_aux+0x38>
 609:	48 83 3d e7 09 20 00 	cmpq   $0x0,0x2009e7(%rip)        # 200ff8 <__cxa_finalize@GLIBC_2.2.5>
 610:	00 
 611:	55                   	push   %rbp
 612:	48 89 e5             	mov    %rsp,%rbp
 615:	74 0c                	je     623 <__do_global_dtors_aux+0x23>
 617:	48 8b 3d ea 09 20 00 	mov    0x2009ea(%rip),%rdi        # 201008 <__dso_handle>
 61e:	e8 0d ff ff ff       	callq  530 <__cxa_finalize@plt>
 623:	e8 48 ff ff ff       	callq  570 <deregister_tm_clones>
 628:	c6 05 e1 09 20 00 01 	movb   $0x1,0x2009e1(%rip)        # 201010 <__TMC_END__>
 62f:	5d                   	pop    %rbp
 630:	c3                   	retq   
 631:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
 638:	f3 c3                	repz retq 
 63a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

0000000000000640 <frame_dummy>:
 640:	55                   	push   %rbp
 641:	48 89 e5             	mov    %rsp,%rbp
 644:	5d                   	pop    %rbp
 645:	e9 66 ff ff ff       	jmpq   5b0 <register_tm_clones>

000000000000064a <main>:
 64a:	55                   	push   %rbp
 64b:	48 89 e5             	mov    %rsp,%rbp
 64e:	48 83 ec 10          	sub    $0x10,%rsp
 652:	be 0a 00 00 00       	mov    $0xa,%esi
 657:	48 8d 3d ba 09 20 00 	lea    0x2009ba(%rip),%rdi        # 201018 <buffer>
 65e:	e8 e1 01 00 00       	callq  844 <clear_all>
 663:	48 8d 05 b6 09 20 00 	lea    0x2009b6(%rip),%rax        # 201020 <buffer+0x8>
 66a:	ba 02 00 00 00       	mov    $0x2,%edx
 66f:	be 2b 00 00 00       	mov    $0x2b,%esi
 674:	48 89 c7             	mov    %rax,%rdi
 677:	e8 87 01 00 00       	callq  803 <set_all>
 67c:	ba 61 00 00 00       	mov    $0x61,%edx
 681:	be 00 00 00 00       	mov    $0x0,%esi
 686:	48 8d 3d 8b 09 20 00 	lea    0x20098b(%rip),%rdi        # 201018 <buffer>
 68d:	e8 0c 01 00 00       	callq  79e <set_value>
 692:	be 09 00 00 00       	mov    $0x9,%esi
 697:	48 8d 3d 7a 09 20 00 	lea    0x20097a(%rip),%rdi        # 201018 <buffer>
 69e:	e8 46 01 00 00       	callq  7e9 <get_value>
 6a3:	88 45 fb             	mov    %al,-0x5(%rbp)
 6a6:	0f b6 45 fb          	movzbl -0x5(%rbp),%eax
 6aa:	83 c0 27             	add    $0x27,%eax
 6ad:	0f be c0             	movsbl %al,%eax
 6b0:	89 c2                	mov    %eax,%edx
 6b2:	be 09 00 00 00       	mov    $0x9,%esi
 6b7:	48 8d 3d 5a 09 20 00 	lea    0x20095a(%rip),%rdi        # 201018 <buffer>
 6be:	e8 db 00 00 00       	callq  79e <set_value>
 6c3:	ba 37 00 00 00       	mov    $0x37,%edx
 6c8:	be 03 00 00 00       	mov    $0x3,%esi
 6cd:	48 8d 3d 44 09 20 00 	lea    0x200944(%rip),%rdi        # 201018 <buffer>
 6d4:	e8 c5 00 00 00       	callq  79e <set_value>
 6d9:	ba 58 00 00 00       	mov    $0x58,%edx
 6de:	be 01 00 00 00       	mov    $0x1,%esi
 6e3:	48 8d 3d 2e 09 20 00 	lea    0x20092e(%rip),%rdi        # 201018 <buffer>
 6ea:	e8 af 00 00 00       	callq  79e <set_value>
 6ef:	ba 32 00 00 00       	mov    $0x32,%edx
 6f4:	be 04 00 00 00       	mov    $0x4,%esi
 6f9:	48 8d 3d 18 09 20 00 	lea    0x200918(%rip),%rdi        # 201018 <buffer>
 700:	e8 99 00 00 00       	callq  79e <set_value>
 705:	be 01 00 00 00       	mov    $0x1,%esi
 70a:	48 8d 3d 07 09 20 00 	lea    0x200907(%rip),%rdi        # 201018 <buffer>
 711:	e8 d3 00 00 00       	callq  7e9 <get_value>
 716:	88 45 fb             	mov    %al,-0x5(%rbp)
 719:	ba 79 00 00 00       	mov    $0x79,%edx
 71e:	be 02 00 00 00       	mov    $0x2,%esi
 723:	48 8d 3d ee 08 20 00 	lea    0x2008ee(%rip),%rdi        # 201018 <buffer>
 72a:	e8 6f 00 00 00       	callq  79e <set_value>
 72f:	0f b6 45 fb          	movzbl -0x5(%rbp),%eax
 733:	83 e8 0c             	sub    $0xc,%eax
 736:	0f be c0             	movsbl %al,%eax
 739:	89 c2                	mov    %eax,%edx
 73b:	be 07 00 00 00       	mov    $0x7,%esi
 740:	48 8d 3d d1 08 20 00 	lea    0x2008d1(%rip),%rdi        # 201018 <buffer>
 747:	e8 52 00 00 00       	callq  79e <set_value>
 74c:	ba 5f 00 00 00       	mov    $0x5f,%edx
 751:	be 05 00 00 00       	mov    $0x5,%esi
 756:	48 8d 3d bb 08 20 00 	lea    0x2008bb(%rip),%rdi        # 201018 <buffer>
 75d:	e8 3c 00 00 00       	callq  79e <set_value>
 762:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
 769:	eb 1c                	jmp    787 <main+0x13d>
 76b:	8b 55 fc             	mov    -0x4(%rbp),%edx
 76e:	48 8d 05 a3 08 20 00 	lea    0x2008a3(%rip),%rax        # 201018 <buffer>
 775:	0f b6 04 02          	movzbl (%rdx,%rax,1),%eax
 779:	0f be c0             	movsbl %al,%eax
 77c:	89 c7                	mov    %eax,%edi
 77e:	e8 9d fd ff ff       	callq  520 <putchar@plt>
 783:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
 787:	83 7d fc 09          	cmpl   $0x9,-0x4(%rbp)
 78b:	76 de                	jbe    76b <main+0x121>
 78d:	bf 0a 00 00 00       	mov    $0xa,%edi
 792:	e8 89 fd ff ff       	callq  520 <putchar@plt>
 797:	b8 00 00 00 00       	mov    $0x0,%eax
 79c:	c9                   	leaveq 
 79d:	c3                   	retq   

000000000000079e <set_value>:
 79e:	55                   	push   %rbp
 79f:	48 89 e5             	mov    %rsp,%rbp
 7a2:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
 7a6:	89 75 f4             	mov    %esi,-0xc(%rbp)
 7a9:	89 d0                	mov    %edx,%eax
 7ab:	88 45 f0             	mov    %al,-0x10(%rbp)
 7ae:	8b 55 f4             	mov    -0xc(%rbp),%edx
 7b1:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
 7b5:	48 01 c2             	add    %rax,%rdx
 7b8:	0f b6 45 f0          	movzbl -0x10(%rbp),%eax
 7bc:	88 02                	mov    %al,(%rdx)
 7be:	90                   	nop
 7bf:	5d                   	pop    %rbp
 7c0:	c3                   	retq   

00000000000007c1 <clear_value>:
 7c1:	55                   	push   %rbp
 7c2:	48 89 e5             	mov    %rsp,%rbp
 7c5:	48 83 ec 10          	sub    $0x10,%rsp
 7c9:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
 7cd:	89 75 f4             	mov    %esi,-0xc(%rbp)
 7d0:	8b 4d f4             	mov    -0xc(%rbp),%ecx
 7d3:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
 7d7:	ba 00 00 00 00       	mov    $0x0,%edx
 7dc:	89 ce                	mov    %ecx,%esi
 7de:	48 89 c7             	mov    %rax,%rdi
 7e1:	e8 b8 ff ff ff       	callq  79e <set_value>
 7e6:	90                   	nop
 7e7:	c9                   	leaveq 
 7e8:	c3                   	retq   

00000000000007e9 <get_value>:
 7e9:	55                   	push   %rbp
 7ea:	48 89 e5             	mov    %rsp,%rbp
 7ed:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
 7f1:	89 75 f4             	mov    %esi,-0xc(%rbp)
 7f4:	8b 55 f4             	mov    -0xc(%rbp),%edx
 7f7:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
 7fb:	48 01 d0             	add    %rdx,%rax
 7fe:	0f b6 00             	movzbl (%rax),%eax
 801:	5d                   	pop    %rbp
 802:	c3                   	retq   

0000000000000803 <set_all>:
 803:	55                   	push   %rbp
 804:	48 89 e5             	mov    %rsp,%rbp
 807:	48 83 ec 20          	sub    $0x20,%rsp
 80b:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
 80f:	89 f0                	mov    %esi,%eax
 811:	89 55 e0             	mov    %edx,-0x20(%rbp)
 814:	88 45 e4             	mov    %al,-0x1c(%rbp)
 817:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
 81e:	eb 19                	jmp    839 <set_all+0x36>
 820:	0f be 55 e4          	movsbl -0x1c(%rbp),%edx
 824:	8b 4d fc             	mov    -0x4(%rbp),%ecx
 827:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
 82b:	89 ce                	mov    %ecx,%esi
 82d:	48 89 c7             	mov    %rax,%rdi
 830:	e8 69 ff ff ff       	callq  79e <set_value>
 835:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
 839:	8b 45 fc             	mov    -0x4(%rbp),%eax
 83c:	3b 45 e0             	cmp    -0x20(%rbp),%eax
 83f:	72 df                	jb     820 <set_all+0x1d>
 841:	90                   	nop
 842:	c9                   	leaveq 
 843:	c3                   	retq   

0000000000000844 <clear_all>:
 844:	55                   	push   %rbp
 845:	48 89 e5             	mov    %rsp,%rbp
 848:	48 83 ec 10          	sub    $0x10,%rsp
 84c:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
 850:	89 75 f4             	mov    %esi,-0xc(%rbp)
 853:	8b 55 f4             	mov    -0xc(%rbp),%edx
 856:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
 85a:	be 00 00 00 00       	mov    $0x0,%esi
 85f:	48 89 c7             	mov    %rax,%rdi
 862:	e8 9c ff ff ff       	callq  803 <set_all>
 867:	90                   	nop
 868:	c9                   	leaveq 
 869:	c3                   	retq   
 86a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

0000000000000870 <__libc_csu_init>:
 870:	41 57                	push   %r15
 872:	41 56                	push   %r14
 874:	49 89 d7             	mov    %rdx,%r15
 877:	41 55                	push   %r13
 879:	41 54                	push   %r12
 87b:	4c 8d 25 36 05 20 00 	lea    0x200536(%rip),%r12        # 200db8 <__frame_dummy_init_array_entry>
 882:	55                   	push   %rbp
 883:	48 8d 2d 36 05 20 00 	lea    0x200536(%rip),%rbp        # 200dc0 <__init_array_end>
 88a:	53                   	push   %rbx
 88b:	41 89 fd             	mov    %edi,%r13d
 88e:	49 89 f6             	mov    %rsi,%r14
 891:	4c 29 e5             	sub    %r12,%rbp
 894:	48 83 ec 08          	sub    $0x8,%rsp
 898:	48 c1 fd 03          	sar    $0x3,%rbp
 89c:	e8 4f fc ff ff       	callq  4f0 <_init>
 8a1:	48 85 ed             	test   %rbp,%rbp
 8a4:	74 20                	je     8c6 <__libc_csu_init+0x56>
 8a6:	31 db                	xor    %ebx,%ebx
 8a8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
 8af:	00 
 8b0:	4c 89 fa             	mov    %r15,%rdx
 8b3:	4c 89 f6             	mov    %r14,%rsi
 8b6:	44 89 ef             	mov    %r13d,%edi
 8b9:	41 ff 14 dc          	callq  *(%r12,%rbx,8)
 8bd:	48 83 c3 01          	add    $0x1,%rbx
 8c1:	48 39 dd             	cmp    %rbx,%rbp
 8c4:	75 ea                	jne    8b0 <__libc_csu_init+0x40>
 8c6:	48 83 c4 08          	add    $0x8,%rsp
 8ca:	5b                   	pop    %rbx
 8cb:	5d                   	pop    %rbp
 8cc:	41 5c                	pop    %r12
 8ce:	41 5d                	pop    %r13
 8d0:	41 5e                	pop    %r14
 8d2:	41 5f                	pop    %r15
 8d4:	c3                   	retq   
 8d5:	90                   	nop
 8d6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
 8dd:	00 00 00 

00000000000008e0 <__libc_csu_fini>:
 8e0:	f3 c3                	repz retq 

Disassembly of section .fini:

00000000000008e4 <_fini>:
 8e4:	48 83 ec 08          	sub    $0x8,%rsp
 8e8:	48 83 c4 08          	add    $0x8,%rsp
 8ec:	c3                   	retq   
