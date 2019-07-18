

Build binary as follow: 
```
gcc encrypt.c -o enc2 -lcrypto
```

```
bash-4.2# ./enc2 id_rsa.pub
```

This will encrypt plain_file, output to plain_file.enc.

```
bash-4.2# ls -l
total 40
-rw-r--r--. 1 root root  3388 Jul 14 17:41 decrypt.c
-rwxr-xr-x. 1 root root 13920 Jul 14 19:48 enc2
-rw-r--r--. 1 root root  4162 Jul 14 19:48 encrypt.c
-rw-r--r--. 1 root root   450 Jul 14 19:44 id_rsa.pub
-rw-r--r--. 1 root root    62 Jul 14 19:44 plain_file
-rw-r--r--. 1 root root   340 Jul 14 19:48 plain_file.enc
bash-4.2# hexdump plain_file.enc
0000000 0000 0001 6991 2adb b803 208f 2dc5 9bb3
0000010 922a 2cef ccc5 830b e30c b0e2 5660 aaca
0000020 2be5 fd4d 9251 b744 d357 33d9 451c 8215
0000030 ed69 bf5d c50b 7bb4 e894 7bd5 9753 56a0
0000040 83d1 c60f aeb1 4cf1 2e87 4d9c 6c4b 0458
0000050 7d8f b7cc 9849 1dec 7e97 9a13 e08b ba0a
0000060 26ca f09b 308c c62e 7ac3 bb1a aaed b5c5
0000070 ce4b 76f3 cfa4 df6d 4ffd b46d ae9d 7a11
0000080 af74 657f a42d 0a88 e5ec ed63 676a 17d3
0000090 c3d6 3252 3ada f80d 4563 8c28 4d4d ff78
00000a0 bfa9 075b a8d1 1990 686d ca14 a041 4e45
00000b0 716b 87cb 64b7 5989 3fa5 86aa dbca f7ed
00000c0 9557 c171 2dc3 58e6 6d5b 3620 044a 6a9e
00000d0 9732 7e92 137f ad0b a93c 0eb6 7ac6 ab7c
00000e0 d5bc 298e c981 f042 fcc9 24ec 5943 e029
00000f0 680a 3280 b9ec cbac 6f1b 5385 b504 1bca
0000100 10a6 f646 2567 9b1f 59ea 04b7 d033 274f
0000110 5274 be66 ab1b 3d51 b24a fd17 1a5f 7a1b
0000120 e44a 24e0 7f4d 189f f0f4 5313 52e4 5eb2
0000130 50f3 eac4 a509 c522 61d6 faeb a239 4a08
0000140 d915 3742 ae75 bc0b 574b 61f4 6a2e 0b64
0000150 07f7 0237
0000154
```


