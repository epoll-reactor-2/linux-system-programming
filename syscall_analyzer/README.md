Minimal syscall analyzer, that actually acts like a `strace`.

# Illustration
```
$ ./syscall_analyzer ffmpeg

ffmpeg returned:
ffmpeg version n5.0 Copyright (c) 2000-2022 the FFmpeg developers
  built with gcc 11.2.0 (GCC)
...

...
openat(dfd = 4294967196, filename = "/sys/devices/system/cpu", flags = O_RDONLY|O_NONBLOCK|O_CLOEXEC) = 4
newfstatat(rdi = 4, rsi = 139772989218579, rdx = 140734585833280, r10 = 4096, r8 = 591872, r9 = 139772989226015 ) = 0
brk(rdi = 94567434383360, rsi = 139772989471392, rdx = 0, r10 = 94567434219520, r8 = 3, r9 = 139772989471488 ) = 94567434383360
getdents64(rdi = 4, rsi = 94567434218944, rdx = 32768, r10 = 94567434219520, r8 = 0, r9 = 139772989471488 ) = 720
getdents64(rdi = 4, rsi = 94567434218944, rdx = 32768, r10 = 139772989115072, r8 = 0, r9 = 0 ) = 0
brk(rdi = 94567434350592, rsi = 0, rdx = -4096, r10 = 139772989115072, r8 = 0, r9 = 0 ) = 94567434350592
close(rdi = 4, rsi = 0, rdx = 139772989504792, r10 = 139772989115072, r8 = 0, r9 = 0 ) = 0
sched_getaffinity(rdi = 23880, rsi = 8, rdx = 94567434115520, r10 = 139772989115072, r8 = 8, r9 = 139772989471488 ) = 8
futex(rdi = 139772770096828, rsi = 129, rdx = 2147483647, r10 = 0, r8 = 202, r9 = 2177 ) = 0
futex(rdi = 139772770096840, rsi = 129, rdx = 2147483647, r10 = 0, r8 = 202, r9 = 2177 ) = 0
brk(rdi = 94567434485760, rsi = 139772989471392, rdx = 0, r10 = 94567434350592, r8 = 3, r9 = 139772989471488 ) = 94567434485760
getrandom(rdi = 140734585834719, rsi = 1, rdx = 1, r10 = 0, r8 = 94567434386016, r9 = 139772989471488 ) = 1
newfstatat(rdi = 4294967196, rsi = 139772973179200, rdx = 140734585831232, r10 = 0, r8 = 0, r9 = 139772989471488 ) = -2
ioctl(rdi = 2, rsi = 21505, rdx = 140734585828976, r10 = 0, r8 = 140734585829040, r9 = 140734585828736 ) = 0
ioctl(rdi = 2, rsi = 21505, rdx = 140734585828928, r10 = 0, r8 = 140734585828992, r9 = 0 ) = 0
write(fd = 2, buf = "ffmpeg version n5.0", count = 19) = 19
write(fd = 2, buf = " Copyright (c) 2000-2022 the FFmpeg developers", count = 46) = 46
write(fd = 2, buf = " ", count = 1) = 1
write(fd = 2, buf = "  built with gcc 11.2.0 (GCC) ", count = 30) = 30
write(fd = 2, buf = "  configuration: --prefix=/usr --disable-debug --disable-static ", count = 982) = 982
write(fd = 2, buf = "  libavutil      57. 17.100 / 57. 17.100 ", count = 41) = 41
write(fd = 2, buf = "  libavcodec     59. 18.100 / 59. 18.100 ", count = 41) = 41
write(fd = 2, buf = "  libavformat    59. 16.100 / 59. 16.100 ", count = 41) = 41
write(fd = 2, buf = "  libavdevice    59.  4.100 / 59.  4.100 ", count = 41) = 41
write(fd = 2, buf = "  libavfilter     8. 24.100 /  8. 24.100 ", count = 41) = 41
write(fd = 2, buf = "  libswscale      6.  4.100 /  6.  4.100 ", count = 41) = 41
write(fd = 2, buf = "  libswresample   4.  3.100 /  4.  3.100 ", count = 41) = 41
write(fd = 2, buf = "  libpostproc    56.  3.100 / 56.  3.100 ", count = 41) = 41
...
```
