cc test/test_fork.c -o testout/test_fork
cc test/test_kill.c -o testout/test_kill
cc test/test_mmap.c -o testout/test_mmap
cc test/test_wait.c -o testout/test_wait

./testout/test_fork
./testout/test_kill
./testout/test_mmap
./testout/test_wait

rm -rf testout/*
rm -rf testout