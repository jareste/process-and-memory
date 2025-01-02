mkdir -p testout
cc test/main.c -pthread -o testout/main
./testout/main
# cc test/zombie.c -o testout/zombie
# ./testout/zombie
# cc test/orphan.c -o testout/orphan
# ./testout/orphan
# cc test/signal.c -o testout/signal
# ./testout/signal
# cc test/signal2.c -o testout/signal2
# ./testout/signal2


rm -rf main #zombieorphan signal signal2