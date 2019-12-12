ip netns exec R1 bird -c ./birdR1.conf -P birdR1.pid -s birdR1.socket
ip netns exec R3 bird -c ./birdR3.conf -P birdR3.pid -s birdR3.socket
