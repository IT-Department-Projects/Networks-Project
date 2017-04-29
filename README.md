# Networks-Project

* Raw Socket program to implement Dynamic Host Control Protocol (DHCP)

## How to run the socket
* You need to give sudo permission for the scoket program to compile and run.

```bash
sudo su
gcc raw_socket.c
./a.out
```

## Instruction to run the file

* First get the interface by running `ifconfig` command in terminal
* It will give ex: enp9s8
```
sudo gcc dhcp.c -lpcap
sudo ./a.out enp9s8
```

# Output:
```
enp9s8 MAC : 40:47:17:14:19:CA
Sending DHCP_DISCOVERY
dhcp.c:269:ether_output::Send 300 bytes

Waiting for DHCP_OFFER
dhcp.c:243:ether_input::Received a frame with length of [334]

 0000 :: 20 47 47 44 0e ca 00 17 7c 55 3b 8a 08 00 45 10 
 0010 :: 01 40 00 00 00 00 10 11 26 46 c0 a8 01 01 c0 b8 
 0020 :: 01 06 00 43 00 44 01 2c 0e 66 02 01 06 00 00 00 
 0030 :: 00 00 00 00 00 00 00 00 00 00 c0 a8 01 06 00 00 
 0040 :: 00 00 00 00 00 00 10 47 47 42 0e ca 00 00 f5 26 
 0050 :: 1b 5b 68 5f 00 00 00 00 00 00 00 00 00 00 00 00 
 0060 :: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
 0070 :: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
 0080 :: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
 0090 :: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
 00a0 :: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
 00b0 :: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
 00c0 :: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
 00d0 :: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
 00e0 :: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
 00f0 :: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
 0100 :: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
 0110 :: 00 00 00 00 00 00 63 82 53 63 35 01 02 36 04 c0 
 0120 :: a8 01 01 33 04 00 01 51 80 01 04 ff ff ff 00 03 
 0130 :: 04 c0 a8 01 01 06 08 da f8 f5 09 da f8 ff 93 0f 
 0140 :: 0b 64 6f 6d 61 69 6e 2e 6e 61 6d 65 ff 00 Got IP 192.168.4.5
```
