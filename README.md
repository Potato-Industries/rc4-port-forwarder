# rc4-port-forwarder
Compact RC4 encryptor / decryptor TCP port forwarder, written for an engagement. 

https://en.wikipedia.org/wiki/RC4 

**Usage**

```
WOPR@WOPR proxy % python proxy.py -h
usage: proxy.py [-h] [-l L] [-t T] [-p P]

Basic TCP port forwarder with RC4 encryption.

optional arguments:
  -h, --help  show this help message and exit
  -l L        Listen on x.x.x.x:xxxx
  -t T        Tunnel to x.x.x.x:xxxx
  -p P        Secret: `openssl passwd -1 -salt xxxxxxxx`
  ```

```
WOPR@WOPR proxy % python proxy.py -l 127.0.0.1:9998 -t target.com:9999 -p `openssl passwd -1 -salt hahaha`
Password: 
listening on: 127.0.0.1:9998
forwarding (rc4): target.com:9999
```

**Behaviour**

Due to the nature of how RC4 encryption works (XOR), the forwarder will encrypt or decrypt depending on the context of the traffic.

- Plaintext traffic -> Listen on x.x.x.x:xxxx -> Encrypt RC4 XOR operation -> Tunnel to x.x.x.x:xxxx
- RC4 traffic -> Listen on x.x.x.x:xxxx -> Decrypt RC4 XOR operation -> Tunnel to x.x.x.x:xxxx 

The tool can be used in multiple scenarios, encrypt generic port traffic to an RC4 application, decrypt RC4 application traffic to plaintext port or as a insecure/obfuscation TCP port forwarder tool if you run it on both ends. 


Enjoy~
