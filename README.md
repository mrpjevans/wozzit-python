# Wozzit

### A common language for the Internet of Things

Version 0.0.1

The Internet of Things (IoT) is all very well, but it seems as each device has
its own protocols and ways of doing things. Wozzit aims to be a common
interface for IoT devices.

It is comprised of two parts, a schema for descriving data and a server, known
as a 'node', for sending and receiving data.

This early implementation create a node in Python and provides help with
creating and receiving messages (known as 'havers').

### Installation

```
pip install requests pync emails notify2
```

### Usage

To start a server on port 10207 for all bound IP addresses:

```
import wozzit
wozzit.listen()
```
