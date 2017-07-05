# burp-vulners-scanner
Burp Suite scanner plugin based on Vulners.com vulnerability database API
- Search fingerprints in http response (inspired by plugin "Software Version Reporter")
  and check found version in vulners.com vulnerability database
- [Experemental] Check unique URLs in vulners.com finding exploits for such paths


## Requirements

- Burp Suite - Professional Edition
- Java 1.7

## Installation

1. Clone repository
2. From command line run
     ```
     mvn package
     ```
3. find plugin.jar in /target folder
3. open Burp Suite -> Extender -> Add -> path to plugin.jar


Ready to install (skip 1-3) build [burp-vulners-scanner-1.0-SNAPSHOT.jar](https://github.com/vankyver/burp-vulners-scanner/blob/master/target/burp-vulners-scanner-1.0-SNAPSHOT.jar)