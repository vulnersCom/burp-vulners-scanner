# burp-vulners-scanner

[![Current Release](https://img.shields.io/github/release/vulnersCom/burp-vulners-scanner.svg "Current Release")](https://github.com/vulnersCom/burp-vulners-scanner/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/vulnersCom/burp-vulners-scanner/total.svg "Downloads")](https://github.com/vulnersCom/burp-vulners-scanner/releases) [![PayPal](https://img.shields.io/badge/donate-PayPal-green.svg)](https://paypal.me/videns)

# Description

Burp Suite scanner plugin based on [Vulners.com](https://vulners.com) vulnerability database API
- Search fingerprints in http response (inspired by plugin "Software Version Reporter")
  and check found version in vulners.com vulnerability database
- [Experemental] Check unique URLs in vulners.com finding exploits for such paths

# How to use

## Requirements

- Burp Suite - Professional Edition
- Java 1.7
- Maven

## Installation

1. Clone repository
2. From command line run
     ```
     mvn package
     ```
3. find burp-vulners-scanner.jar in /target folder
4. open Burp Suite -> Extender -> Add -> path to plugin.jar


## Build
Ready to install build [burp-vulners-scanner.jar](https://github.com/vulnersCom/burp-vulners-scanner/releases/latest)
