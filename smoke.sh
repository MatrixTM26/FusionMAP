#!/bin/bash

nmap -sV --script http-security-audit.nse -d testasp.vulnweb.com
