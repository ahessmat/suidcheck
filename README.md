# suidcheck
A tool used for checking SUID binaries for potential vulnerabilities

22 July 2021
This tool is meant to be a complement to existing binary checkers, like suid3num.py and linPEAS.

However, there are circumstances that arise in the course of performing privilege escalation on a target that you are not able to run automated scripts on the target, but may be able to do some basic code execution (i.e. "ls").

This script takes the output from your target and identifies relevant vulnerabilities. It queries GTFObins for the latest binaries that the site is tracking, then evaluates the provided output to pick out any binaries that may be useful in privilege escalation.
