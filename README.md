# ATFM
Code repository for ATFM project

This project aims to bring to a company a very-low-cost solution of honeypot which can log a maximum of scans or attacks in order to detect any suspicious intrusion on a critical network.

Two hardwares : raspberry Pi
   - The first one is the "critical honeypot"
   - The second one is the "forensic analyst" which get back all the logs from the other one and which is able to present graphical analysis to an human person (XML or WEB outputs). And furthermore, it's able to avoid any corruption of the other Raspberry OS by hosting a PXE clean image of the honeypot which is going to reboot every X hours.
   - We aim to use the FIR project, from CERT Société Générale, to warn the admin when an incident occurs.

# Honeypot

# Analyst
