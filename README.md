# CS 410/591 - Computer Security
# Final Project : Honeypot

## Descriptiong:
A simple Honeypot Implementation

## Contact
Kirk Powell
kirk.powell@siu.edu

# Installation
Do not use this service without being aware of the full consequence.  It will open a bash terminal to the machine with no restrictions.  It is designed to entice a hacker to track their activities and garner as much information about them before the honeypot is compromised, destroyed, or otherwise incapacitated.

Compile the ```server.c``` file: ```gcc server.exe -o server.c```  
Set up on any computer connected to the internet and run ```./server.exe```

Client connections are made through IP access ```./client.exe 127.0.0.1```

## Presentation

There is a set of slides (presentation.odp) that explains what a honeypot is and how it works.  Review this material if you are unclear about honeypots.