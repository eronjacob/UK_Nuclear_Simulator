# UK NUCLEAR SIMULATOR PROGRAM

## ABOUT THE PROJECT
The UK Nuclear Simulator is a multi-component C software design that models a nuclear defense system. It consists of 4 clients: missileSilo, submarine, radar and satellite while the server is called nuclearControl. The system simulates with key features sucn as real-time threat detection and response using TCP sockets for communication, Caesar cipher encryption for securing messaging, and multi-threading for concurrent client handling. The server (nuclearControl) is responsible for processing intelligence reports from 2 of the 4 clients: radar and satellite. By doing so, the server issues launch commands to the other 2 clients, missileSilo and submarine, when threats presents themselves higher than the critical threshold. The program developed a test mode for simulating war scenarios and then generates detailed logs and summaries for operation test analysis. To tackle safety measures to the system, thread safety, reliable socket communication, and robust error 
handling. 

# TABLE OF CONTENTS
## GETTING STARTED

### PROJECT STATUS
The UK Nuclear Simulator is reliable and operational for education and demonstration purposes. It is often updated to address bugs and provide feature enhancements like more sophisticated encryption or additional client types. All components are completely functional and the present version enables a 60-second simulation cycle.

### INSTALLATION
Note: If the files are in a folder, you have to set the directory first otherwise the terminal will not be able to find the files you want to compile. Example, if the folder is named "UK_Nuclear_Simulator", you have to enter "cd Uk_Nuclear_Simulator" in the terminal.

Then, bash "sudo apt-get install build-essential" and "sudo apt install libssl-dev" in the same terminal to install essential tools and libraries on Debian-based systems.

sudo apt-get install build-essential: Installs a collection of tools required for compiling and building C programs including the C compiler (gcc) and header files (stdio.h and stdlib.h) . 

sudo apt install libssl-dev: Installs OpenSSl functions that enables C programs to use cryptographic functions like the Caesar cipher for secure communications. It provides tools to implement cryptographic algorithms in networked applications projects, especially for the UK Nuclear Simulator.

Now you can compile the UK Nuclear Simulator on a POSIX-compliant system.

#### PREREQUISITES:
* C compiler: gcc
* POSIX-compliant environment with support for sockets and threads
* Terminal knowledge for running commands

#### STEPS TO COMPILE THE SERVER AND CLIENTS:
* Step 1: Compile "gcc -o nuclearControl nuclearControl.c -pthread" in one terminal for the server. -pthread is required for POSIX thread support

* Step 2: Compile the clients in ; "gcc -missileSilo missileSilo.c", "gcc -o submarine submarine.c", "gcc -o radar radar.c", and "gcc -o satellite satellite.c", in the same terminal as the server.

### USAGE INSTRUCTIONS
Since the project runs as a server-client system, below are steps for running the simulation.

#### SIMULATION WORKFLOW.
* Step 1: Type "./nuclearControl --test" in 1 terminal. This enters to test mode that generates random threats with 50% chance of exceeding the critical threshold to send launch commands. It also starts the server to listen on ports 8081 (missileSilo), 8082 (submarine), 8083 (radar), and 8084 (satellite) to move on to client connections.

* Step 2: Type "./missileSilo", "./submarine", "./radar", and "./satellite" in seperate terminals for each clients. This begins the simulation and builds the log files for all components.

* Step 3: The simulation begins to run for 60 seconds and its happening in the log files.

* Step 4: After 60 seconds, the server will disconnect from the clients and terminate the simulation. As a result, the txt files will generate the summary of the operations for each components. 

#### OUTPUT LOG & SUMMARY FILES
(nuclearControl.log)
* ===== Nuclear Control Log =====
* Simulation Start: Mon Apr 14 20:24:37 2025
* =============================

* [Mon Apr 14 20:24:37 2025] STARTUP      Server started on port 8081
* [Mon Apr 14 20:24:37 2025] STARTUP      Server started on port 8082
* [Mon Apr 14 20:24:37 2025] STARTUP      Server started on port 8083
* [Mon Apr 14 20:24:37 2025] STARTUP      Server started on port 8084
* [Mon Apr 14 20:24:37 2025] WAR_TEST     Source: TEST, Type: Sea, Details: Naval Fleet, Threat Level: 75, Location: Arctic Ocean
* [Mon Apr 14 20:24:37 2025] COMMAND      Encrypted command: frppdqg:odxqfk|wdujhw:Dufwlf Rfhdq
* [Mon Apr 14 20:24:37 2025] COMMAND      Decrypted command: command:launch|target:Arctic Ocean
* [Mon Apr 14 20:24:38 2025] CONNECTION   Client connected from 127.0.0.1:8084
* [Mon Apr 14 20:24:38 2025] MESSAGE      Encrypted message: vrxufh:Vdwhoolwh|wbsh:Vsdfh|gdwd:Edoolvwlf Plvvloh|wkuhdw_ohyho:25|orfdwlrq:Dufwlf Rfhdq
* [Mon Apr 14 20:24:38 2025] MESSAGE      Decrypted message: source:Satellite|type:Space|data:Ballistic Missile|threat_level:25|location:Arctic Ocean
* [Mon Apr 14 20:24:38 2025] THREAT       Source: Satellite, Type: Space, Details: Ballistic Missile, Threat Level: 25, Location: Arctic Ocean
* [Mon Apr 14 20:24:39 2025] CONNECTION   Client connected from 127.0.0.1:8083
* [Mon Apr 14 20:24:39 2025] MESSAGE      Encrypted message: vrxufh:Udgdu|wbsh:Dlu|gdwd:Vwhdowk Erpehu|wkuhdw_ohyho:29|orfdwlrq:Lulvk Vhd
* [Mon Apr 14 20:24:39 2025] MESSAGE      Decrypted message: source:Radar|type:Air|data:Stealth Bomber|threat_level:29|location:Irish Sea
* [Mon Apr 14 20:24:39 2025] THREAT       Source: Radar, Type: Air, Details: Stealth Bomber, Threat Level: 29, Location: Irish Sea
* [Mon Apr 14 20:24:41 2025] CONNECTION   Client connected from 127.0.0.1:8081
* [Mon Apr 14 20:24:41 2025] CONNECTION   Client connected from 127.0.0.1:8081


(nuclearControl_summary.txt)
* ===== Nuclear Control Simulation Summary =====
* Simulation End: Mon Apr 14 20:26:07 2025
* Total Threats Detected: 19
* Total Commands Issued: 14
* Connected Clients:
* =====================================


(missileSilo.log)
* ===== Missile Silo Log =====
* Simulation Start: Mon Apr 14 20:24:41 2025
* ==========================

* [Mon Apr 14 20:24:41 2025] STARTUP    Missile Silo System initializing
* [Mon Apr 14 20:24:41 2025] CONNECTION Connected to Nuclear Control
* [Mon Apr 14 20:24:47 2025] MESSAGE    Received: [Encrypted] frppdqg:odxqfk|wdujhw:Qruwk Dwodqwlf -> [Decrypted] command:launch|target:North Atlantic
* [Mon Apr 14 20:24:47 2025] COMMAND    Launching missile at North Atlantic
* [Mon Apr 14 20:24:47 2025] FEEDBACK   Missile launched at North Atlantic successfully
* [Mon Apr 14 20:24:49 2025] MESSAGE    Received: [Encrypted] frppdqg:odxqfk|wdujhw:Edowlf Vhd -> [Decrypted] command:launch|target:Baltic Sea
* [Mon Apr 14 20:24:49 2025] COMMAND    Launching missile at Baltic Sea
* [Mon Apr 14 20:24:49 2025] FEEDBACK   Missile launched at Baltic Sea successfully
* [Mon Apr 14 20:24:55 2025] MESSAGE    Received: [Encrypted] frppdqg:odxqfk|wdujhw:Dufwlf Rfhdq -> [Decrypted] command:launch|target:Arctic Ocean
* [Mon Apr 14 20:24:55 2025] COMMAND    Launching missile at Arctic Ocean


(missileSilo_summary.txt)
* ===== Nuclear Control Simulation Summary =====
* Simulation End: Mon Apr 14 20:26:07 2025
* Total Threats Detected: 19
* Total Commands Issued: 14
* Connected Clients:
* =====================================


(submarine.log)
* ===== Submarine Log =====
* Simulation Start: Mon Apr 14 20:24:41 2025
* =======================

* [Mon Apr 14 20:24:41 2025] STARTUP    Submarine System initializing
* [Mon Apr 14 20:24:41 2025] CONNECTION Connected to Nuclear Control
* [Mon Apr 14 20:24:47 2025] MESSAGE    Received: [Encrypted] frppdqg:odxqfk|wdujhw:Qruwk Dwodqwlf -> [Decrypted] command:launch|target:North Atlantic
* [Mon Apr 14 20:24:47 2025] COMMAND    Launching torpedo at North Atlantic
* [Mon Apr 14 20:24:47 2025] FEEDBACK   Torpedo launched at North Atlantic successfully
* [Mon Apr 14 20:24:49 2025] MESSAGE    Received: [Encrypted] frppdqg:odxqfk|wdujhw:Edowlf Vhd -> [Decrypted] command:launch|target:Baltic Sea
* [Mon Apr 14 20:24:49 2025] COMMAND    Launching torpedo at Baltic Sea


(submarine_summary.txt)
* ===== Submarine Simulation Summary =====
* Simulation End: Mon Apr 14 20:26:07 2025
* Total Torpedoes Launched: 7
* =====================================


(radar.log)
* ===== Radar Log =====
* Simulation Start: Mon Apr 14 20:24:39 2025
* ====================

* [Mon Apr 14 20:24:39 2025] STARTUP    Radar System initializing
* [Mon Apr 14 20:24:39 2025] CONNECTION Connected to Nuclear Control
* [Mon Apr 14 20:24:39 2025] INTEL      Sending Intelligence: Type=Air, Details=Stealth Bomber, ThreatLevel=29, Location=Irish Sea, [Encrypted] vrxufh:Udgdu|wbsh:Dlu|gdwd:Vwhdowk Erpehu|wkuhdw_ohyho:29|orfdwlrq:Lulvk Vhd
* [Mon Apr 14 20:24:49 2025] INTEL      Sending Intelligence: Type=Air, Details=Drone Swarm, ThreatLevel=87, Location=Baltic Sea, [Encrypted] vrxufh:Udgdu|wbsh:Dlu|gdwd:Gurqh Vzdup|wkuhdw_ohyho:87|orfdwlrq:Edowlf Vhd
* [Mon Apr 14 20:24:59 2025] INTEL      Sending Intelligence: Type=Air, Details=Missile Strike, ThreatLevel=42, Location=English Channel, [Encrypted] vrxufh:Udgdu|wbsh:Dlu|gdwd:Plvvloh Vwulnh|wkuhdw_ohyho:42|orfdwlrq:Hqjolvk Fkdqqho
* [Mon Apr 14 20:25:06 2025] INTEL      Sending Intelligence: Type=Air, Details=Stealth Bomber, ThreatLevel=22, Location=Irish Sea, [Encrypted] vrxufh:Udgdu|wbsh:Dlu|gdwd:Vwhdowk Erpehu|wkuhdw_ohyho:22|orfdwlrq:Lulvk Vhd


(radar_summary.txt)
* ===== Radar Simulation Summary =====
* Simulation End: Mon Apr 14 20:25:39 2025
* Total Intelligence Reports Sent: 8
* =====================================


(satellite.log)
* ===== Satellite Log =====
* Simulation Start: Mon Apr 14 20:24:38 2025
* =======================

* [Mon Apr 14 20:24:38 2025] STARTUP    Satellite System initializing
* [Mon Apr 14 20:24:38 2025] CONNECTION Connected to Nuclear Control
* [Mon Apr 14 20:24:38 2025] INTEL      Sending Intelligence: Type=Space, Details=Ballistic Missile, ThreatLevel=25, Location=Arctic Ocean, [Encrypted] vrxufh:Vdwhoolwh|wbsh:Vsdfh|gdwd:Edoolvwlf Plvvloh|wkuhdw_ohyho:25|orfdwlrq:Dufwlf Rfhdq
* [Mon Apr 14 20:24:48 2025] INTEL      Sending Intelligence: Type=Sea, Details=Satellite Anomaly, ThreatLevel=26, Location=Barents Sea, [Encrypted] vrxufh:Vdwhoolwh|wbsh:Vhd|gdwd:Vdwhoolwh Dqrpdob|wkuhdw_ohyho:26|orfdwlrq:Eduhqwv Vhd
* [Mon Apr 14 20:24:55 2025] INTEL      Sending Intelligence: Type=Air, Details=Ballistic Missile, ThreatLevel=85, Location=Arctic Ocean, [Encrypted] vrxufh:Vdwhoolwh|wbsh:Dlu|gdwd:Edoolvwlf Plvvloh|wkuhdw_ohyho:85|orfdwlrq:Dufwlf Rfhdq
* [Mon Apr 14 20:25:03 2025] INTEL      Sending Intelligence: Type=Space, Details=Naval Fleet, ThreatLevel=10, Location=Mediterranean, [Encrypted] vrxufh:Vdwhoolwh|wbsh:Vsdfh|gdwd:Qdydo Iohhw|wkuhdw_ohyho:10|orfdwlrq:Phglwhuudqhdq


(satellite_summary.txt)
* ===== Satellite Simulation Summary =====
* Simulation End: Mon Apr 14 20:25:40 2025
* Total Intelligence Reports Sent: 8
* =====================================

## CONTRIBUTION GUIDELINES
This project welcomes anybody to contribute to enhance the UK Nuclear Simulator project. Whether its fixing any errors, enhancing security features, improving client-server connections, your input is valuable.

Note: A few things to keep in mind when working on this project.
* 1. Make sure the directory is included to the terminal (e.g, "cd folder_name).
* 2. Before compiling the files, make sure you type "sudo apt-get install build-essential" and "sudo apt install libssl-dev" in the  terminal to install essential tools and libraries on Debian-based systems.

### OPEN IDEAS
A few things could be done such as:
* 1. Figuring out how to replace the caesar cipher with stronger encryption such as the AES encryption.
* 2. Expanding the threat types by adding new enemies to the system for the radar and satellite to pick up.
* 3. Improving the test mode that does not allow the 60 second simulaiton cycle to start immediately once the server starts.

### TIPS
* 1. Start small when it comes to error handling because it is the most challenging part and the smallest mistake can make a big impact.
* 2. Double check before running everything to decrease the number of connection failures in the system. 

## LICENSE
The license for this project was from Github and Visual Studio Code. Copyright from one's work is unacceptable but it will be an open source project.

## ACKNOWLEDGEMENT
Nobody had contributed to this project except me and therefore, it is an individual project.