# Microburst

##Project Description
Due to the increasing demand for network services and the emergence of more and more different network applications, the problems of packet loss and delay have become intolerable. Therefore, Microbursts become difficult to ignore in the data center network. However, the typical congestion control method is too late for Microbursts.

MODFIM is an in-network method for mitigating Microbursts through programmable switches. It consists of three main components: (1) Detour Launcher (2) Packet Sequencer and (3) Post Detour Handler.

Detour Launcher is responsible for detecting the occurrence and end of microburst, and based on this, decides whether to detour or send the packet normally, so it includes a microburst detector and port selector. If Detour Launcher decides to detour the packet, the packet will then be sent to the Packet Sequencer. This component is responsible for controlling the sequence number sending, recycling and blocking or releasing of packets during the detour of ordered packets. If Detour Launcher finds that the microburst has just ended, it will send the packet to the Post-detour Handler. This component uses the time-stamped record and finds the interval of the stream segment to release other packets that have been detoured but not yet released. After the end, the status will change to No Microburst.

##Contribution:
+    • Respond to unpredictable microbursts in real-time
+    • Eliminate packet loss when an Microburst happens