#pragma once
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <thread>
#include <chrono>
#include <ctime>

using namespace std;

#define MTU 280	
#define IHL 40		//IPv6 Header Length in bytes
#define FHL	8		//IPv6 Fragment Header Length in bytes

//Extension Header 										Type 	Description
/****************************************************************************************************************************/
//Hop - by - Hop Options								0		Options that need to be examined by all devices on the path.
//Destination Options(before routing header)			60		Options that need to be examined only by the destination of the packet.
//Routing												43		Methods to specify the route for a datagram(used with Mobile IPv6).
//Fragment												44		Contains parameters for fragmentation of datagrams.
//Authentication Header(AH)								51		Contains information used to verify the authenticity of most parts of the packet.
//Encapsulating Security Payload(ESP)					50		Carries encrypted data for secure communication
//Destination Options(before upper - layer header)		60		Options that need to be examined only by the destination of the packet
//Mobility(currently without upper - layer header		135		Parameters used with Mobile IPv6
//Host Identity Protocol								139		Used for Host Identity Protocol version 2 (HIPv2)
//Shim6 Protocol										140		Used for Shim6
//Reserved												253		Used for experimentation and testing
//Reserved												254		Used for experimentation and testing
//No Next Header										59		Indicates that there is no next header

class IExtentionHeader {
public:
	uint8_t NextHeader;													//(8 bit) Identifies the type of header immediately following the IExtention Header
	uint8_t HdrExtLen;													//(8 bit) Length of Extension Options header in 8 - octet units, not including the first 8 octets
																		//PS: Extension Header Length = HdrExtLen + 1
	IExtentionHeader& operator=(const IExtentionHeader& LeftOperand);	
};

class IHeader {
public:
	uint8_t Version{ 6 };								//(4 bit) IP version = 6
	uint8_t TrafficClass;								//(8 bit) traffic class field
	uint32_t FlowLabel;									//(20 bit) flow label
	uint16_t PayloadLength;								//(16 bit) Length of the IPv6 payload, the rest of the packet following this IPv6 header, in bytes
	uint8_t NextHeader;									//(8 bit) Identifies the type of header immediately following the IPv6 header
	uint8_t HopLimit{ 123 };							//(8 bit) Decremented by 1 by each node that forwards the packet.
														//The packet is discarded if Hop Limit is decremented to zero.
	uint16_t SourceAddress[8]{ 0,0,0,0,0,0,0,1 };		//(128 bit) Address of the originator of the packet
	uint16_t DestinationAddress[8]{ 0,0,0,0,0,0,0,1 };	//(128 bit) Address of the intended recipient of the packet
														//possible not the ultimate recipient if Routing Header is present
	IHeader& operator=(const IHeader& LeftOperand);
};

//NextHeader = 0
class IHopbyHopHeader : public IExtentionHeader {
public:
	size_t Options{ 0x00 };			// Variable-length field, of length such that the complete Hop - by - Hop Options header is an integer multiple of 8 octets long

	IHopbyHopHeader& operator=(const IHopbyHopHeader& LeftOperand);
};

//NextHeader = 43
class IRoutingHeader : public IExtentionHeader {
public:
	uint8_t RoutingType;			//(8 bit) Identifier of a particular Routing header variant
	uint8_t SegmentsLeft;			//(8 bit) Number of route segments remaining, i.e., number of explicitly listed intermediate nodes still to be visited before reaching the final destination
	size_t type_specification;		//Variable-length field, of format determined by the Routing Type, and of length such that the complete Routing header is an integer multiple of 8 octets long

	IRoutingHeader& operator=(const IRoutingHeader& LeftOperand);
};

//NextHeader = 44
class IFragmentHeader {
public:
	uint8_t NextHeader{ 59 };			//(8 bit) Identifies the type of header immediately following the Fragment Header
	uint8_t Reserved{ 0x00 };			//(8 bit) Initialized to zero for transmission; ignored on reception
	uint16_t FragmentOffset{ 0x00 };	//(16 bit) The offset, in 8-octet units, of the data following this header, relative to the start of the Fragmentable Part of the original packet
	uint8_t Res{ 0x00 };				//(2 bit) Initialized to zero for transmission; ignored on reception
	uint8_t Mflag{ 0x00 };				//(1 bit) 1 = more fragments; 0 = last fragment
	uint32_t Identification{0x00};		//(32 bit) Current time of sent original packet

	IFragmentHeader& operator=(const IFragmentHeader& LeftOperand);
};

class IDatagram {
public:
	IHeader* Header{ nullptr };									//IPv6 Header of Original Datagram
	vector<IExtentionHeader*>* ExtentionHeaders{ nullptr };		//Extension Header(s) of Original Datagram
	//TODO: upper-layer headers buffer
	IFragmentHeader* FragmentHeader{ nullptr };					//Fragment Header of Original Datagram
	vector<uint8_t>* Data{ nullptr };							//Datagram data
	~IDatagram();												//Destructor IDatagram
};

class ISocketSender {
public:
	vector<IDatagram*> SendingDatagrams;				//Buffer for send datagrams
	void proc_print_datagram(IDatagram* SendDatagram);	//Print Datagram procedure
	void proc_fragmentation(IDatagram* SendDatagram);	//Fragmentation procedure
};

class ResourcesBuffer {
public:
	IFragmentHeader FRAGMENT_HEADER_BUFFER;					//fragment header buffer
	vector<IExtentionHeader*>* ExtHdr_BUFFER{ nullptr };	//extension headers buffer
	vector<uint8_t> DATA_BUFFER;							//data buffer
	vector<bool> RCVBT;										//fragment block bit table
	IHeader HEADER_BUFFER;									//header buffer
	int TIMER{ 0 };											//timer
	uint16_t TDL{ 0 };										//total data length field
	size_t TimerStartTime{ 0 };								//Current start time

	ResourcesBuffer();										//Constructor ResourcesBuffer
	~ResourcesBuffer();										//Destructor ResourcesBuffer
};

class ISocketReceiver {
	bool DestroyTimerThread{ true };									//Variable for destroy TimerThread
	size_t TLB{ 15 };													//Timer Lower Bound
public:
	~ISocketReceiver();													//Destructor ISocketReceiver
	map<string, ResourcesBuffer*> SOCKET_BUFFER;						//Socket Buffer
	void CreateTimerThread();											//CreateTimerThread method
	void proc_print_datagram(IDatagram* ReassembledReceivedDatagram);	//Print Datagram procedure
	void proc_reassembly(IDatagram* ReceivedDatagram);					//Reassembly procedure
	void proc_timer_checker();											//Timer checker procedure
};