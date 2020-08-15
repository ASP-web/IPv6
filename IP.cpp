#include "IP.h"
#include "IP.h"
#include <algorithm>

void ISocketSender::proc_print_datagram(IDatagram* SendDatagram) {
	//re-nodes is 4
	SendDatagram->Header->HopLimit -= 4;

	uint16_t EHL = 0;
	for (size_t i = 0; i < SendDatagram->ExtentionHeaders->size(); i++) { EHL += (*SendDatagram->ExtentionHeaders)[i]->HdrExtLen + 1; }

	cout << "Datagram [FRAGMENT/FULL] is sent!" << endl;
	cout << "Datagram with Version: " << (int)SendDatagram->Header->Version << endl;
	cout << "Datagram with IPv6 Header Length: " << (int)IHL << endl;
	cout << "Datagram with IPv6 All Extension Length: " << (int)EHL << endl;
	cout << "Datagram with IPv6 Fragment Header Length: " << (int)FHL << endl;
	cout << "Datagram with Payload length: " << (int)SendDatagram->Header->PayloadLength << endl;
	cout << "Datagram with Identification: " << (int)SendDatagram->FragmentHeader->Identification << endl;
	cout << "Datagram with M Flag: " << (int)SendDatagram->FragmentHeader->Mflag << endl;
	cout << "Datagram with Fragment Offset: " << (int)SendDatagram->FragmentHeader->FragmentOffset << endl;
	cout << "Datagram with HopLimit: " << (int)SendDatagram->Header->HopLimit << endl << endl;

	SendingDatagrams.push_back(SendDatagram);
	return;
}

//Fragmentation procedure
//Notation:
//EHL - All Extension Headers Length
//FHL - Fragment Header Length
//FO - Fragment Offset
//IHL - Internet Header Length
//MF - More Fragments flag
//OFO - Old Fragment Offset
//OMF - Old More Fragments flag
//NFB - Number of Fragment Blocks
//MTU - Maximum Transmission Unit

void ISocketSender::proc_fragmentation(IDatagram* SendDatagram) {
	//IHL + Payload Length <= MTU ?
	if (SendDatagram->Header->PayloadLength + IHL <= MTU) { proc_print_datagram(SendDatagram); return; }

	//Produce the first fragment = SendDatagram
	//(1) Copy the original internet header
	else {
		IDatagram* OldSendDatagram = new IDatagram;

		OldSendDatagram->Header = new IHeader;
		*OldSendDatagram->Header = *SendDatagram->Header;

		OldSendDatagram->ExtentionHeaders = new vector<IExtentionHeader*>(SendDatagram->ExtentionHeaders->size(), nullptr);
		for (size_t i = 0; i < OldSendDatagram->ExtentionHeaders->size(); i++) { 	
			uint8_t ExtensionHeaderID;
			if (i == 0) { ExtensionHeaderID = SendDatagram->Header->NextHeader; }
			else { ExtensionHeaderID = (*SendDatagram->ExtentionHeaders)[i - 1]->NextHeader; }
			
			if (ExtensionHeaderID == 0) (*OldSendDatagram->ExtentionHeaders)[i] = new IHopbyHopHeader;
			else if (ExtensionHeaderID == 43) (*OldSendDatagram->ExtentionHeaders)[i] = new IRoutingHeader;
			//TODO: other Extension Headers's IDs

			*(*OldSendDatagram->ExtentionHeaders)[i] = *(*SendDatagram->ExtentionHeaders)[i]; 
		}
		
		OldSendDatagram->FragmentHeader = new IFragmentHeader;
		*OldSendDatagram->FragmentHeader = *SendDatagram->FragmentHeader;

		//Copy pointers to Data
		OldSendDatagram->Data = SendDatagram->Data;

		//(2)
		//NFB = (MTU - IHL - EHL - FHL) / 8;
		uint16_t EHL = 0, NFB = MTU - IHL  - FHL;
		for (size_t i = 0; i < SendDatagram->ExtentionHeaders->size(); i++) { EHL += (*SendDatagram->ExtentionHeaders)[i]->HdrExtLen + 1; }
		NFB = (NFB - EHL) / 8;

		//(3) Attach the first NFB*8 data octets
		vector<uint8_t>* FirstFragmentData = new vector<uint8_t>((size_t)NFB * 8, 0x00);
		memcpy(
			FirstFragmentData->data(),
			SendDatagram->Data->data(),
			(size_t)NFB * 8
		);
		SendDatagram->Data = FirstFragmentData;

		//(4) Correct the header
		//MF <- 1; Payload Length <- (NFB*8) + EHL + FHL
		//Fragment Header's Next Header = 59
		//Last Extension Header's Next Header = 44
		SendDatagram->FragmentHeader->Mflag = 0x01;
		SendDatagram->Header->PayloadLength = NFB * 8 + EHL + FHL;
		(*SendDatagram->ExtentionHeaders)[SendDatagram->ExtentionHeaders->size() - 1]->NextHeader = 44;

		//(5) Submit fragment to the next step in datagram processing
		proc_print_datagram(SendDatagram);

		//Produce the second fragment
		//(6) Selectively copy the internet header
		IDatagram* SecondFragmentSendDatagram = new IDatagram;
		
		SecondFragmentSendDatagram->Header = new IHeader;
		*SecondFragmentSendDatagram->Header = *OldSendDatagram->Header;

		SecondFragmentSendDatagram->ExtentionHeaders = new vector<IExtentionHeader*>(OldSendDatagram->ExtentionHeaders->size(), nullptr);
		for (size_t i = 0; i < SecondFragmentSendDatagram->ExtentionHeaders->size(); i++) {

			uint8_t ExtensionHeaderID;
			if (i == 0) { ExtensionHeaderID = OldSendDatagram->Header->NextHeader; }
			else { ExtensionHeaderID = (*OldSendDatagram->ExtentionHeaders)[i - 1]->NextHeader; }

			if (ExtensionHeaderID == 0) (*SecondFragmentSendDatagram->ExtentionHeaders)[i] = new IHopbyHopHeader;
			else if (ExtensionHeaderID == 43) (*SecondFragmentSendDatagram->ExtentionHeaders)[i] = new IRoutingHeader;
			//TODO: other Extension Header's IDs
			//TODO: REWRITE EXTENTION HEADER CREATOR

			*(*SecondFragmentSendDatagram->ExtentionHeaders)[i] = *(*OldSendDatagram->ExtentionHeaders)[i];
		}

		SecondFragmentSendDatagram->FragmentHeader = new IFragmentHeader;
		*SecondFragmentSendDatagram->FragmentHeader = *OldSendDatagram->FragmentHeader;

		//(7) Append the remaining data
		vector<uint8_t>* SecondFragmentData = new vector<uint8_t>(OldSendDatagram->Data->size() - ((size_t)NFB * 8), 0x00);
		memcpy(
			SecondFragmentData->data(),
			OldSendDatagram->Data->data() + ((size_t)NFB * 8),
			OldSendDatagram->Data->size() - ((size_t)NFB * 8)
		);

		SecondFragmentSendDatagram->Data = SecondFragmentData;

		//(8) Correct the header:
		//Payload Length <- Old  Payload Length - (NFB*8)
		SecondFragmentSendDatagram->Header->PayloadLength = OldSendDatagram->Header->PayloadLength - (NFB * 8);
		//FO <- OFO + NFB
		SecondFragmentSendDatagram->FragmentHeader->FragmentOffset =
			OldSendDatagram->FragmentHeader->FragmentOffset + NFB;
		//MF <- OMF
		SecondFragmentSendDatagram->FragmentHeader->Mflag = OldSendDatagram->FragmentHeader->Mflag;

		//(10) Submit fragment to the fragmentation test
		delete OldSendDatagram;
		proc_fragmentation(SecondFragmentSendDatagram);
	}
}

ISocketReceiver::~ISocketReceiver() { DestroyTimerThread = true; }

void ISocketReceiver::CreateTimerThread() {
	if (DestroyTimerThread == true) {
		DestroyTimerThread = false;
		new thread([this]() { this->proc_timer_checker(); });
	}
}

void ISocketReceiver::proc_print_datagram(IDatagram* ReassembledReceivedDatagram) {
	uint16_t EHL = 0;
	for (size_t i = 0; i < ReassembledReceivedDatagram->ExtentionHeaders->size(); i++) { EHL += (*ReassembledReceivedDatagram->ExtentionHeaders)[i]->HdrExtLen + 1; }

	cout << "Datagram [FULL] is received!" << endl;
	cout << "Datagram with Version: " << (int)ReassembledReceivedDatagram->Header->Version << endl;
	cout << "Datagram with IPv6 Header Length: " << (int)IHL << endl;
	cout << "Datagram with IPv6 All Extension Length: " << (int)EHL << endl;
	cout << "Datagram with IPv6 Fragment Header Length: " << (int)FHL << endl;
	cout << "Datagram with Payload length: " << (int)ReassembledReceivedDatagram->Header->PayloadLength << endl;
	cout << "Datagram with Identification: " << (int)ReassembledReceivedDatagram->FragmentHeader->Identification << endl;
	cout << "Datagram with M Flag: " << (int)ReassembledReceivedDatagram->FragmentHeader->Mflag << endl;
	cout << "Datagram with Fragment Offset: " << (int)ReassembledReceivedDatagram->FragmentHeader->FragmentOffset << endl;
	cout << "Datagram with HopLimit: " << (int)ReassembledReceivedDatagram->Header->HopLimit << endl << endl;

	delete ReassembledReceivedDatagram;
	return;
}

//Reassembly procedure
//Notation:
//FO - Fragment Offset
//IHL - Internet Header Length
//MF - More Fragments flag
//TTL - Time To Live
//NFB - Number of Fragment Blocks
//TL - Total Length
//TDL - Total Data Length
//BUFID - Buffer Identifier
//RCVBT - Fragment Received Bit Table
//TLB - Timer Lower Bound

void ISocketReceiver::proc_reassembly(IDatagram* ReceivedDatagram) {
	//(1) BUFID <- Source Address|Destination Address|Identification
	string SourceAddress, DestinationAddress;
	for (uint8_t i = 0; i < 8; i++) {
		SourceAddress += to_string(ReceivedDatagram->Header->SourceAddress[i]);
		DestinationAddress += to_string(ReceivedDatagram->Header->DestinationAddress[i]);
	}
	string BUFID =
		SourceAddress +
		DestinationAddress +
		to_string(ReceivedDatagram->FragmentHeader->Identification);
	//(2) IF FO = 0 AND MF = 0
	if ((ReceivedDatagram->FragmentHeader->FragmentOffset == 0x00) && (ReceivedDatagram->FragmentHeader->Mflag == 0x00)) {
		//(3) THEN IF buffer with BUFID is allocated
		if (SOCKET_BUFFER.find(BUFID) != SOCKET_BUFFER.end()) {
			//(4)THEN flush all reassembly resources for this BUFID
			ResourcesBuffer* BUFID_RESOURCES = SOCKET_BUFFER.at(BUFID);
			delete BUFID_RESOURCES;
			SOCKET_BUFFER.erase(BUFID);
			//(5) Submit datagram to next step; DONE
			proc_print_datagram(ReceivedDatagram);
			return;
		}
		else {
			//(5) Submit datagram to next step; DONE
			proc_print_datagram(ReceivedDatagram);
			return;
		}
	}
	ResourcesBuffer* BUFID_RESOURCES;
	//(6) ELSE IF no buffer with BUFID is allocated
	if (SOCKET_BUFFER.find(BUFID) == SOCKET_BUFFER.end()) {
		//(7) THEN allocate reassembly resources
		//with BUFID
		//TIMER <- TLB; TDL <- 0;
		BUFID_RESOURCES = new ResourcesBuffer;
		BUFID_RESOURCES->TIMER = (int)TLB; BUFID_RESOURCES->TDL = 0;
		SOCKET_BUFFER.insert(pair<string, ResourcesBuffer*>(BUFID, BUFID_RESOURCES));
	}
	BUFID_RESOURCES = SOCKET_BUFFER.at(BUFID);
	//(8) put data from fragment into data buffer with
	//BUFID from octet FO*8 to octet (Payload Length - EHL - FHL) + FO*8
	uint16_t EHL = 0;
	for (size_t i = 0; i < ReceivedDatagram->ExtentionHeaders->size(); i++) { EHL += (*ReceivedDatagram->ExtentionHeaders)[i]->HdrExtLen + 1; }
	uint32_t FirstOctet = ReceivedDatagram->FragmentHeader->FragmentOffset * 8;
	uint32_t LastOctet =
		ReceivedDatagram->Header->PayloadLength -
		EHL -
		FHL +
		ReceivedDatagram->FragmentHeader->FragmentOffset * 8;
	if (BUFID_RESOURCES->DATA_BUFFER.size() < LastOctet) { BUFID_RESOURCES->DATA_BUFFER.resize(LastOctet); }
	for (uint32_t i = FirstOctet; i < LastOctet; i++) { BUFID_RESOURCES->DATA_BUFFER[i] = (*ReceivedDatagram->Data)[i - FirstOctet]; }

	//(9) set RCVBT bits from FO to FO+((Payload Length - EHL - FHL + 7)/8)
	uint32_t FirstBit = ReceivedDatagram->FragmentHeader->FragmentOffset;
	uint32_t LastBit =
		ReceivedDatagram->FragmentHeader->FragmentOffset +
		((ReceivedDatagram->Header->PayloadLength - EHL - FHL + 7) / 8);
	if (BUFID_RESOURCES->RCVBT.size() < LastBit) { BUFID_RESOURCES->RCVBT.resize(LastBit); }
	for (uint32_t i = FirstBit; i < LastBit; i++) { BUFID_RESOURCES->RCVBT[i] = true; }

	//(10) IF MF = 0 THEN TDL <- Payload Length - EHL - FHL + (FO*8)
	if (ReceivedDatagram->FragmentHeader->Mflag == 0x00) {
		BUFID_RESOURCES->TDL =
			ReceivedDatagram->Header->PayloadLength -
			EHL -
			FHL +
			ReceivedDatagram->FragmentHeader->FragmentOffset * 8;
	}

	//(11) IF FO = 0 THEN put header in header buffer, put extension headers in extension header buffer, put fragment header in fragment header buffer
	if (ReceivedDatagram->FragmentHeader->FragmentOffset == 0x00) { 
		BUFID_RESOURCES->HEADER_BUFFER = *ReceivedDatagram->Header; 

		BUFID_RESOURCES->ExtHdr_BUFFER = new vector<IExtentionHeader*>(ReceivedDatagram->ExtentionHeaders->size(), nullptr);
		for (size_t i = 0; i < BUFID_RESOURCES->ExtHdr_BUFFER->size(); i++) {
			uint8_t ExtensionHeaderID;
			if (i == 0) { ExtensionHeaderID = ReceivedDatagram->Header->NextHeader; }
			else { ExtensionHeaderID = (*ReceivedDatagram->ExtentionHeaders)[i - 1]->NextHeader; }

			if (ExtensionHeaderID == 0) (*BUFID_RESOURCES->ExtHdr_BUFFER)[i] = new IHopbyHopHeader;
			else if (ExtensionHeaderID == 43) (*BUFID_RESOURCES->ExtHdr_BUFFER)[i] = new IRoutingHeader;
			//TODO: other Extension Headers's IDs

			*(*BUFID_RESOURCES->ExtHdr_BUFFER)[i] = *(*ReceivedDatagram->ExtentionHeaders)[i];
		}

		BUFID_RESOURCES->FRAGMENT_HEADER_BUFFER = *ReceivedDatagram->FragmentHeader;
	}

	//(12) IF TDL != 0
	if (BUFID_RESOURCES->TDL != 0) {
		//(13) AND all RCVBT bits from 0 to (TDL+7)/8 are set
		for (uint32_t i = 0; i < (uint32_t)((BUFID_RESOURCES->TDL + 7) / 8); i++) {
			if (BUFID_RESOURCES->RCVBT[i] != true) {
				//(17) TIMER <- MAX(TIMER, TTL)
				BUFID_RESOURCES->TIMER = max(BUFID_RESOURCES->TIMER, (int)BUFID_RESOURCES->HEADER_BUFFER.HopLimit);
				//(18) give up until next fragment or timer expires
				//TODO: call ICMP message for get needs fragment
				time_t current_time;
				BUFID_RESOURCES->TimerStartTime = time(&current_time);
				return;
			}
		}

		//(14) THEN Payload Length <- TDL+EHL+FHL
		BUFID_RESOURCES->HEADER_BUFFER.PayloadLength = BUFID_RESOURCES->TDL + EHL + FHL;

		//(15) Submit datagram to next step
		IDatagram* ReassembledReceivedDatagram = new IDatagram;

		ReassembledReceivedDatagram->Header = new IHeader;
		ReassembledReceivedDatagram->FragmentHeader = new IFragmentHeader;
		ReassembledReceivedDatagram->Data = new vector<uint8_t>;

		*ReassembledReceivedDatagram->Header = BUFID_RESOURCES->HEADER_BUFFER;

		ReassembledReceivedDatagram->ExtentionHeaders = new vector<IExtentionHeader*>(BUFID_RESOURCES->ExtHdr_BUFFER->size(), nullptr);
		for (size_t i = 0; i < ReassembledReceivedDatagram->ExtentionHeaders->size(); i++) {
			uint8_t ExtensionHeaderID;
			if (i == 0) { ExtensionHeaderID = BUFID_RESOURCES->HEADER_BUFFER.NextHeader; }
			else { ExtensionHeaderID = (*BUFID_RESOURCES->ExtHdr_BUFFER)[i - 1]->NextHeader; }

			if (ExtensionHeaderID == 0) (*ReassembledReceivedDatagram->ExtentionHeaders)[i] = new IHopbyHopHeader;
			else if (ExtensionHeaderID == 43) (*ReassembledReceivedDatagram->ExtentionHeaders)[i] = new IRoutingHeader;
			//TODO: other Extension Headers's IDs

			*(*ReassembledReceivedDatagram->ExtentionHeaders)[i] = *(*BUFID_RESOURCES->ExtHdr_BUFFER)[i];
		}

		*ReassembledReceivedDatagram->FragmentHeader = BUFID_RESOURCES->FRAGMENT_HEADER_BUFFER;
		*ReassembledReceivedDatagram->Data = BUFID_RESOURCES->DATA_BUFFER;

		ReassembledReceivedDatagram->FragmentHeader->Mflag = 0x00;
		proc_print_datagram(ReassembledReceivedDatagram);

		//(16) free all reassembly resources
		//for this BUFID; DONE
		delete BUFID_RESOURCES;
	}
}

void ISocketReceiver::proc_timer_checker() {
	//(19) timer expires: flush all reassembly with this BUFID; DONE.
	while (DestroyTimerThread != true) {
		this_thread::sleep_for(2s);
		for (auto it = SOCKET_BUFFER.begin(); it != SOCKET_BUFFER.end(); ++it) {
			time_t current_time;
			//TIMER = TIMER-(CURRENT_TIME-START_TIME)
			it->second->TIMER -= (int)((time(&current_time) - it->second->TimerStartTime));
			//CHECK TIMER = 0
			if (it->second->TIMER >= 0) {
				delete it->second;
				SOCKET_BUFFER.erase(it->first);
			}
		}
	}
}

ResourcesBuffer::ResourcesBuffer() { time_t current_time; TimerStartTime = time(&current_time); }

ResourcesBuffer::~ResourcesBuffer() {
	for (size_t i = 0; i < ExtHdr_BUFFER->size(); i++) delete (*ExtHdr_BUFFER)[i];
	delete ExtHdr_BUFFER;
	DATA_BUFFER.clear();
	RCVBT.clear();
}

IDatagram::~IDatagram() {
	delete Header;
	for (size_t i = 0; i < ExtentionHeaders->size(); i++) { delete (*ExtentionHeaders)[i]; }
	delete ExtentionHeaders;
	delete FragmentHeader;
	delete Data;
}

IExtentionHeader& IExtentionHeader::operator=(const IExtentionHeader& LeftOperand) {
	if (&LeftOperand == this) return *this;
	NextHeader = LeftOperand.NextHeader;
	HdrExtLen = LeftOperand.HdrExtLen;
	return *this;
}

IHeader& IHeader::operator=(const IHeader& LeftOperand) {
	if (&LeftOperand == this) return *this;
	Version = LeftOperand.Version;
	TrafficClass = LeftOperand.TrafficClass;
	FlowLabel = LeftOperand.FlowLabel;
	PayloadLength = LeftOperand.PayloadLength;
	NextHeader = LeftOperand.NextHeader;
	HopLimit = LeftOperand.HopLimit;

	for (uint8_t i = 0; i < 8; i++) {
		SourceAddress[i] = LeftOperand.SourceAddress[i];
		DestinationAddress[i] = LeftOperand.DestinationAddress[i];
	}
	return *this;
}

IRoutingHeader& IRoutingHeader::operator=(const IRoutingHeader& LeftOperand) {
	if (&LeftOperand == this) return *this;
	RoutingType = LeftOperand.RoutingType;
	SegmentsLeft = LeftOperand.SegmentsLeft;
	type_specification = LeftOperand.type_specification;
	return *this;
}

IFragmentHeader& IFragmentHeader::operator=(const IFragmentHeader& LeftOperand) {
	if (&LeftOperand == this) return *this;
	NextHeader = LeftOperand.NextHeader;
	Reserved = LeftOperand.Reserved;
	FragmentOffset = LeftOperand.FragmentOffset;
	Res = LeftOperand.Res;
	Mflag = LeftOperand.Mflag;
	Identification = LeftOperand.Identification;
	return *this;
}

IHopbyHopHeader& IHopbyHopHeader::operator=(const IHopbyHopHeader& LeftOperand) {
	if (&LeftOperand == this) return *this;
	Options = LeftOperand.Options;
	return *this;
}
