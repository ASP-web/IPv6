#include "IP.h"
#include <iostream>
#include <vector>

using namespace std;

int main(char argc, char** argv) {
	//Notation:
	//EHL = All Extension Headers Length
	//IHL - Internet Header Length
	//FHL - Fragment Header Length
	//MTU - Maximum Transmission Unit

	/*TEST FRAGMENTATION WITH (MTU = 280, IHL = 40, FHL = 8, EHL = 102) EXAMPLE*/
	ISocketSender SENDER;

	IDatagram* OriginalDatagram = new IDatagram;

	OriginalDatagram->ExtentionHeaders = new vector<IExtentionHeader*>;
	IHopbyHopHeader* FirstExtHdr = new IHopbyHopHeader;
	FirstExtHdr->HdrExtLen = 40;
	FirstExtHdr->NextHeader = 43;
	OriginalDatagram->ExtentionHeaders->push_back(FirstExtHdr);

	IRoutingHeader* SecondExtHdr = new IRoutingHeader;
	SecondExtHdr->HdrExtLen = 60;
	SecondExtHdr->NextHeader = 44;
	OriginalDatagram->ExtentionHeaders->push_back(SecondExtHdr);

	OriginalDatagram->FragmentHeader = new IFragmentHeader;
	OriginalDatagram->FragmentHeader->Identification = 0x00;

	//452 SEND DATA BYTES 
	OriginalDatagram->Data = new vector<uint8_t>(100, 0x0);
	OriginalDatagram->Data->resize(200); memset(OriginalDatagram->Data->data() + 100, 0x1, 100);
	OriginalDatagram->Data->resize(300); memset(OriginalDatagram->Data->data() + 200, 0x2, 100);
	OriginalDatagram->Data->resize(400); memset(OriginalDatagram->Data->data() + 300, 0x3, 100);
	OriginalDatagram->Data->resize(452); memset(OriginalDatagram->Data->data() + 400, 0x4, 52);

	OriginalDatagram->Header = new IHeader;
	//Payload Length < - Data Length + EHL + FHL
	uint16_t EHL = 0;
	for (size_t i = 0; i < OriginalDatagram->ExtentionHeaders->size(); i++) { EHL += (*OriginalDatagram->ExtentionHeaders)[i]->HdrExtLen + 1; }
	OriginalDatagram->Header->PayloadLength =
		(uint16_t)(OriginalDatagram->Data->size()) +
		EHL +
		FHL;
	OriginalDatagram->Header->NextHeader = 0;

	SENDER.proc_fragmentation(OriginalDatagram);

	/*TEST REASSEBLY*/
	ISocketReceiver RECEIVER;
	for (size_t i = 0; i < SENDER.SendingDatagrams.size(); i++) { RECEIVER.proc_reassembly(SENDER.SendingDatagrams[i]); }

	return 0;
}