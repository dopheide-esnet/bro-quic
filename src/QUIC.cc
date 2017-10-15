// Generated by binpac_quickstart

#include "QUIC.h"

#include "Reporter.h"

#include "events.bif.h"

using namespace analyzer::quic;

QUIC_Analyzer::QUIC_Analyzer(Connection* c)

: analyzer::Analyzer("QUIC", c)

	{
	interp = new binpac::QUIC::QUIC_Conn(this);
	
	}

QUIC_Analyzer::~QUIC_Analyzer()
	{
	delete interp;
	}

void QUIC_Analyzer::Done()
	{
	
	Analyzer::Done();
	
	}

void QUIC_Analyzer::DeliverPacket(int len, const u_char* data,
	 			  bool orig, uint64 seq, const IP_Hdr* ip, int caplen)
	{
	Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);

	try
		{
		interp->NewData(orig, data, data + len);
		}
	catch ( const binpac::Exception& e )
		{
		ProtocolViolation(fmt("Binpac exception: %s", e.c_msg()));
		}
	}
