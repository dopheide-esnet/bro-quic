// Generated by binpac_quickstart

#ifndef ANALYZER_PROTOCOL_QUIC_QUIC_H
#define ANALYZER_PROTOCOL_QUIC_QUIC_H

#include "events.bif.h"


#include "analyzer/protocol/udp/UDP.h"

#include "quic_pac.h"

namespace analyzer { namespace quic {

class QUIC_Analyzer

: public analyzer::Analyzer {

public:
	QUIC_Analyzer(Connection* conn);
	virtual ~QUIC_Analyzer();

	// Overriden from Analyzer.
	virtual void Done();
	
	virtual void DeliverPacket(int len, const u_char* data, bool orig,
					uint64 seq, const IP_Hdr* ip, int caplen);
	

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new QUIC_Analyzer(conn); }

protected:
	binpac::QUIC::QUIC_Conn* interp;
	
};

} } // namespace analyzer::* 

#endif