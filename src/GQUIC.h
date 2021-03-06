// Generated by binpac_quickstart

#ifndef ANALYZER_PROTOCOL_QUIC_GQUIC_H
#define ANALYZER_PROTOCOL_QUIC_GQUIC_H

#include "events.bif.h"


#include "analyzer/protocol/udp/UDP.h"

#include "gquic_pac.h"

namespace analyzer { namespace gquic {

class GQUIC_Analyzer

: public analyzer::Analyzer {

public:
	GQUIC_Analyzer(Connection* conn);
	virtual ~GQUIC_Analyzer();

	// Overriden from Analyzer.
	virtual void Done();
	
	virtual void DeliverPacket(int len, const u_char* data, bool orig,
					uint64 seq, const IP_Hdr* ip, int caplen);
	

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new GQUIC_Analyzer(conn); }

protected:
	binpac::GQUIC::GQUIC_Conn* interp;
	
};

} } // namespace analyzer::* 

#endif
