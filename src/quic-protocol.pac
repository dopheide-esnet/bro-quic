# Dop: Oct 2017

type QUIC_PDU(is_orig: bool) = record {
	QH: QUIC_Header;
	data: bytestring &restofdata;
} &byteorder=bigendian;


type QUIC_Header = record {
	flags	: uint8;
	CID		: uint64;
	packet_num	: uint32;
	version : bytestring &length=4;
} &let {
	version_bool : bool = $context.connection.determine_version_flag_and_continue(flags);
}	

refine connection QUIC_Conn += {
	function determine_version_flag_and_continue(flags : uint8) : bool
		%{
			// this tells us we have a long form header and it should contain a version string
			if(flags & 0x80)
				return true;

			bro_analyzer()->SetSkip(true);
			return false;
		%}
};

