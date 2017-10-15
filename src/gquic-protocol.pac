# Dop: Oct 2017

type GQUIC_PDU(is_orig: bool) = record {
	QH: GQUIC_Header;
	data: bytestring &restofdata;
} &byteorder=bigendian;

### DOP is it little or big endian?
# big according to https://github.com/quicwg/base-drafts/wiki/QUIC-Versions

type GQUIC_Header = record {
	flags	: uint8;
	CID		: uint64;   # 64 bit integer
	version : bytestring &length=4; # 4 byte string
} &let {
	version_bool : bool = $context.connection.determine_version_flag_and_continue(flags);
}	
# pull out more flags?  Do we care?

#	version_bool : bool = (flags & 0x01) ? true : false &check(version_bool == true);
# seems clear that &check is broken so pulled this out to a function to stop processing
# the connection


# This significantly reduces the calls to quic_event (by about 90% in our small test sample).
# will still need to check for version_bool == F in the event for those packets that get through.
refine connection GQUIC_Conn += {
	function determine_version_flag_and_continue(flags : uint8) : bool
		%{
			if(flags & 0x01)
				return true;

			bro_analyzer()->SetSkip(true);
			return false;
		%}
};

# add sequence later... I _think_ it's always 1 byte during the initial negotiation, can
# increase later
# problem is, after negotiation, you lose the version string and end up with just [flags, CID,
# sequence] or even just [flags, sequence] with no CID.
# in theory, if we saw the initial negotiation, we can track CIDs, but there really isn't
# much to gain.
