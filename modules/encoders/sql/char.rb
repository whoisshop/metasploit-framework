##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Encoder

	def initialize
		super(
			'Name'             => 'SQL CHAR Encoder',
			'Description'      => %q{
				This encoder returns a CHAR string encapsulated in
				CHAR(). WARNING: This significantly increases the size of payload
			},
			'Author'           => 'shop <whoisshop[at]gmail.com>',
			'Liscense'         => MSF_LICENSE,
			'Arch'             => ARCH_ALL,
			'EncoderType'      => Msf::Encoder::Type::Unspecified
		)
	end

	def encode_block(state, buf)
		
		# SQLi commonly utlizies char to evade the use of quotes in text.
		#
		# This could be used when, for example, quote escaping in sql is necessary.
		# ex. UNION ALL SELECT 1,2,3,passthru('whoami');,5,6-- >> 
		#     UNION ALL SELECT 1,2,3,CHAR(112,97,......,41),5,6--
		#
		sql_char = ""

		buf.each_byte {|c| sql_char << c.to_s+"," }
		sql_char.chomp!(",")

		return "CHAR(#{sql_char})"
	end

end
