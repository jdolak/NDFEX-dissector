--[[

  This is a Wireshark dissector for the NDFEX protocol for Notre Dames's HFT Techonologies SP 2025 class.

  To install, copy this file to your Wireshark plugins direcroty.
  This can be done with the following command on MacOS:
    `cp ./wireshark_dissector.lua /Applications/Wireshark.app/Contents/PlugIns/wireshark/wireshark_dissector.lua`
  and reloading Wireshark's plugins.

  This was made by:
    - Jachob Dolak

]]--

-- header parser
do
  local ndfex_proto = Proto("NDFEX","NDFEX Protocol")

  local magic_number = ProtoField.string("ndfex.magic_number", "magic_number", base.NONE)
  local length = ProtoField.uint16("ndfex.length", "length", base.DEC)
  local seq_num = ProtoField.uint32("ndfex.seq_num", "seq_num", base.DEC)
  local timestamp = ProtoField.uint64("ndfex.timestamp", "timestamp", base.DEC)
  local msg_type = ProtoField.uint8("ndfex.msg_type", "msg_type", base.DEC)

  ndfex_proto.fields = { magic_number, length, seq_num, timestamp, msg_type  }

  function ndfex_proto.dissector(buffer,pinfo,tree)

      pinfo.cols.protocol = "NDFEX"
      local subtree = tree:add(ndfex_proto,buffer(),"NDFEX Protocol Header")
      
      subtree:add_le(magic_number, buffer(0,8))
      subtree:add_le(length, buffer(8,2))
      subtree:add_le(seq_num, buffer(10,4))
      subtree:add_le(timestamp, buffer(14,8))
      subtree:add_le(msg_type, buffer(22,1)) 
      
  end

  local udp_table = DissectorTable.get("udp.port")
  -- register our protocol to handle udp port 12345
  udp_table:add(12345,ndfex_proto)
end

-- body parser
do
  local ndfex_wrapper_proto = Proto("ndfex_extra", "NDFEX Protocol Data");

  local F_order_id = ProtoField.uint64("ndfex.order_id", "Order ID", base.DEC)
  local F_symbol = ProtoField.uint32("ndfex.symbol", "Symbol", base.DEC)
  local F_side = ProtoField.uint8("ndfex.side", "Side", base.DEC)
  local F_quantity = ProtoField.uint32("ndfex.quantity", "Quantity", base.DEC)
  local F_price = ProtoField.int32("ndfex.price", "Price", base.DEC)
  local F_flags = ProtoField.uint8("ndfex.flags", "Flags", base.HEX)
  
  local F_type_s = ProtoField.string("ndfex.type", "Type", base.NONE)

  ndfex_wrapper_proto.fields = { F_order_id, F_symbol, F_side, F_quantity, F_price, F_flags }

  local f_msg_type = Field.new("ndfex.msg_type")
  local original_ndfex_dissector

  function ndfex_wrapper_proto.dissector(tvbuffer, pinfo, treeitem)

      original_ndfex_dissector:call(tvbuffer, pinfo, treeitem)
      local msg_type = f_msg_type()

      if msg_type then
          
          local subtreeitem = treeitem:add(ndfex_wrapper_proto, tvbuffer)

          if msg_type.value == 1 then -- new order

              subtreeitem:add(F_type_s, tvbuffer(), msg_type):set_text("TYPE : New Order")

              subtreeitem:add_le(F_order_id, tvbuffer(23,8))
              subtreeitem:add_le(F_symbol, tvbuffer(31,4))
              subtreeitem:add_le(F_side, tvbuffer(35,1))
              subtreeitem:add_le(F_quantity, tvbuffer(36,4))
              subtreeitem:add_le(F_price, tvbuffer(40,4))
              subtreeitem:add_le(F_flags, tvbuffer(44,1))
          
          elseif msg_type.value == 2 then -- delete order

              subtreeitem:add(F_type_s, tvbuffer(), msg_type):set_text("TYPE : Delete Order")

              subtreeitem:add_le(F_order_id, tvbuffer(23,8))

          elseif msg_type.value == 3 then -- modify order

              subtreeitem:add(F_type_s, tvbuffer(), msg_type):set_text("TYPE : Modify Order")

              subtreeitem:add_le(F_order_id, tvbuffer(23,8))
              subtreeitem:add_le(F_side, tvbuffer(31,1))
              subtreeitem:add_le(F_quantity, tvbuffer(32,4))
              subtreeitem:add_le(F_price, tvbuffer(36,4))

          elseif msg_type.value == 4 then -- trade

              subtreeitem:add(F_type_s, tvbuffer(), msg_type):set_text("TYPE : Trade")

              subtreeitem:add_le(F_order_id, tvbuffer(23,8))
              subtreeitem:add_le(F_quantity, tvbuffer(31,4))
              subtreeitem:add_le(F_price, tvbuffer(35,4))

          elseif msg_type.value == 5 then -- trade summary

              subtreeitem:add(F_type_s, tvbuffer(), msg_type):set_text("TYPE : Trade Summary")

              subtreeitem:add_le(F_symbol, tvbuffer(23,4))
              subtreeitem:add_le(F_side, tvbuffer(27,1))
              subtreeitem:add_le(F_quantity, tvbuffer(28,4))
              subtreeitem:add_le(F_price, tvbuffer(32,4))

          end
      end
  end

  local udp_dissector_table = DissectorTable.get("udp.port")
  original_ndfex_dissector = udp_dissector_table:get_dissector(12345) -- save the original dissector so we can still get to it
  udp_dissector_table:add(12345, ndfex_wrapper_proto)                 -- and take its place in the dissector table
end
