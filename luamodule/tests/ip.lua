-- ip.lua

function test_ip_create(ip, expected, is4, is6, should_fail)
   if #ip ~= #should_fail then
      error("Input sequences length mismatch")
   end
   for i = 1,#ip,1 do
      local ret, ip_str = pcall(ur_ip, ip[i])
      if not ret then
         if not should_fail[i] then
            error("ur_ip failed: " .. ip_str)
         end
      else
         if should_fail[i] then
            error("ur_ip should have failed")
         end
         if ip_str ~= expected[i] then
            if expected[i] == nil then expected[i] = "(nil)" end
            if ip_str == nil then ip_str = "(nil)" end
            error(string.format("ur_ip('%s') returned '%s', expected '%s'", ip[i], ip_str, expected[i]))
         end
         if ip_str ~= nil then
            is_ipv4 = ur_ip4(ip_str)
            if is_ipv4 ~= is4[i] then
               error(string.format("ur_ip4('%s') returned '%s', expected '%s'", ip_str, is_ipv4, is4[i]))
            end
            is_ipv6 = ur_ip6(ip_str)
            if is_ipv6 ~= is6[i] then
               error(string.format("ur_ip6('%s') returned '%s', expected '%s'", ip_str, is_ipv6, is6[i]))
            end
         end
      end
   end
end

function on_init()
   local ip = {"192.168.0.1", "8.8.8.8", "0000:0000::1"}
   local expected = {"192.168.0.1", "8.8.8.8", "::1"}
   local is4 = {true, true, false}
   local is6 = {false, false, true}
   local should_fail = {false, false, false}

   test_ip_create(ip, expected, is4, is6, should_fail)
end

function on_template_recv()
   local ip = {0x11223344, {192, 168, 0, 1}, "2000:0000::1234:1"}
   local expected = {nil, nil, "2000::1234:1"}
   local is4 = {false, false, false}
   local is6 = {false, false, true}
   local should_fail = {true, true, false}

   test_ip_create(ip, expected, is4, is6, should_fail)

   local ip1, ip2, ip3, ip4 = ur_ip("192.168.0.1", "::1", "", "10.200.4.1")
   if not ur_ip4(ip1) or not ur_ip6(ip2) or ip3 ~= nil or not ur_ip4(ip4) then
      error("ur_ip multiple arguments failed")
   end

   local ip4_1, ip4_2, ip4_4 = ur_ip4(ip1, ip2, ip4)
   if not ip4_1 or ip4_2 or not ip4_4 then
      error("ur_ip4 multiple arguments failed")
   end

   if pcall(ur_ip4, ip1, ip3) then
      error("ur_ip4 should have failed")
   end

   local ip6_1, ip6_2, ip6_4 = ur_ip6(ip1, ip2, ip4)
   if ip6_1 or not ip6_2 or ip6_4 then
      error("ur_ip6 multiple arguments failed")
   end

   if pcall(ur_ip6, ip1, ip2, ip3) then
      error("ur_ip6 should have failed")
   end
end

function on_record_recv()
   local ip = {"", {192, 168, 0, 1}, "2000:0000::1234:1"}
   local expected = {nil, nil, "2000::1234:1"}
   local is4 = {false, false, false}
   local is6 = {false, false, true}
   local should_fail = {false, true, false}

   test_ip_create(ip, expected, is4, is6, should_fail)

   local ip, ip2 = ur_ip("10.20.30.40", "2001:0db8:85a3:1234:5678:8a2e:0370:7334")
   local ip1 = ip

   ip_mask_op = getmetatable(ip1)["__div"]
   if not pcall(ip_mask_op, ip1, 24) then
      error("mask of ipv4 address failed")
   end
   if pcall(ip_mask_op, ip1, "192.168.0.1") then
      error("mask of ipv4 address should have failed")
   end
   if pcall(ip_mask_op, 24, ip1) then
      error("mask of ipv4 address should have failed")
   end
   if pcall(ip_mask_op, ip1, -1) or pcall(ip_mask_op, ip1, 33) then
      error("mask of ipv4 address should have failed")
   end
   if pcall(ip_mask_op, ip2, -1) or pcall(ip_mask_op, ip2, 129) then
      error("mask of ipv6 address should have failed")
   end

   if ip1 / 32 ~= ip1 or ip1 / 0 ~= "0.0.0.0" then
      error("/0 or /24 mask of ipv4 address failed")
   end

   if ip2 / 0 ~= "::" or ip2 / 32 ~= "2001:db8::" or ip2 / 64 ~= "2001:db8:85a3:1234::" or
      ip2 / 96 ~= "2001:db8:85a3:1234:5678:8a2e::" or ip2 / 128 ~= ip2 then
      error("/0, /32, /64, /96, /128 mask of ipv6 address failed")
   end

   if ip1 / 24 ~= "10.20.30.0" or (ip1 / 24) / 16 ~= "10.20.0.0" then
      error("/24, (/24)/16 mask of ipv4 address failed")
   end

   if ip2 / 24 ~= "2001:d00::" or (ip2 / 56) / 20 ~= "2001::" then
      error("/24, (/56)/20 mask of ipv6 address failed")
   end
end
