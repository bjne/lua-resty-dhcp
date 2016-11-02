local packet = require "resty.dhcp.packet"
local match = string.match
local floor = math.floor

local _M = { _VERSION = 0.1 }

_M.serve = function(callback)
    local sock = ngx.req.udp_socket()
    if not sock then
        return nil, "no socket"
    end

    sock:settimeout(5000)

    local data, err = sock:receive()
    if not data then
        return nil, "failed to read packet"
    end

    local packet, err = packet.new(data)
    if not packet then
        return nil, err
    end

    if not packet:op() == 'REQUEST' then
        return nil, "Unsupported DHCP operation"..packet:op()
    end

    local options, err = packet:options()
    if not options then
        return nil, err
    end

    local msg_type, reply_msg_type = options.dhcp_msg_type

    if msg_type == 'DISCOVER' then
        reply_msg_type = 'OFFER'
    elseif msg_type == 'REQUEST' then
        reply_msg_type = 'ACK'
    else
        return nil, "unknown message type: "..msg_type
    end

    local reply, err = callback(msg_type, packet, options)
    if not reply then
        return nil, err
    end

    packet:op('REPLY')
    reply.options = reply.options or {}
    reply.options.dhcp_msg_type = reply.options.dhcp_msg_type or reply_msg_type

    for k,v in pairs(reply) do
        if not packet[k] or type(packet[k]) ~= "function" then
            return nil, "unsupported operation: "..k
        end

        local ok, err = packet[k](packet, v)
        if not ok then
            return nil, err
        end
    end

    return sock:send(packet:data())
end

return _M

-- vim: ts=4 sw=4 et ai
