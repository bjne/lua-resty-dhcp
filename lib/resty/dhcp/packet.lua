local ffi = require "ffi"
local options = require "resty.dhcp.options"

local sizeof = ffi.sizeof
local offsetof = ffi.offsetof
local C = ffi.C

ffi.cdef[[
typedef uint8_t socklen_t;

/* RFC 2131 */
typedef struct dhcp_packet {
    uint8_t _op;
    uint8_t _htype;
    uint8_t _hlen;
    uint8_t _hops;
    uint32_t _xid;
    uint16_t _secs;
    uint16_t _flags;
    uint32_t _ciaddr;
    uint32_t _yiaddr;
    uint32_t _siaddr;
    uint32_t _giaddr;
    uint8_t _chaddr[16];
    uint8_t _sname[64];
    uint8_t _file[128];
    uint32_t _cookie;
    uint8_t _options[?];
} dhcp_packet_t __attribute__((packed));

int inet_pton(int af, const char *src, void *dst);
const char *inet_ntop(int af, const void *src, char *dst, socklen_t size);

uint32_t ntohl (uint32_t __netlong);
uint32_t htonl (uint32_t __hostlong);
]]

local dhcp = {
    op = {
         [1] = 'REQUEST',    REQUEST    =  1,
         [2] = 'REPLY',      REPLY      =  2,
    },
    htype = {
         [1] = 'ETHERNET',   ETHERNET   =  1,
         [6] = 'IEEE802',    IEEE802    =  6,
         [7] = 'ARCNET',     ARCNET     =  7,
        [11] = 'LOCALTALK',  LOCALTALK  = 11,
        [12] = 'LOCALNET',   LOCALNET   = 12,
        [14] = 'SMDS',       SMDS       = 14,
        [15] = 'FRAMERELAY', FRAMERELAY = 15,
        [16] = 'ATM1',       ATM1       = 16,
        [17] = 'HDLC',       HDLC       = 17,
        [18] = 'FC',         FC         = 18,
        [19] = 'ATM2',       ATM2       = 19,
        [20] = 'SERIAL',     SERIAL     = 20
    },
    flags = {
         [0] = 'UNICAST',    UNICAST    =  0,
         [1] = 'BROADCAST',  BROADCAST  =  1
    }
}

local dhcp_packet_t = ffi.typeof("struct dhcp_packet")

local AF_INET = 2
local INET_ADDRSTRLEN = 16
local DHCP_MIN_SIZE = sizeof(dhcp_packet_t, 0)
local INET_BUF = ffi.new("char[?]", INET_ADDRSTRLEN)

local function inet_addr(ptr, addr)
    if addr then
        return C.inet_pton(AF_INET, addr, ptr)
    end

    ffi.fill(INET_BUF, INET_ADDRSTRLEN)
    if C.inet_ntop(AF_INET, ptr , INET_BUF, INET_ADDRSTRLEN) ~= nil then
        return (string.gsub(ffi.string(INET_BUF, INET_ADDRSTRLEN), "%z*$",""))
    end
end

local function _iaddr(ptr, what, addr)
    local _ptr = ffi.cast("uint8_t *", ptr[0]) + offsetof(dhcp_packet_t, what)

    return inet_addr(_ptr, addr)
end

ffi.metatype(dhcp_packet_t, { __index = {
    op = function(pkt, op)
        if op then
            if not dhcp.op[op] then
                return nil, "unknown op: "..op
            end
            pkt[0]._op = dhcp.op[op]
        else
            return dhcp.op[pkt._op]
        end
    end,
    htype = function(pkt, htype)
        if htype then
            pkt[0]._htype = dhcp.htype[htype]
        else
            return dhcp.htype[pkt._htype]
        end
    end,
    xid = function(pkt, xid)
        if xid then
            if type(xid) == "number" then
                pkt[0]._xid = C.htonl(xid)
            end
        else
            return C.ntohl(pkt._xid)
        end
    end,
    ciaddr = function(pkt, addr)
        return _iaddr(pkt, "_ciaddr", addr)
    end,
    yiaddr = function(pkt, addr)
        return _iaddr(pkt, "_yiaddr", addr)
    end,
    siaddr = function(pkt, addr)
        return _iaddr(pkt, "_siaddr", addr)
    end,
    giaddr = function(pkt, addr)
        return _iaddr(pkt, "_giaddr", addr)
    end,
    chaddr = function(pkt, chaddr)
        if chaddr then
            local i=0
            string.gsub(chaddr, "(..)[:%z]", function(x)
                pkt._chaddr[i] = tonumber(x, 16)
                i = i + 1
            end)
        end

        local chaddr = ffi.string(pkt._chaddr,6)
        return string.sub((string.gsub(chaddr, "(.)", function(x)
            return string.format("%02x", string.byte(x))..":"
        end)),1,-2)
    end,
    sname = function(pkt, sname)
        if sname then
            if #sname > 64 then
                return nil, "sname must not exceed 64 bytes"
            end
            ffi.fill(pkt._sname, 64)
            ffi.copy(pkt._sname, sname, #sname)
            return true
        end

        return (string.gsub(ffi.string(pkt._sname, 64), "%z.*",""))
    end,
    file = function(pkt, file)
        if file then
            if #file > 128 then
                return nil, "file must not exceed 128 bytes"
            end
            ffi.fill(pkt._file, 128)
            ffi.copy(pkt._file, file, #file)
        end
    end,
    options = function(pkt, options)
        if options then
            local len, err = pkt.__options:encode(pkt.__options_size, options)
            if not len then
                return nil, err
            end

            pkt.__options_length = len
            return len
        end

        return pkt.__options:decode(pkt.__options_size)
    end,
    data = function(pkt)
        local length = DHCP_MIN_SIZE + pkt.__options_length
        return ffi.string(pkt.__packet, length)
    end}
})

local _P = { _version = 0.1 }

_P.new = function(data, options_size)
    options_size = options_size or 308
    local packet = dhcp_packet_t(options_size)
    if not packet then
        return nil, "failed to allocate memory for packet"
    end

    if data then
        if #data > (DHCP_MIN_SIZE + options_size) then
            return nil, "packet too large"
        end
        ffi.copy(packet, data)
    end

    local _packet = ffi.cast("struct dhcp_packet *", packet)

    local options = options.new(_packet._options)
    local options_length

    if data then
        options_length = #data - DHCP_MIN_SIZE
    else
        options_length = 1
        options._options_ptr[0] = 255
    end

    local self = {
        __packet = packet,
        __options = options,
        __options_length = options_length,
        __options_size = options_size
    }

    return setmetatable(self, { __index = _packet })
end

return _P

-- vim: ts=4 sw=4 et ai
