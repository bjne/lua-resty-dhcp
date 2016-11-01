local ffi = require "ffi"

local C = ffi.C
local gsub = string.gsub
local lower = string.lower

ffi.cdef[[
typedef uint8_t socklen_t;

int inet_pton(int af, const char *src, void *dst);
const char *inet_ntop(int af, const void *src, char *dst, socklen_t size);

uint16_t ntohs(uint16_t netshort);
uint16_t htons(uint16_t hostshort);

uint32_t ntohl (uint32_t __netlong);
uint32_t htonl (uint32_t __hostlong);
]]

local N = 'N'
local _options = {
      [0] = { type='pad',    len=0, name='Pad',                      rfc=2132 },
      [1] = { type='inet',   len=4, name='Subnet Mask',              rfc=2132 },
      [2] = { type='void',   len=4, name='Time Offset',              rfc=2132 },
      [3] = { type='inet',   len=N, name='Router',                   rfc=2132 },
      [4] = { type='inet',   len=N, name='Time Server',              rfc=2132 },
      [5] = { type='inet',   len=N, name='Name Server',              rfc=2132 },
      [6] = { type='inet',   len=N, name='Domain Server',            rfc=2132 },
      [7] = { type='inet',   len=N, name='Log Server',               rfc=2132 },
      [8] = { type='inet',   len=N, name='Quotes Server',            rfc=2132 },
      [9] = { type='void',   len=N, name='LPR Server',               rfc=2132 },
     [10] = { type='void',   len=N, name='Impress Server',           rfc=2132 },
     [11] = { type='void',   len=N, name='RLP Server',               rfc=2132 },
     [12] = { type='string', len=N, name='Hostname',                 rfc=2132 },
     [13] = { type='uint16', len=2, name='Boot File Size',           rfc=2132 },
     [14] = { type='void',   len=N, name='Merit Dump File',          rfc=2132 },
     [15] = { type='string', len=N, name='Domain Name',              rfc=2132 },
     [16] = { type='void',   len=N, name='Swap Server',              rfc=2132 },
     [17] = { type='void',   len=N, name='Root Path',                rfc=2132 },
     [18] = { type='void',   len=N, name='Extension File',           rfc=2132 },
     [19] = { type='void',   len=1, name='Forward On/Off',           rfc=2132 },
     [20] = { type='void',   len=1, name='SrcRte On/Off',            rfc=2132 },
     [21] = { type='void',   len=N, name='Policy Filter',            rfc=2132 },
     [22] = { type='void',   len=2, name='Max DG Assembly',          rfc=2132 },
     [23] = { type='void',   len=1, name='Default IP TTL',           rfc=2132 },
     [24] = { type='void',   len=4, name='MTU Timeout',              rfc=2132 },
     [25] = { type='void',   len=N, name='MTU Plateau',              rfc=2132 },
     [26] = { type='uint16', len=2, name='MTU Interface',            rfc=2132 },
     [27] = { type='void',   len=1, name='MTU Subnet',               rfc=2132 },
     [28] = { type='inet',   len=4, name='Broadcast Address',        rfc=2132 },
     [29] = { type='void',   len=1, name='Mask Discovery',           rfc=2132 },
     [30] = { type='void',   len=1, name='Mask Supplier',            rfc=2132 },
     [31] = { type='void',   len=1, name='Router Discovery',         rfc=2132 },
     [32] = { type='inet',   len=4, name='Router Request',           rfc=2132 },
     [33] = { type='void',   len=N, name='Static Route',             rfc=2132 },
     [34] = { type='void',   len=1, name='Trailers',                 rfc=2132 },
     [35] = { type='uint32', len=4, name='ARP Timeout',              rfc=2132 },
     [36] = { type='void',   len=1, name='Ethernet',                 rfc=2132 },
     [37] = { type='void',   len=1, name='Default TCP TTL',          rfc=2132 },
     [38] = { type='uint32', len=4, name='Keepalive Time',           rfc=2132 },
     [39] = { type='void',   len=1, name='Keepalive Data',           rfc=2132 },
     [40] = { type='void',   len=N, name='NIS Domain',               rfc=2132 },
     [41] = { type='void',   len=N, name='NIS Servers',              rfc=2132 },
     [42] = { type='void',   len=N, name='NTP Servers',              rfc=2132 },
     [43] = { type='void',   len=N, name='Vendor Specific',          rfc=2132 },
     [44] = { type='void',   len=N, name='NETBIOS Name Srv',         rfc=2132 },
     [45] = { type='void',   len=N, name='NETBIOS Dist Srv',         rfc=2132 },
     [46] = { type='void',   len=1, name='NETBIOS Node Type',        rfc=2132 },
     [47] = { type='void',   len=N, name='NETBIOS Scope',            rfc=2132 },
     [48] = { type='void',   len=N, name='X Window Font',            rfc=2132 },
     [49] = { type='void',   len=N, name='X Window Manager',         rfc=2132 },
     [50] = { type='inet',   len=4, name='Address Request',          rfc=2132 },
     [51] = { type='uint32', len=4, name='Address Lease Time',       rfc=2132 },
     [52] = { type='void',   len=1, name='Overload',                 rfc=2132 },
     [53] = { type='mtype',  len=1, name='DHCP Msg Type',            rfc=2132 },
     [54] = { type='inet',   len=4, name='DHCP Server Id',           rfc=2132 },
     [55] = { type='plist',  len=N, name='Parameter List',           rfc=2132 },
     [56] = { type='void',   len=N, name='DHCP Message',             rfc=2132 },
     [57] = { type='void',   len=2, name='DHCP Max Msg Size',        rfc=2132 },
     [58] = { type='uint32', len=4, name='Renewal Time',             rfc=2132 },
     [59] = { type='uint32', len=4, name='Rebinding Time',           rfc=2132 },
     [60] = { type='void',   len=N, name='Class Id',                 rfc=2132 },
     [61] = { type='void',   len=N, name='Client Id',                rfc=2132 },
     [62] = { type='void',   len=N, name='NetWare/IP Domain',        rfc=2242 },
     [63] = { type='void',   len=N, name='NetWare/IP',               rfc=2242 },
     [64] = { type='void',   len=N, name='NIS-Domain-Name',          rfc=2132 },
     [65] = { type='void',   len=N, name='NIS-Server-Addr',          rfc=2132 },
     [66] = { type='void',   len=N, name='Server-Name',              rfc=2132 },
     [67] = { type='void',   len=N, name='Bootfile-Name',            rfc=2132 },
     [68] = { type='void',   len=N, name='Home-Agent-Addrs',         rfc=2132 },
     [69] = { type='void',   len=N, name='SMTP-Server',              rfc=2132 },
     [70] = { type='void',   len=N, name='POP3-Server',              rfc=2132 },
     [71] = { type='void',   len=N, name='NNTP-Server',              rfc=2132 },
     [72] = { type='void',   len=N, name='WWW-Server',               rfc=2132 },
     [73] = { type='void',   len=N, name='Finger-Server',            rfc=2132 },
     [74] = { type='void',   len=N, name='IRC-Server',               rfc=2132 },
     [75] = { type='void',   len=N, name='StreetTalk-Server',        rfc=2132 },
     [76] = { type='void',   len=N, name='STDA-Server',              rfc=2132 },
     [77] = { type='string', len=N, name='User-Class',               rfc=3004 },
     [78] = { type='void',   len=N, name='Directory Agent',          rfc=2610 },
     [79] = { type='void',   len=N, name='Service Scope',            rfc=2610 },
     [80] = { type='void',   len=0, name='Rapid Commit',             rfc=4039 },
     [81] = { type='void',   len=N, name='Client FQDN',              rfc=4702 },
     [82] = { type='void',   len=N, name='Relay Agent Information',  rfc=3046 },
     [83] = { type='void',   len=N, name='iSNS',                     rfc=4174 },
     [85] = { type='void',   len=N, name='NDS Servers',              rfc=2241 },
     [86] = { type='void',   len=N, name='NDS Tree Name',            rfc=2241 },
     [87] = { type='void',   len=N, name='NDS Context',              rfc=2241 },
     [90] = { type='void',   len=N, name='Authentication',           rfc=3118 },
     [93] = { type='void',   len=N, name='Client System',            rfc=4578 },
     [94] = { type='void',   len=N, name='Client NDI',               rfc=4578 },
     [95] = { type='void',   len=N, name='LDAP',                     rfc=3679 },
     [97] = { type='void',   len=N, name='UUID/GUID',                rfc=4578 },
     [98] = { type='void',   len=N, name='User-Auth',                rfc=2485 },
    [100] = { type='void',   len=N, name='PCode',                    rfc=4833 },
    [101] = { type='void',   len=N, name='TCode',                    rfc=4833 },
    [112] = { type='void',   len=N, name='Netinfo Address',          rfc=3679 },
    [113] = { type='void',   len=N, name='Netinfo Tag',              rfc=3679 },
    [114] = { type='void',   len=N, name='URL',                      rfc=3679 },
    [116] = { type='void',   len=N, name='Auto-Config',              rfc=2563 },
    [117] = { type='void',   len=N, name='Name Service Search',      rfc=2937 },
    [118] = { type='inet',   len=4, name='Subnet Selection',         rfc=3011 },
    [119] = { type='void',   len=N, name='Domain Search',            rfc=3397 },
    [120] = { type='void',   len=N, name='SIP Servers DHCP',         rfc=3361 },
    [121] = { type='void',   len=N, name='Classless Static Route',   rfc=3442 },
    [122] = { type='void',   len=N, name='CCC',                      rfc=3495 },
    [123] = { type='void',   len=1, name='GeoConf',                  rfc=6225 },
    [175] = { type='ipxe',   len=1, name='iPXE',                     rfc=0000 },
    [209] = { type='void',   len=N, name='Configuration File',       rfc=5071 },
    [210] = { type='void',   len=N, name='Path Prefix',              rfc=5071 },
    [211] = { type='void',   len=4, name='Reboot Time',              rfc=5071 },
    [220] = { type='void',   len=N, name='Subnet Allocation',        rfc=6656 },
    [255] = { type='end',    len=0, name='End',                      rfc=2132 }
}

local _ipxe_options = {
      [1] = { type='int8',   len=1, name='Priority'            },
      [8] = { type='uint8',  len=1, name='Keep SAN'            },
      [9] = { type='uint8',  len=1, name='SAN Boot'            },
     [85] = { type='string', len=N, name='Syslog'              },
     [91] = { type='string', len=N, name='Cert'                },
     [92] = { type='string', len=N, name='Privkey'             },
     [93] = { type='string', len=N, name='CrossCert'           },
    [176] = { type='uint8',  len=1, name='No ProxyDHCP'        },
    [177] = { type='string', len=N, name='Bus ID'              },
    [189] = { type='string', len=N, name='BIOS Drive'          },
    [190] = { type='string', len=N, name='Username'            },
    [191] = { type='string', len=N, name='Password'            },
    [192] = { type='string', len=N, name='Reverse Username'    },
    [193] = { type='string', len=N, name='Reverse Password'    },
    [203] = { type='string', len=N, name='iSCSI Initiator IQN' },
    [235] = { type='string', len=N, name='Version'             },
    [255] = { type='end',    len=0, name='Option List End'     },
--[[
        feature indicators
--]]
     [16] = { type='uint8',  len=1, name='PXE Extension'       },
     [17] = { type='uint8',  len=1, name='iSCSI'               },
     [18] = { type='uint8',  len=1, name='AoE'                 },
     [19] = { type='uint8',  len=1, name='HTTP'                },
     [20] = { type='uint8',  len=1, name='HTTPS'               },
     [21] = { type='uint8',  len=1, name='TFTP'                },
     [22] = { type='uint8',  len=1, name='FTP'                 },
     [23] = { type='uint8',  len=1, name='DNS'                 },
     [24] = { type='uint8',  len=1, name='bzImage'             },
     [25] = { type='uint8',  len=1, name='MultiBoot'           },
     [26] = { type='uint8',  len=1, name='SLAM'                },
     [27] = { type='uint8',  len=1, name='SLP'                 },
     [32] = { type='uint8',  len=1, name='NBI'                 },
     [33] = { type='uint8',  len=1, name='PXE'                 },
     [34] = { type='uint8',  len=1, name='ELF'                 },
     [35] = { type='uint8',  len=1, name='COMBOOT'             },
     [36] = { type='uint8',  len=1, name='EFI'                 },
     [37] = { type='uint8',  len=1, name='FCoE'                },
     [38] = { type='uint8',  len=1, name='VLAN'                },
     [39] = { type='uint8',  len=1, name='MENU'                },
     [40] = { type='uint8',  len=1, name='SDI'                 },
     [41] = { type='uint8',  len=1, name='NFS'                 },
}

local msg_type = {
    [1] = 'DISCOVER',   DISCOVER   =  1,
    [2] = 'OFFER',      OFFER      =  2,
    [3] = 'REQUEST',    REQUEST    =  3,
    [4] = 'DECLINE',    DECLINE    =  4,
    [5] = 'ACK',        ACK        =  5,
    [6] = 'NAK',        NAK        =  6,
    [7] = 'RELEASE',    RELEASE    =  7,
    [8] = 'INFORM',     INFORM     =  8
}

local function _key(key)
    return lower(gsub(key, "[ -]", "_"))
end

local mt = { __index = function(self, key)
    key = _key(key)

    local value = rawget(self, key)
    if value then
        return value
    end

    for k,v in pairs(self) do
        if type(v) ~= "function" then
            name = _key(v.name)
            if key == name then
                v.tag = k
                self[key] = v
                return self[key]
            end
        end
    end
end}

local options_mt = { __index = function(self, key)
    key = _key(key)

    local value = rawget(self, key)
    if value then
        return value
    end

    for k,v in pairs(self) do
        k = _key(k)
        if k == key then
            return v
        end
    end
end}

setmetatable(_options, mt)
setmetatable(_ipxe_options, mt)

local AF_INET = 2
local INET_ADDRSTRLEN = 16
local INET_BUF = ffi.new("char[?]", INET_ADDRSTRLEN)
local _do_type

local function inet_addr(ptr, addr)
    if addr then
        return C.inet_pton(AF_INET, addr, ptr)
    end

    ffi.fill(INET_BUF, INET_ADDRSTRLEN)
    if C.inet_ntop(AF_INET, ptr , INET_BUF, INET_ADDRSTRLEN) ~= nil then
        return (gsub(ffi.string(INET_BUF, INET_ADDRSTRLEN), "%z*$", ""))
    end
end

local _O = { options = _options }

local encode = function(ptr, len, valid_options, options)
    local eom = ptr + len
    local total_length = 0
    for option, value in pairs(options) do
        local o = valid_options[option]

        if not o then
            return nil, "unknown option: "..option
        end

        if not _do_type[o.type] then
            return nil, "no encoder for: "..o.type
        end

        local len, err = _do_type[o.type](ptr + 2, eom - ptr - 2 , value)
        if not len then
            return nil, err
        end

        ptr[0] = o.tag
        ptr[1] = len
        ptr = ptr + 1 + 1 + len
        total_length = total_length + 1 + 1 + len
    end

    ptr[0] = 255
    return total_length + 1
end

local decode = function(ptr, len, valid_options)
    local eom = ptr + len
    local options = {}

    while true do
        if ptr > eom then
            break
        end

        local option = valid_options[ptr[0]]

        if not option then
            return nil, "unknown option: "..ptr[0]
        end

        if option.type == "end" then
            break
        end

        if option.len == N or option.len > 0 then
            if ptr + 1 > eom then
                return nil, "EOM reached after option"
            end

            local len = ptr[1]
            if ptr + 1 + 1 + len >= eom then
                return nil, "EOM reached after length"
            end

            if not _do_type[option.type] then
                return nil, "no decoder for: "..option.type
            end

            options[option.name] = _do_type[option.type](ptr + 2, len)
            ptr = ptr + 1 + 1 + len
        else
            ptr = ptr + 1
        end
    end

    return setmetatable(options, options_mt)
end

_do_type = {
    uint8 = function(ptr, len, value)
        if value then
            ptr[0] = value
            return 1
        end

        return ptr[0]
    end,
    uint16 = function(ptr, len, value)
        ptr = ffi.cast("uint16_t *", ptr)
        if value then
            ptr[0] = C.htons(value)
            return 4
        end

        return C.ntohs(ptr[0])
    end,
    uint32 = function(ptr, len, value)
        ptr = ffi.cast("uint32_t *", ptr)
        if value then
            ptr[0] = C.htonl(value)
            return 4
        end

        return C.ntohl(ptr[0])
    end,
    plist = function(ptr, len, value)
        if value then
            return nil, "plist encoding currently unsupported"
        end

        local list = {}
        for i=0,len-1 do
            local option = _options[ptr[i]]
            if not option then
                return nil, "unknown list option: "..ptr[i]
            end

            list[option.name] = option
        end
        return list
    end,
    mtype = function(ptr, len, value)
        if value then
            if not msg_type[value] then
                return nil, "unknown msg type: "..value
            end

            ptr[0] = msg_type[value]
            return 1
        end

        return msg_type[ptr[0]]
    end,
    string = function(ptr, len, value)
        if value then
            if #value > len then
                return nil, "not enough room"
            end

            ffi.copy(ptr, value, #value)
            return #value
        end

        return ffi.string(ptr, len)
    end,
    inet = function(ptr, len, value)
        if value then
            if type(value) ~= "table" then
                value = { value }
            end

            for i=1,#value do
                inet_addr(ptr + (i-1)*4, value[i])
            end

            return #value * 4
        end

        if len == 4 then
            return inet_addr(ptr)
        else
            local t = {}
            for i=0,len-1,4 do
                table.insert(t, inet_addr(ptr + i))
            end
            return t
        end
    end,
    ipxe = function(ptr, len, value)
        if value then
            return encode(ptr, len, _ipxe_options, value)
        end

        return decode(ptr, len, _ipxe_options)
    end
}

_O.encode = function(self, len, options)
    options = options or {}

    return encode(self.options_ptr, len, _options, options)
end

_O.decode = function(self, len)
    return decode(self.options_ptr, len, _options)
end

local _M = { _version = 0.1 }

_M.new = function(options_ptr)
    return setmetatable({ options_ptr = options_ptr }, { __index = _O })
end

return _M

-- vim: ts=4 sw=4 et ai
