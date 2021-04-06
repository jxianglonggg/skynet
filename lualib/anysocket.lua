local skynet = require "skynet"
local socketdriver = require "skynet.socketdriver"
local websocket = require "http.websocket"
local netpack = require "skynet.netpack"
local socket = require "skynet.socket"
local M = {}
local queue
local listen_socket

local function send_tcp(fd, result)
    socketdriver.send(fd, netpack.pack(result))
end

local function send_websocket(fd, result, form)
    websocket.write(fd, result, form)
end

local function tostring_tcp(msg)
    return netpack.tostring(msg)
end

local function tostring_websocket(msg)
    return msg
end

local function listen_tcp(address, port, MSG)
    MSG.close_ = MSG.close
    MSG.error_ = MSG.error
    MSG.close = function (fd)
		if fd ~= listen_socket then
            MSG.close_()
		else
			listen_socket = nil
		end
	end

	MSG.error = function (fd, msg)
		if fd == listen_socket then
			skynet.error("listen accpet error:",msg)
		else
			MSG.error_(fd, msg)
		end
	end

    local function dispatch_msg(fd, msg, sz)
        local message = netpack.tostring(msg, sz)
        MSG.message(fd, message)
	end

	MSG.data = dispatch_msg

	local function dispatch_queue()
		local fd, msg, sz = netpack.pop(queue)
		if fd then
			-- may dispatch even the handler.message blocked
			-- If the handler.message never block, the queue should be empty, so only fork once and then exit.
			skynet.fork(dispatch_queue)
			dispatch_msg(fd, msg, sz)

			for fd, msg, sz in netpack.pop, queue do
				dispatch_msg(fd, msg, sz)
			end
		end
	end

	MSG.more = dispatch_queue

    assert(not listen_socket)
    listen_socket = socketdriver.listen(address, port)
    socketdriver.start(listen_socket)
    skynet.register_protocol {
		name = "socket",
		id = skynet.PTYPE_SOCKET,	-- PTYPE_SOCKET = 6
		unpack = function ( msg, sz )
			return netpack.filter( queue, msg, sz)
		end,
		dispatch = function (_, _, q, type, ...)
			queue = q
			if type then
				MSG[type](...)
			end
		end
	}
    return listen_socket
end

local function listen_websocket(address, port, MSG)
    print("address=", address, ";port=", port, ";MSG=", MSG)
    MSG.connect = function(fd)
        local msg = websocket.addrinfo(fd)
        MSG.open(fd, msg)
    end
    MSG.handshake = function (fd, header, url)
	    local addr = websocket.addrinfo(fd)
	    print("ws handshake from: " .. tostring(fd), "url", url, "addr:", addr)
	    print("----header-----")
	    for k,v in pairs(header) do
	        print(k,v)
	    end
	    print("--------------")
	end
    assert(not listen_socket)
    listen_socket = socket.listen(address, port)
    socket.start(listen_socket, function(fd, addr)
        websocket.accept(fd, MSG, M.protocol, addr)
    end)
    return listen_socket
end

local function close_tcp(sock)
    assert(sock)
    socketdriver.close(sock)
end

local function close_websocket(sock)
    websocket.close(sock)
end

local function start_tcp(fd)
    socketdriver.start(fd)
end

local function start_websocket(fd, addr)
    websocket.accept(fd, nil, M.protocol,addr)
end

local function readline_tcp(fd)
    return socket.readline(fd)
end

local function readline_websocket(fd)
    return websocket.read(fd)
end

function M.is_websocket()
    return M.protocol == "ws" or M.protocol == "wss"
end

function M.nodelay(fd)
    socketdriver.nodelay(fd)
end

function M.init(protocol)
    M.protocol = protocol
    if M.is_websocket() then
        M.send = send_websocket
        M.tostring = tostring_websocket
        M.listen = listen_websocket
        M.close = close_websocket
        M.start = start_websocket
        M.readline = readline_websocket
    else
        M.send = send_tcp
        M.tostring = tostring_tcp
        M.listen = listen_tcp
        M.close = close_tcp
        M.start = start_tcp
        M.readline = readline_tcp
    end
end

return M