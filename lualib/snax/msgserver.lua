local skynet = require "skynet"
local gateserver = require "snax.gateserver"
local crypt = require "skynet.crypt"
local socket = require "anysocket"
local assert = assert
local b64encode = crypt.base64encode
local b64decode = crypt.base64decode

--[[

Protocol:

	All the number type is big-endian

	Shakehands (The first package)

	Client -> Server :

	base64(uid)@base64(server)#base64(subid):index:base64(hmac)

	Server -> Client

	XXX ErrorCode
		405 Forbidden
		404 User Not Found
		403 Index Expired
		401 Unauthorized
		400 Bad Request
		200 OK

	Req-Resp

	Client -> Server : Request
		word size (Not include self)
		string content (size-4)
		dword session

	Server -> Client : Response
		word size (Not include self)
		string content (size-5)
		byte ok (1 is ok, 0 is error)
		dword session

API:
	server.userid(username)
		return uid, subid, server

	server.username(uid, subid, server)
		return username

	server.login(username, secret)
		update user secret

	server.logout(username)
		user logout

	server.ip(username)
		return ip when connection establish, or nil

	server.start(conf)
		start server

Supported skynet command:
	kick username (may used by loginserver)
	login username secret  (used by loginserver)
	logout username (used by agent)

Config for server.start:
	conf.expired_number : the number of the response message cached after sending out (default is 128)
	conf.login_handler(uid, secret) -> subid : the function when a new user login, alloc a subid for it. (may call by login server)
	conf.logout_handler(uid, subid) : the functon when a user logout. (may call by agent)
	conf.kick_handler(uid, subid) : the functon when a user logout. (may call by login server)
	conf.request_handler(username, session, msg) : the function when recv a new request.
	conf.register_handler(servername) : call when gate open
	conf.disconnect_handler(username) : call when a connection disconnect (afk)
]]

local server = {}

skynet.register_protocol {
	name = "client",
	id = skynet.PTYPE_CLIENT,
	--pack = skynet.pack
}

local user_online = {}
local handshake = {}
local connection = {}

function server.userid(username)
	-- base64(uid)@base64(server)#base64(subid)
	local uid, servername, subid = username:match "([^@]*)@([^#]*)#(.*)"
	return b64decode(uid), b64decode(subid), b64decode(servername)
end

function server.username(uid, subid, servername)
	return string.format("%s@%s#%s", b64encode(uid), b64encode(servername), b64encode(tostring(subid)))
end

function server.logout(username)
	local u = user_online[username]
	user_online[username] = nil

	local fd = u.fd
	if fd then
		gateserver.closeclient(fd)
		connection[fd] = nil
	end
end

function server.login(username, secret)
	print("server.login username=",username)
	local uid, subid, servername = server.userid(username)
	skynet.logi("uid=", uid, ";subid=", subid, ";servername=", servername)
	assert(user_online[username] == nil)
	user_online[username] = {
		secret = secret,
		version = 0,
		index = 0,
		username = username,
		response = {},	-- response cache
	}
end

function server.ip(username)
	local u = user_online[username]
	if u and u.fd then
		return u.ip
	end
end

function server.start(conf, protocol)
	socket.init(protocol)
	local expired_number = conf.expired_number or 128

	local handler = {}

	local CMD = {
		login = assert(conf.login_handler),
		logout = assert(conf.logout_handler),
		kick = assert(conf.kick_handler),
		send_push = assert(conf.send_push_handler)
	}

	function handler.command(cmd, _, ...)
		local f = assert(CMD[cmd])
		return f(...)
	end

	function handler.open(_, gateconf)
		local servername = assert(gateconf.servername)
		return conf.register_handler(servername)
	end

	function handler.connect(fd, addr)
		handshake[fd] = addr
		-- gateserver.openclient(fd)
	end

	function handler.disconnect(fd)
		handshake[fd] = nil
		local c = connection[fd]
		if c then
			c.fd = nil
			connection[fd] = nil
			if conf.disconnect_handler then
				conf.disconnect_handler(c.username)
			end
		end
	end

	handler.error = handler.disconnect

	-- atomic , no yield
	local function do_auth(fd, message, addr)
		local username, index, hmac = string.match(message, "([^:]*):([^:]*)")

		local u = user_online[username]
		if u == nil then
			local uid, subid, servername =  server.userid(username)
			skynet.loge("uid=", uid, ";subid=", subid, ";servernam=", servername)
			return "404 User Not Found "
		end
		local idx = assert(tonumber(index))

		if idx <= u.version then
			return "403 Index Expired"
		end
		print("wsmsgserver.lua 8")
		local text = string.format("%s:%s", username, index)
		if not (protocol == "ws" or protocol == "wss") then
			hmac = b64decode(hmac)
			local v = crypt.hmac_hash(u.secret, text)	-- equivalent to crypt.hmac64(crypt.hashkey(text), u.secret)
			if v ~= hmac then
				return "401 Unauthorized"
			end
		end

		local forbidTime = conf.create_msgagent_handler(username, fd)
		if forbidTime then
			return "Fail|" .. tostring(forbidTime)
		end
		u.version = idx
		u.fd = fd
		u.ip = addr
		connection[fd] = u
	end

	local function auth(fd, addr, msg)
		print("wsmsgserver.lua 1")
		local ok, result = pcall(do_auth, fd, msg, addr)
		print("ok=", ok, "result=", result)
		if not ok then
			skynet.loge(result)
			result = "400 Bad Request"
		end
		print("wsmsgserver.lua 2")
		local close = result ~= nil

		if result == nil then
			result = "200 OK"
		end
		print("wsmsgserver.lua 3")
		socket.send(fd, result)
		print("wsmsgserver.lua 4")
		if close then
			gateserver.closeclient(fd)
		end
	end

	local request_handler = assert(conf.request_handler)

	-- u.response is a struct { return_fd , response, version, index }
	local function retire_response(u)
		if u.index >= expired_number * 2 then
			local max = 0
			local response = u.response
			for k,p in pairs(response) do
				if p[1] == nil then
					-- request complete, check expired
					if p[4] < expired_number then
						response[k] = nil
					else
						p[4] = p[4] - expired_number
						if p[4] > max then
							max = p[4]
						end
					end
				end
			end
			u.index = max + 1
		end
	end

	local function do_request(fd, message)
		local u = assert(connection[fd], "invalid fd")

		pcall(conf.request_handler, u.username, message)
	end

	local function request(fd, msg, sz)
		local ok, err = pcall(do_request, fd, msg)
		-- not atomic, may yield
		if not ok then
			skynet.error(string.format("Invalid package %s : %s", err, msg))
			if connection[fd] then
				gateserver.closeclient(fd)
			end
		end
	end

	function handler.message(fd, msg)
		local addr = handshake[fd]
		--print("wsmsgserver.lua ",fd,msg,addr)
		if addr then
			auth(fd,addr,msg)
			handshake[fd] = nil
		else
			request(fd, msg)
		end
	end

	function handler.close(fd, code, reason)
		skynet.logi("fd =>", fd, "close;code =>", code, ";reason =>", reason)
	end

	return gateserver.start(handler, protocol)
end

return server
