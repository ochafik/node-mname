/*
 * Copyright (c) 2018, Joyent, Inc
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

var assert = require('assert-plus');
var util = require('util');
var stream = require('stream');


var FRAME_TYPE_CLIENT_HELLO = 1;
var FRAME_TYPE_INBOUND_UDP = 2;
var FRAME_TYPE_INBOUND_TCP = 3;
var FRAME_TYPE_CLIENT_HEARTBEAT = 4;
var FRAME_TYPE_SERVER_HELLO = 1001;
var FRAME_TYPE_OUTBOUND_UDP = 1002;
var FRAME_TYPE_INBOUND_TCP_OK = 1003;
var FRAME_TYPE_SERVER_HEARTBEAT = 1004;

var SIZE_U32 = 4;


function BalancerTransform(opts) {
        var self = this;

        stream.Transform.call(self);

        self.bal_accum = new Buffer(0);
        self.bal_tcp = null;
        self.bal_hello = false;
        self.bal_log = opts.log;
        self.bal_sock = opts.sock;
}
util.inherits(BalancerTransform, stream.Transform);

BalancerTransform.prototype.discard = function (n) {
        var self = this;

        self.bal_accum = self.bal_accum.slice(n);
};

BalancerTransform.prototype.avail = function (n) {
        var self = this;

        return (self.bal_accum.length >= n);
};

/*
 * Read a little endian uint32_t from a four byte aligned offset into the
 * buffer.
 */
BalancerTransform.prototype.readU32 = function (offs) {
        var self = this;

        return (self.bal_accum.readUInt32LE(offs * SIZE_U32));
};

/*
 * Read a little endian IPv4 address from a four byte aligned offset into the
 * buffer.
 */
BalancerTransform.prototype.readIPv4 = function (offs) {
        var self = this;

        var ipaddr = [
                self.bal_accum.readUInt8(offs * SIZE_U32 + 3),
                self.bal_accum.readUInt8(offs * SIZE_U32 + 2),
                self.bal_accum.readUInt8(offs * SIZE_U32 + 1),
                self.bal_accum.readUInt8(offs * SIZE_U32 + 0)
        ].join('.');

        return (ipaddr);
};

BalancerTransform.prototype._transform = function (o, _, done) {
        var self = this;
        var sock = self.bal_sock;
        var log = self.bal_log;

        if (self.bal_tcp !== null) {
                /*
                 * We are piped to the emulated TCP stream, so just pass on
                 * buffers as we get them.
                 */
                self.push(o);
                setImmediate(done);
                return;
        }

        self.bal_accum = Buffer.concat([ self.bal_accum, o ],
            self.bal_accum.length + o.length);

        while (self.avail(SIZE_U32)) {
                /*
                 * Read frame type.
                 */
                var frame_type = self.readU32(0);
                var out, ipaddr, port;

                if (frame_type === FRAME_TYPE_CLIENT_HELLO) {
                        self.discard(SIZE_U32);
                        self.bal_hello = true;

                        /*
                         * A CLIENT_HELLO frame requires a SERVER_HELLO
                         * response.
                         */
                        out = new Buffer(SIZE_U32);
                        out.writeUInt32LE(FRAME_TYPE_SERVER_HELLO, 0);
                        sock.write(out);
                        continue;
                }

                if (frame_type === FRAME_TYPE_INBOUND_TCP) {
                        /*
                         * This frame signals a request to convert this session
                         * to a TCP proxy session.
                         */
                        if (!self.avail(3 * SIZE_U32)) {
                                /*
                                 * Wait for the entire frame to arrive.
                                 */
                                break;
                        }

                        ipaddr = self.readIPv4(1);
                        port = self.readU32(2);

                        log.info('backend TCP connection: ' +
                            'remote peer %s:%d', ipaddr, port);

                        /*
                         * Send acknowledgement to the balancer that this is
                         * now a proxied TCP stream.
                         */
                        out = new Buffer(SIZE_U32);
                        out.writeUInt32LE(FRAME_TYPE_INBOUND_TCP_OK, 0);
                        sock.write(out);

                        sock.on('timeout', function () {
                                self.emit('timeout');
                        });
                        sock.on('error', function (err) {
                                self.emit('err', err);
                        });

                        /*
                         * Dress this Transform up as if it were a regular TCP
                         * connection from a DNS client.
                         */
                        var tcp = Object.create(self);

                        tcp.remoteAddress = ipaddr;
                        tcp.remotePort = port;
                        tcp.setTimeout = sock.setTimeout.bind(sock);
                        tcp.end = sock.end.bind(sock);
                        tcp.destroy = sock.destroy.bind(sock);
                        tcp.write = sock.write.bind(sock);

                        self.bal_tcp = tcp;
                        self.emit('inbound_tcp', tcp);

                        /*
                         * Push any remaining data after the frame header into
                         * the emulated TCP stream.
                         */
                        self.discard(3 * SIZE_U32);
                        self.push(self.bal_accum);
                        self.bal_accum = null;

                        setImmediate(done);
                        return;
                }

                if (!self.bal_hello) {
                        log.warn('frame type %d before HELLO', frame_type);
                        sock.destroy();
                        return;
                }

                if (frame_type === FRAME_TYPE_CLIENT_HEARTBEAT) {
                        self.discard(SIZE_U32);

                        /*
                         * The balancer expects a prompt reply for each
                         * heartbeat frame.
                         */
                        out = new Buffer(SIZE_U32);
                        out.writeUInt32LE(FRAME_TYPE_SERVER_HEARTBEAT, 0);
                        sock.write(out);
                        continue;
                }

                /*
                 * All other frame types have been processed already.  At this
                 * point, the frame _must_ be an inbound UDP packet.
                 */
                if (frame_type !== FRAME_TYPE_INBOUND_UDP) {
                        log.warn('frame type %d invalid', frame_type);
                        sock.destroy();
                        return;
                }

                var headerlen = 4 * SIZE_U32;
                if (!self.avail(headerlen)) {
                        /*
                         * The complete header has not yet arrived.
                         */
                        break;
                }

                ipaddr = self.readIPv4(1);
                port = self.readU32(2);
                var datalen = self.readU32(3);

                if (!self.avail(headerlen + datalen)) {
                        /*
                         * Entire frame has not yet arrived.
                         */
                        break;
                }

                log.trace('balancer packet: %s:%d (len %d)', ipaddr, port,
                    datalen);

                var rinfo = { address: ipaddr, port: port };

                self.emit('inbound_udp', rinfo,
                    self.bal_accum.slice(headerlen, headerlen + datalen),
                    function reply(buf, from, len, sendport, addr, cb) {
                        assert.equal(from, 0);
                        assert.equal(len, buf.length);

                        var hdr = new Buffer(4 * SIZE_U32);
                        hdr.writeUInt32LE(FRAME_TYPE_OUTBOUND_UDP, 0);

                        var octs = addr.split('.');
                        hdr.writeUInt8(octs[3], 1 * SIZE_U32 + 0);
                        hdr.writeUInt8(octs[2], 1 * SIZE_U32 + 1);
                        hdr.writeUInt8(octs[1], 1 * SIZE_U32 + 2);
                        hdr.writeUInt8(octs[0], 1 * SIZE_U32 + 3);

                        hdr.writeUInt32LE(sendport, 2 * SIZE_U32);
                        hdr.writeUInt32LE(len, 3 * SIZE_U32);

                        sock.write(hdr);
                        sock.write(buf);

                        setImmediate(cb);
                });

                self.discard(headerlen + datalen);
        }

        setImmediate(done);
};


function wrapBalancerConnection(opts) {
        var log = opts.log;
        var sock = opts.sock;

        var t = new BalancerTransform({ log: log, sock: sock });

        sock.pipe(t);

        sock.on('end', function () {
                log.warn('balancer ended connection');
        });
        sock.on('error', function (err) {
                log.warn(err, 'error on balancer connection');
                sock.destroy();
        });
        sock.on('close', function () {
                log.trace('balancer socket closed');
        });

        return (t);
}

module.exports = {
        wrapBalancerConnection: wrapBalancerConnection
};
