/*
 * Copyright (c) 2015 Trevor Orsztynowicz
 * Copyright (c) 2015 Joyent, Inc
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
var named = require('../lib');

var dig = require('./dig');

if (require.cache[__dirname + '/helper.js'])
        delete require.cache[__dirname + '/helper.js']
var helper = require('./helper');


///--- Globals

var test = helper.test;
var before = helper.before;
var after = helper.after;

var options = {port: 9999, server: '::1'};



///--- Tests

before(function (callback) {
        this.server = named.createServer({
                log: helper.getLog('server')
        });

        this.server.on('query', function (query, cb) {
                var domain = query.name()
                var type = query.type();

                switch (type) {
                case 'A':
                        var record = new named.ARecord('127.0.0.1');
                        query.addAnswer(domain, record);
                        break;
                case 'AAAA':
                        var record = new named.AAAARecord('::1');
                        query.addAnswer(domain, record);
                        break;
                case 'CAA':
                        var record = new named.CAARecord('issue', 'issuer.org', {flags: 1});
                        query.addAnswer(domain, record);
                        break;
                case 'CNAME':
                        var record = new named.CNAMERecord('cname.example.com');
                        query.addAnswer(domain, record);
                        break;
                case 'NS':
                        var record = new named.NSRecord('ns.example.com');
                        query.addAnswer(domain, record);
                        break;
                case 'MX':
                        var record = new named.MXRecord('smtp.example.com');
                        query.addAnswer(domain, record);
                        break;
                case 'SOA':
                        var record = new named.SOARecord('example.com');
                        query.addAnswer(domain, record);
                        break;
                case 'SRV':
                        var record = new named.SRVRecord('sip.example.com', 5060);
                        query.addAnswer(domain, record);
                        break;
                case 'TXT':
                        var record = new named.TXTRecord('hello world');
                        query.addAnswer(domain, record);
                        break;
                }
                query.respond();
                cb();
        });

        this.server.listen(options.port, options.server, function() {
                process.nextTick(callback);
        });
});


after(function (callback) {
        this.server.close(callback);
});


test('listen and close (port only)', function (t) {
        // don't conflict with the server made in 'before'
        var server = named.createServer();
        server.listen(1153, function () {
                process.nextTick(function () {
                        server.close(function () {
                                t.end();
                        })
                });
        });
});


test('listen and close (port and ::1)', function(t) {
        var server = named.createServer();
        server.listen(String(1153), '::1', function() {
                process.nextTick(function () {
                        server.close(function () {
                                t.end();
                        })
                });
        });
});


test('answer query: example.com (A)', function (t) {
        dig('example.com', 'A', options, function (err, results) {
                t.ifError(err);
                t.deepEqual(results.answers, [{
                        name: 'example.com.',
                        ttl: 5, type: 'A',
                        target: '127.0.0.1'
                }]);
                t.end();
        });
});


test('answer query: example.com (AAAA)', function (t) {
        dig('example.com', 'AAAA', options, function (err, results) {
                t.ifError(err);
                t.deepEqual(results.answers, [{
                        name: 'example.com.',
                        ttl: 5, type: 'AAAA',
                        target: '::1'
                }]);
                t.end();
        });
});


test('answer query: example.com (CAA)', function (t) {
        dig('example.com', 'CAA', options, function (err, results) {
                t.ifError(err);
                t.deepEqual(results.answers, [{
                        name: 'example.com.',
                        ttl: 5, type: 'CAA',
                        tag: 'issue',
                        value: 'issuer.org',
                        flags: 1,
                }]);
                t.end();
        });
});


test('answer query: example.com (CNAME)', function (t) {
        dig('www.example.com', 'CNAME', options, function (err, results) {
                t.ifError(err);
                t.deepEqual(results.answers, [{
                        name: 'www.example.com.',
                        ttl: 5,
                        type: 'CNAME',
                        target: 'cname.example.com.'
                }]);
                t.end();
        });
});

test('answer query: example.com (NS)', function (t) {
        dig('example.com', 'NS', options, function (err, results) {
                t.ifError(err);
                t.deepEqual(results.answers, [{
                        name: 'example.com.',
                        ttl: 5,
                        type: 'NS',
                        target: 'ns.example.com.'
                }]);
                t.end();
        });
});


test('answer query: example.com (MX)', function (t) {
        dig('example.com', 'MX', options, function (err, results) {
                t.ifError(err);
                t.deepEqual(results.answers, [{
                        name: 'example.com.',
                        ttl: 5,
                        type: 'MX',
                        target: '0 smtp.example.com.'
                }]);
                t.end();
        });
});


test('answer query: example.com (SOA)', function (t) {
        dig('example.com', 'SOA', options, function (err, results) {
                t.ifError(err);
                t.deepEqual(results.answers, [{
                        name: 'example.com.',
                        ttl: 5,
                        type: 'SOA',
                        target: 'example.com. hostmaster.example.com. 0 86400 7200 1209600 10800'
                }]);
                t.end();
        });
});


test('answer query: example.com (SRV)', function (t) {
        dig('_sip._tcp.example.com', 'SRV', options, function (err, results) {
                t.ifError(err);
                t.deepEqual(results.answers, [{
                        name: '_sip._tcp.example.com.',
                        ttl: 5,
                        type: 'SRV',
                        target: '0 10 5060 sip.example.com.'
                }]);
                t.end();
        });
});


test('answer query: example.com (TXT)', function (t) {
        dig('example.com', 'TXT', options, function (err, results) {
                t.ifError(err);
                t.deepEqual(results.answers, [{
                        name: 'example.com.',
                        ttl: 5,
                        type: 'TXT',
                        target: '"hello world"'
                }]);
                t.end();
        });
});
