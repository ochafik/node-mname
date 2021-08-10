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

if (require.cache[__dirname + '/helper.js'])
        delete require.cache[__dirname + '/helper.js']
var helper = require('./helper');

var test = helper.test;

var testRecord = function(record, t) {
        if (!record)
                t.ok(false, 'record could not be created');

        if (record && record.valid()) {
                t.ok(true, 'valid record created');
        }
        else {
                t.ok(false, 'record was not valid');
        }

        t.end()
}

test('create a valid record (A)', function(t) {
        var record = new named.ARecord('127.0.0.1');
        testRecord(record, t);
});

test('create a valid record (AAAA)', function(t) {
        var record = new named.AAAARecord('::1');
        testRecord(record, t);
});

test('create a valid record (CAA)', function(t) {
        var record = new named.CAARecord('issue', 'issuer.org', {flags: 1});
        testRecord(record, t);
});

test('create a valid record (CNAME)', function(t) {
        var record = new named.CNAMERecord('alias.example.com');
        testRecord(record, t);
});

test('create a valid record (NS)', function(t) {
        var record = new named.NSRecord('ns.example.com');
        testRecord(record, t);
});

test('create a valid record (MX)', function(t) {
        var record = new named.MXRecord('smtp.example.com');
        testRecord(record, t);
});

test('create a valid record (SOA)', function(t) {
        var record = new named.SOARecord('example.com');
        testRecord(record, t);
});

test('create a valid record (SRV)', function(t) {
        var record = new named.SRVRecord('_sip._udp.example.com', 5060);
        testRecord(record, t);
});

test('create a valid record (TXT)', function(t) {
        var record = new named.TXTRecord('hello world');
        testRecord(record, t);
});
