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
var validators = require('../lib/validators');

if (require.cache[__dirname + '/helper.js'])
        delete require.cache[__dirname + '/helper.js']
var helper = require('./helper');

var test = helper.test;

var toTest = {
        nsName: [
                [ 'example.com', true ],
                [ '0example.com', true ],
                [ '_example.com', false ],
                [ '0_example.com', false ],
                [ '-example.com', false ],
                [ '0-example.com', true ],
                [ 'example-one.com', true ],
                [ 'example-111.com', true ],
                [ 'Example-111.com', true ],
                [ 'a name with spaces', false ],
        ],
        UInt32BE: [
                [ 'hello', false ],
                [ '12345', true ],
                [ 4294967296, false ],
                [ 10, true ]
        ],
        UInt16BE: [
                [ 'hello', false ],
                [ '12345', true ],
                [ 65536, false ],
                [ 10, true ]
        ],
        nsText: [
                [ 'hello world', true ],
        ]
};

test('testing validator (nsName)', function(t) {
        var k = 'nsName';
        for (var i in toTest.k) {
                var s = toTest.k[i][0];
                var ok = toTest.k[i][1];
                var result = validators.k(s);
                t.equal(result, ok);
        }
        t.end();
});

test('testing validator (UInt32BE)', function(t) {
        var k = 'UInt32BE';
        for (var i in toTest.k) {
                var s = toTest.k[i][0];
                var ok = toTest.k[i][1];
                var result = validators.k(s);
                t.equal(result, ok);
        }
        t.end();
});

test('testing validator (UInt16BE)', function(t) {
        var k = 'UInt16BE';
        for (var i in toTest.k) {
                var s = toTest.k[i][0];
                var ok = toTest.k[i][1];
                var result = validators.k(s);
                t.equal(result, ok);
        }
        t.end();
});

test('testing validator (nsText)', function(t) {
        var k = 'nsText';
        for (var i in toTest.k) {
                var s = toTest.k[i][0];
                var ok = toTest.k[i][1];
                var result = validators.k(s);
                t.equal(result, ok);
        }
        t.end();
});
