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
var ipaddr = require('ipaddr.js');
var net = require('net');

module.exports = {
        nsName: function (v) {
                // hostname regex per RFC1123
                /*JSSTYLED*/
                var reg = /^([a-z0-9]|[a-z0-9][a-z0-9\-]{0,61}[a-z0-9])(\.([a-z0-9]|[a-z0-9][a-z0-9\-]{0,61}[a-z0-9]))*$/i;
                if (typeof (v) !== 'string')
                        return false;
                if (v.length > 255)
                        return false;

                if (reg.test(v)) {
                        return true;
                } else {
                        return false;
                }
        },
        UInt32BE: function (v) {
                if (typeof (v) === 'number') {
                        var n = parseInt(v, 10);
                        if (n !== NaN && n >= 0 && n < 4294967296) {
                                return true;
                        } else {
                                return false;
                        }
                } else {
                        return false;
                }
        },
        UInt16BE: function (v) {
                if (typeof (v) === 'number') {
                        var n = parseInt(v, 10);
                        if (n !== NaN && n >= 0 && n < 65536) {
                                return true;
                        } else {
                                return false;
                        }
                } else {
                        return false;
                }
        },
        UInt8BE: function(v) { 
          if (typeof(v) === 'number') {
            var n = parseInt(v);
            if (n !== NaN && n >= 0 && n < 256) {
              return true;
            }
            else {
              return false;
            }
          }
          else {
            return false;
          }
        },
        nsText: function (v) {
                if (typeof (v) === 'string') {
                        if (v.length < 256)
                                return true;
                }
                return false;
        },
        IPv4: function (v) {
                return net.isIPv4(v);
        },
        IPv6: function (v) {
                return net.isIPv6(v);
        },
        validate: function (obj, model) {
                var result = true;
                for (var v in model) {
                        if (!model[v](obj[v])) {
                                result = false;
                                break;
                        }
                }
                return result;
        }
};
