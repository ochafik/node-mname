var validators = require('../validators');
var assert = require('assert-plus');


// https://datatracker.ietf.org/doc/html/rfc6844#page-8
function CAA(tag, value, opts) {
        assert.string(tag, 'tag');
        assert.string(value, 'value');
        assert.optionalObject(opts, 'options');
        if (tag != 'issue' && tag != 'issuewild' && tag != 'iodef') {
                throw 'Invalid tag: ' + tag;
        }

        if (!opts)
                opts = {};

        var defaults = {
                flags: 0,
        };

        for (key in defaults) {
                if (key in opts) continue;
                opts[key] = defaults[key];
        }

        this.tag = tag;
        this.value = value;
        this.flags = opts.flags;
        this._type = 'CAA';
}
module.exports = CAA;


CAA.prototype.valid = function valid() {
        var self = this, model = {};
        model = {
                flags: validators.UInt8BE,
                tag: validators.nsText,
                value: validators.nsText,
        };
        return validators.validate(self, model);
};
